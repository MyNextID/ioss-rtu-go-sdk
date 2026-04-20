# IOSS-RTU-GO-SDK

> The SDK used to issue and verify/validate IOSS-RTU (Import One-Stop Shop Right To Use) tokens

**Status:** 🟢 Active  
**Stack:** `Golang`  
**Owners:** @zbrumen, @oriiyx  
**Last reviewed:** 2026-04-17

---

## Data types

### RTU

RTU object defines the IOSS-RTU token that is issued and/or verified

```go
type RTU struct {
    // Version is the type of this signed rtu (schema id). It determines what type of payload we should expect
    Version Version `json:"version" asn1:""`
    // Payload is the raw byte array of the RTU payload
    Payload []byte `json:"payload" asn1:""`
    // Signature is the raw byte array of the signature
    Signature []byte `json:"signature" asn1:""`
    // Algorithm is the signature algorithm for the Signature of the given Payload in this Signed structure
    Algorithm SignatureAlgorithm `json:"algorithm" asn1:",utf8,optional"`
}
```

The library also defines an `RawRTU` and `PackedRTU`. 
Both are encoded versions of the above RTU structure.

`RawRTU` is ASN.1 DER encoded RTU, while `PackedRTU` is base64url encoded RawRTU. 

NOTE: IOSS-RTU Deposit service requires `PackedRTU` to be sent via API

#### Schema
ASN.1 DER schema of the RTU object:
```asn
-- Top-level signed envelope.  DER-encode this structure for QR / API transport.
SignedData ::= SEQUENCE {
    version     INTEGER,

    -- DER-encoded IOSSRTU payload (the bytes that were hashed and signed).
    payload     OCTET STRING,

    -- DER-encoded signature bytes: (depends on algorithm and version)
    signature   OCTET STRING
    
    -- Algorithm is the signature algorithm for the signature and/or CPK inside of the payload.
    algorithm   UTF8String OPTIONAL
}
```

### Payload

```go
// Payload is the structureless data container for all versions of RTU
type Payload struct {
	// unexported fields
}
```

`Payload` is a structure used to store all relevant data inside an `RTU.Payload`.

It allows setting and getting of all stored information of an `IOSS-RTU`

Each `Version` supported in this library should be able to parse its own data structure into `rtu.SchemaPayload`, which is
an interface that allows conversion to `rtu.Payload`. See the CONTRIBUTION section for more details on `SchemaPayload` and
how to add a new version

### SignatureAlgorithms

This SDK has a `PublicKey` and `PrivateKey` structure to help join correct CPK and keys to its rightful `SignatureAlgorithm`

List of available SignatureAlgorithms:
```go
const (
	AlgorithmNone      SignatureAlgorithm = ""
	AlgorithmEcdsaP256 SignatureAlgorithm = "ecdsa-p256"
)
```

SignatureAlgorithms define a signature algorithm type. It also implements `Digest` method, which returns a digest of a payload
based on the signature type. Example: `rtu.AlgorithmEcdsaP256` returns a SHA256 digest, to be signed with an ECDSA private key.

### CPK

CPK - Compressed Public Key is a raw byte array compressed representation of a public key.

```go
type CPK []byte
```

It has a method `Parse`, that allows recovery of a publicKey, with a given `SignatureAlgorithm` and returns a `rtu.PublicKey`


Example: For the signature algorithm `rtu.AlgorithmEcdsaP256`, the CPK value is:
```go
var key *ecdsa.PublicKey // key is on P-256 curve

var cpk CPK = elliptic.MarshalCompressed(key.Curve, key.X, key.Y)
```

### Keys

`PublicKey` is the combination of a SignatureAlgorithm with a publicKey `crypto.PublicKey` and a computedCPK `rtu.CPK`.

`PrivateKey` is the same as `PublicKey` but also adds the correct privateKey into the combination.

## Versions

For future improvements to the RTU structure and/or adding signature support, each `rtu.RTU` signed object has a `Version` property,
which defines the signature type, signature algorithms supported, maxRTUSize, maxRTUPayload size and payload structure along with 
all the validation rules for the fields inside the correct payload structure.

Currently this library support IOSS-RTU Versions:
```go
const (
	Version1 Version = 1
)
```

### Version 1

#### Payload schema

ASN.1 Schema:
```asn1
IOSSRTUVersion1 DEFINITIONS IMPLICIT TAGS ::= BEGIN

-- A 33-byte compressed P-256 public key point.
-- Prefix byte is 0x02 (even Y) or 0x03 (odd Y), followed by the 32-byte X coordinate.
CompressedPublicKey ::= OCTET STRING (SIZE(33))

-- A single consignment identifier.
ConsignmentID ::= UTF8String (SIZE(1..35))

-- An ordered list of consignment identifiers. Max 10 entries; all entries must be unique.
ConsignmentIDList ::= SEQUENCE (SIZE(1..10)) OF ConsignmentID

-- Credential payload. The DER encoding of this structure is what gets hashed and signed.
IOSSRTU ::= SEQUENCE {
    -- 33-byte compressed ECDSA P-256 public key embedded by the SDK (see CPK section below).
    cpk                 CompressedPublicKey,

    delegatedUse        BOOLEAN,

    -- [0] and [1] context tags are required — both fields share the UTF8String universal
    -- tag with transactionID; without tags the decoder cannot tell them apart when absent.
    sellerName          [0] UTF8String OPTIONAL,   -- max 100 characters
    sellerAddress       [1] UTF8String OPTIONAL,   -- max 100 characters

    -- 1–50 characters
    transactionID       UTF8String,

    -- Unix epoch timestamp; must be strictly in the future at sign and verify time.
    validUntil          INTEGER,

    -- When present, must match ^[A-Z]{2}-[A-Z0-9]{1,4}$
    limitDeliveryArea   UTF8String OPTIONAL,

    consignmentIDs      ConsignmentIDList OPTIONAL,

    -- When present, must be in range 1..100
    limitConsignments   INTEGER OPTIONAL
}
END
```

## Signers

### SignV1

`SignV1` is a `rtu.Signer` function, that signs a `rtu.Payload` with an ECDSA-P256 private key (version 1 only supports that algorithm),
and creates a `rtu.Version1` RTU
```go

key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
	panic(err)
}

privateKey, err := rtu.NewECPrivateKey(key)
if err != nil {
	panic(err)
}

payload := rtu.NewPayload("TX_ID", time.Now().Add(time.Hour)).SetDelegatedUse(false)

// Sign the payload as an Version1 RTU object, with the given privateKey
signedRtu, err := rtu.SignV1(payload, privateKey)
```

### Sign

`Sign` is a helper function, that takes a `rtu.Version`, `rtu.Payload` and `rtu.PrivateKey` variable, and generates a `rtu.PackedRTU`

```go
key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
	panic(err)
}

privateKey, err := rtu.NewECPrivateKey(key)
if err != nil {
	panic(err)
}

payload := rtu.NewPayload("TX_ID", time.Now().Add(time.Hour)).SetDelegatedUse(false)

// Sign the payload as an Version1 RTU object, with the given privateKey
packedRtu, err := rtu.Sign(rtu.Version1, paylaod, privateKey)

```

### External Signer

`ExternalSigner` is a service, that enables issuers to sign via an external private key. It needs the `rtu.PublicKey` representation
of the external signer's public key, and the version of the RTU object it is producing. 

You can then use its methods `ComputeDigest` to generate the correct digest to sign and the raw payload, that was constructed from `rtu.Payload`.
Signing the digest with the correct private key, and offering the signature along with the given raw payload into `ConstructSigned` allows the signer
to validate your signature (and validate it was signed with the correct private key) and construct the correct RTU object.

`ConstructSigned` returns a PackedRTU for easier usage, to get a `RawRTU` use `ConstructSignedRaw`,
or if you wish to get an `rtu.RTU` object, use `ConstructSignedObj`.

```go
var publicKey rtu.PublicKey // get public key for your signer, import *ecdsa.PublicKey with rtu.NewECPublicKey(publicKey)

externalSigner := rtu.NewExternalSigner(rtu.Version1, publicKey)

var payload *rtu.Payload // create your Payload for the RTU token

digest, rawPayload, err := externalSigner.ComputeDigest(payload)
if err != nil {
	panic(err)
}

var signature []byte // get signature from external signer using digest as the payload to sign

signedRtu, err := externalSigner.ConstructSigned(rawPayload, signature)
if err != nil {
	panic(err)
}

// signedRtu is the rtu.PackedRTU, that can be used to send to rtu deposit service
```

---

## Licence

See [LICENCE](LICENCE).
