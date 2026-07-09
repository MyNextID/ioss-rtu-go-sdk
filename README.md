IOSS RTU Go SDK
===============

A Go library for signing, verifying, and encoding IOSS RTU (Import One-Stop Shop Right to Use) credentials. Produces
ASN.1 DER-encoded `RTU` (`SignedData`) output suitable for base64url encoding and QR code transport.

**Key properties:**

- ECDSA P-256 signing and verification (Go standard library `crypto/ecdsa`)
- ASN.1 DER encode/decode for the `IOSSRTU` payload and `SignedData` envelope — byte-compatible with the Java and C SDKs
- External / HSM signing workflow via `ExternalSigner.ComputeDigest()` + `ExternalSigner.ConstructSigned()`
- Key loading from PEM (SEC1 and PKCS#8)
- Compressed P-256 public key encode/decode
- QR code compatibility — encoded output enforced under size limits
- Versioned schema design — forward-compatible with future RTU layouts and signature algorithms
- Multiple formats (ASN1 encoded RTUs and JWT encoded RTUs)

Table of Contents
-----------------

- [IOSS RTU Go SDK](#ioss-rtu-go-sdk)
	- [Table of Contents](#table-of-contents)
	- [Requirements](#requirements)
	- [Installation](#installation)
	- [Quickstart](#quickstart)
	- [API Overview](#api-overview)
	- [Data Types](#data-types)
		- [Payload](#payload)
		- [RTU](#rtu)
		- [Key types](#key-types)
	- [Signing Workflows](#signing-workflows)
		- [Internal signing](#internal-signing)
		- [Verification](#verification)
		- [External / HSM signing](#external--hsm-signing)
	- [Key Loading](#key-loading)
		- [PEM — private key](#pem--private-key)
		- [Compressed public key](#compressed-public-key)
		- [Deriving the public key from a private key](#deriving-the-public-key-from-a-private-key)
	- [Versions](#versions)
		- [Version 1](#version-1)
	- [Size Limits](#size-limits)
	- [Errors](#errors)
	- [ASN.1 Schema](#asn1-schema)
	- [Building from Source](#building-from-source)
	- [Testing](#testing)
	- [License](#license)

Requirements
------------

- **Go 1.26 or later** — the SDK targets the toolchain declared in `go.mod` and relies on standard-library generics
  and testing features available from that release.
- **Dependency**: `github.com/lestrrat-go/jwx/v3` used for handling JWK keys and parsing 'alg' jwa.SignatureAlgorithms 
  to rtu.SignatureAlgorithms

Installation
------------

Add the module to your project:

```bash
go get github.com/MyNextID/ioss-rtu-go-sdk@latest
```

Then import it. The package is conventionally aliased to `rtu`:

```go
import rtu "github.com/MyNextID/ioss-rtu-go-sdk"
```

Quickstart
----------

At a high level, the signing workflow is:

1. Load a P-256 private key into a `rtu.PrivateKey` (see [Key Loading](#key-loading)).
2. Build a `rtu.UnsignedPayload` with `rtu.New(format, version)` and the chainable `Set*()` methods (see [Payload](#payload)).
3. Call `rtu.Sign()` with the `rtu.UnsignedPayload` and `rtu.PrivateKey` to get a `PackedRTU` base64url
   token for QR encoding or transport.

`internal/examples/signer/main.go` is a self-contained starting point you can copy into your own project: it generates
a key, signs a credential, and prints the base64url token ready for QR encoding. The example uses `signASN` function, to
generate the payload and output the final base64url encoded `PackedRTU`. For JWT encoding, a `signJWT` and `signJWTWithJWK`
functions have been added. Companion examples for verification and
the HSM workflow live alongside it in `internal/examples`. Run any of them straight from the source tree:

```bash
go run ./internal/examples/signer
```

ASN.1 DER encoded example (for QR codes):
```go
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

func main() {
	// 1. Load a P-256 private key (SEC1 or PKCS#8 PEM).
	pem, err := os.ReadFile("private-key.pem")
	if err != nil {
		log.Fatal(err)
	}
	key, err := rtu.LoadPrivateKeyPEM(pem)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Populate the credential. (arguments are: transactionID, validUntil, delegatedUse)
	payload := rtu.NewVersion1ASN("tx-001", time.Now().Add(24*time.Hour), false).
		SetSellerName("Example Seller")

	// 3. Sign and pack to a base64url token, ready for a QR code.
	token, err := rtu.Sign(payload, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(token) // base64url credential, ready for a QR code
}
```

For verification and the external/HSM signing workflow, see [Signing Workflows](#signing-workflows).

API Overview
------------

The SDK returns errors as values rather than panicking — signing, verification, validation, and key loading all return
an `error` that callers are expected to handle, because silent failures are unacceptable in customs and tax contexts.
Sentinel errors can be matched with `errors.Is()`, and field-level failures are returned as `*rtu.ValidationError`; see section
[Errors](#errors) for the full list.

The typical call sequence follows one of the signing workflows described in [Signing Workflows](#signing-workflows).

The table below is a quick reference to the SDK's exported API — the functions and methods you call directly. Every
symbol is documented in full, with examples, on [pkg.go.dev](https://pkg.go.dev/github.com/MyNextID/ioss-rtu-go-sdk) or
locally via `go doc`.
The **Receiver** column indicates where each entry is defined: `package` marks a package-level function
(called as `rtu.Function(...)`), while different type names such as `*RTU` or `PackedRTU` denote methods on instances of those types
(called as `Receiver.Function()`). All receiver and parameter types are described in [Data Types](#data-types).

| Function            | Receiver          | Parameters                                                     | Returns                               | Purpose                                                                  |
|---------------------|-------------------|----------------------------------------------------------------|---------------------------------------|--------------------------------------------------------------------------|
| `New`               | `package`         | `format Format, version Version`                               | `UnsignedPayload, error`              | Create a credential payload for the given format and version             |
| `LoadPrivateKeyPEM` | `package`         | `pemBytes []byte`                                              | `PrivateKey, error`                   | Load a P-256 private key from PEM (SEC1 or PKCS#8)                       |
| `NewECPublicKey`    | `package`         | `pub *ecdsa.PublicKey`                                         | `PublicKey, error`                    | Wrap a raw P-256 public key (for external signing)                       |
| `Sign`              | `package`         | `payload UnsignedPayload, key PrivateKey, opts ...SignOptions` | `PackedRTU, error`                    | Derive CPK, validate fields, sign, and return a ready-to-use `PackedRTU` |
| `Verify`            | `package`         | `packed PackedRTU, opts ...VerifyOptions`                      | `Payload, PublicKey, error`           | Verify signature, validate fields, return the payload                    |
| `Pack`              | `RTU`             | —                                                              | `PackedRTU, error`                    | ASN.1 DER-encode then base64url-encode                                   |
| `Parse`             | `PackedRTU`       | —                                                              | `RTU, error`                          | Decode and validate the envelope                                         |
| `ComputeDigest`     | `*ExternalSigner` | `data *Payload`                                                | `digest []byte, payload []byte, error` | Encode payload and return its SHA-256 digest (for HSM signing)           |
| `ConstructSigned`   | `*ExternalSigner` | `payload []byte, signature []byte`                             | `PackedRTU, error`                    | Assemble a `PackedRTU` from payload and external signature               |
| `CPK`               | `PublicKey`       | —                                                              | `CPK`                                 | Derive the 33-byte compressed public key                                 |
| `Public`            | `PrivateKey`      | —                                                              | `PublicKey`                           | Return the raw public key                                                |
| `Parse`             | `CPK`             | `algorithm SignatureAlgorithm`                                 | `PublicKey, error`                    | Recover a `PublicKey` from a compressed public key                       |

Data Types
----------

### Payload

The `Payload` interface is a set of read-only getters for all possible fields inside an RTU and the metadata getters for
`Format() Format` and `Version() Version`.

The `UnsignedPayload` interface wraps the `Payload` and adds chainable `Set*()` methods for all the possible fields 
inside an RTU payload. alongside `PublicKey() PublicKey` and `SetPublicKey(key PublicKey) (UnsignedPayload, error)`. 
Setter for public key can return error, in case the `Version` or `Format` do not support the given `PublicKey` type
the `SetPublicKey` is called automatically by the `ExternalSigner` service or the `Sign` function — 
do not set it manually. Instances must pass validation before they can be signed.

When building a new instance of the credential payload (`UnsignedPayload`), there are a few options:
- `New(format Format, version Version) (UnsignedPayload, error)`
- `NewVersion1ASN(txID string, validUntil time.Time, delegatedUse bool) UnsignedPayload`
- `NewVersion1JWT(txID string, validUntil time.Time, delegatedUse bool) UnsignedPayload`

`NewVersion1ASN` and `NewVersion1JWT` are considered 'wrapper' functions, as they do the same as `New`, but since
they do not take `Format` and `Version` as an argument, they are error safe. They also take the required fields for
`Version1` RTUs as arguments, ensuring the fields are set

```go
payload := rtu.NewVersion1ASN("TX-001", time.Now().Add(24*time.Hour), false). // transactionID (1–50 bytes), validUntil (future), delegatedUse
	SetSellerName("Acme Corp").           // optional, max 100 bytes
	SetSellerAddress("Brussels").         // optional, max 100 bytes
	SetLimitDeliveryArea("DE-BY").        // optional, pattern: [A-Z]{2}-[A-Z0-9]{1,4}
	SetConsignments([]string{"CNS001"})   // optional, max 10 entries, each 1–35 bytes, no duplicates
```

| Field               | Type            | Required  | Constraints                                                                                          |
|---------------------|-----------------|-----------|------------------------------------------------------------------------------------------------------|
| `PublicKey`         | `rtu.PublicKey` | internal  | Set automatically by the signer; value derived from `rtu.PrivateKey` or set by `*rtu.ExternalSigner` |
| `TransactionID`     | `string`        | yes       | 1–50 bytes                                                                                           |
| `ValidUntil`        | `time.Time`     | yes       | Unix timestamp strictly in the future                                                                |
| `DelegatedUse`      | `boolean`       | yes       | No constraints                                                                                       |
| `SellerName`        | `string`        | no        | Max 100 bytes                                                                                        |
| `SellerAddress`     | `string`        | no        | Max 100 bytes                                                                                        |
| `LimitDeliveryArea` | `string`        | no        | Must match `^[A-Z]{2}-[A-Z0-9]{1,4}$`                                                                |
| `ConsignmentIDs`    | `string array`  | no (excl) | Max 10 entries; each 1–35 bytes; no duplicates                                                       |
| `LimitConsignments` | `integer`       | no (excl) | 1–100 when set                                                                                       |

`ConsignmentIDs` and `LimitConsignments` are mutually exclusive — setting both returns a `*ValidationError` on
`LimitConsignments`.

### RTU

The `RTU` interface defines a signed valid RTU payload. In case of ASN1.DER encoded RTUs,
the final `RTU` envelope is something like the following structure:
```go
type asn1RtuObject struct {
	Version   Version            // schema id; determines how Payload is parsed
	Payload   []byte             // DER-encoded IOSSRTU payload (the bytes that were signed)
	Signature []byte             // raw signature bytes
	Algorithm SignatureAlgorithm // optional; empty means the version's default algorithm
}
```

For JWT encoded RTUs the `RTU` interface is defined by the following structure:
```go
type jwtRtuObject struct {
	Header json.RawMessage  // JWT Protected header as a json string
	Payload json.RawMessage // JWT Payload (of the RTU) as a json string
	Signature []byte        // A valid JWS signature
}
```

Finally, the `RTU` interface has an encoded form named `PackedRTU`. In the case of ASN.1 DER encoding,
it is simply the base64url encoded byte array of the ASN.1 DER encoded RTU struct.
For JWT, it is the JWS Compact string. For decoding the `PackedRTU` either `PackedRTU.Parse` is used (which
tries to decode every possible format), or the separate `DecodeASN` and `DecodeJWT` package functions can be used.

### Key types

P-256 keys are wrapped in `PrivateKey` and `PublicKey`, which bind a raw `crypto` key to its `SignatureAlgorithm` and a
precomputed CPK. Keys on any curve other than P-256 (secp256r1) are rejected with `ErrKeyInvalid`.

The compressed public key (CPK) embedded in the payload is 33 bytes: a one-byte prefix (`0x02` for even Y, `0x03` for
odd Y) followed by the 32-byte X coordinate. Use `PublicKey.GetCPK()` to obtain the compressed form and `CPK.Parse()` to
recover a `PublicKey` from it.

For JWT encodings, a new interface is made available `PublicKeyJWK`. This creates a jwk key alongside the `CPK` and 
raw `crypto` key. If available, JWT signers will include `jwk` header instead of `cpk` allowing easier integration
with already existing systems. A `PublicKeyJWK` can easily be created with the package functions:
`AddJWKToPublicKey` and `AddJWKToPrivateKey`, which wrap the existing `PublicKey` and create a JWK key for it.

You can also create a `PublicKey` directly from a jwk, with the `NewJWKPublicKey` package function.

Signing Workflows
-----------------

The following examples show how to use the SDK to produce and consume credentials. Use **internal signing** when the
private key is available in-process, or **external signing** when the key is managed by an HSM or signing service.

### Internal signing

`Sign()` is the entry point for signing when the private key is available in-process. Pass the target version and it:

1. Derives the compressed public key (CPK) from `key` and embeds it in the payload. In case
of JWT encoding and a `PublicKeyJWK` it derives the `jwk` instead.
2. Validates all fields in the `Payload` (see [Data Types](#data-types) for constraints). This functionality
can be turned off with `WithoutSignValidation()` as a `SignOption`
3. Encodes the `IOSSRTU` payload (using `UnsignedPayload.Marshal` method).
4. Computes a digest of the encoded payload, based on the keys `SignatureAlgorithm`.
5. Produces a signature over the digest (using `PrivateKey.Sign` to encode the signature correctly based on the format).
6. Wraps payload and signature into a `RTU` and encodes it into a `PackedRTU` ready for QR code or API transport.

```go
key, err := rtu.LoadPrivateKeyPEM(pemBytes)
if err != nil {
	log.Fatal(err)
}

payload := rtu.NewVersion1ASN("TX-2026-001", time.Now().Add(48*time.Hour), false)

token, err := rtu.Sign(payload, key)
if err != nil {
	log.Fatal(err)
}
```

Do not set the PublicKey on the payload manually before calling `Sign()` — the signer derives it from `key` and overwrites
any value you set.

### Verification

For verification a package wide function has been made: `Verify`

It accepts the `PackedRTU` and extra options for verification (allowing enabled/disable of certain validations etc.)
The returned values are: `Payload, PublicKey, error`. Error can be a `ValidationError` in which case, the decoding was ok
but the validation and/or verification of the payload or signature went wrong.
The `Payload` is a read-only interface, allowing consumption of the RTU payload fields
The `PublicKey` is also returned, where `CPK` and other values can be read.


```go
var packed rtu.PackedRTU = "...packed rtu..."


payload, publicKey, err := rtu.Verify(packed)
if err != nil {
	// envelope is not encoded properly, fails validation or signature incorrect
	// (unknown version, size out of range, unsupported algorithm, rtu.ValidationError, incorrect signature)
	log.Fatal(err)
}

// publicKey is a rtu.PublicKey, which has been validated and the signature was verified with it.
// payload is a rtu.Payload — decoded, signature-verified, and fully validated.
```

If the source is trusted, validation can be skipped for performance by calling `Verify` with `WithIgnoreValidation` option
and `WithNoSignatureVerification` options.
This is not recommended unless you control the source.

### External / HSM signing

Use `ExternalSigner` when the private key is held in a hardware security module (HSM) or a remote signing service. The
signer needs only the `Format` and `Version` of the RTUs that will be signed and the `PublicKey` of the external key.

**Step 1 — compute the digest:**

`ComputeDigest()` embeds the `PublicKey`, encodes the payload, and returns both the payload bytes and the 
`SignatureAlgorithm` specific hash digest to sign externally:

```go
var publicKey rtu.PublicKey // a secp256r1 public key wrapped into a rtu.PublicKey
signer := rtu.NewExternalSigner(rtu.ASN1, rtu.Version1, publicKey)

payload := rtu.NewVersion1ASN("TX-HSM-001", time.Now().Add(48*time.Hour), false)

digest, rawPayload, err := signer.ComputeDigest(payload)
if err != nil {
	log.Fatal(err)
}

// digest      — 32-byte SHA-256 hash, send to the HSM
// rawPayload  — DER-encoded IOSSRTU, retain until step 2
```

**Step 2 — assemble the signed credential:**

Once the HSM returns a DER-encoded ECDSA signature over the digest, submit it together with the retained payload:

```go
signature := myHSM.SignDigest(digest) // your HSM call

token, err := signer.ConstructSigned(rawPayload, signature)
if err != nil {
	log.Fatal(err)
}

// token is a PackedRTU, ready for the deposit service.
```

Before assembling the final envelope, `ConstructSigned()` verifies the signature against the CPK embedded in the payload.
If the HSM signed with a different key, the call returns `ErrKeyInvalid` or `ErrSignatureInvalid`. `ConstructSigned()`
returns a `PackedRTU`; use `ConstructSignedRaw()` for a `RawRTU` or `ConstructSignedObj()` for an `*RTU`.

Key Loading
-----------

The SDK loads P-256 keys from standard formats. Key-loading and key-construction helpers return `ErrKeyInvalid` on
failure.

### PEM — private key

Accepts both SEC1 (`EC PRIVATE KEY`) and PKCS#8 (`PRIVATE KEY`) PEM blocks:

```go
pem, err := os.ReadFile("private-key.pem")
if err != nil {
	log.Fatal(err)
}
key, err := rtu.LoadPrivateKeyPEM(pem)
```

To wrap an in-memory `*ecdsa.PrivateKey` (for example one returned by an HSM client), use `NewECPrivateKey()`; for a
public key only, use `NewECPublicKey()`.

### Compressed public key

Convert between a `PublicKey` and the 33-byte compressed SEC1 form:

```go
cpk := publicKey.CPK()             // PublicKey → 33-byte CPK
recovered, err := cpk.Parse(rtu.AlgorithmEcdsaP256) // CPK → PublicKey
```

### Deriving the public key from a private key

A `PrivateKey` can retrieve its `PublicKey` with `Public()` method call:

```go
pub := key.Public() 	  // rtu.PublicKey
cpk := key.Public().CPK() // 33-byte compressed form
```

Formats
-------

Since v0.3, IOSSRTUs can be represented as both:
- ASN.1 DER encoded RTUs
- JWT encoded RTUs (JWS Compact only)

Since the schemas and signatures are different between these 2 encodings, a `Format` type
has been added to differentiate between them.

```go
const (
	FormatNone Format = "" // FormatNone is used, when no format was recognized in verification
	ASN1       Format = "asn1" // ASN1 is the Format for ASN.1 DER encoded RTUs
	JWT        Format = "jwt" // JWT is the Format for JWT (JWS Compact) encoded RTUs
)
```

When building a new `rtu.UnsignedPayload` it is therefore required to provide a `Format` as well as a `Version`
to build the correct payload and encode it properly.
```go
unsignedPayload, err := rtu.New(rtu.ASN1, rtu.Version1)
```

Note: Above error is only not nil, if an unknown `Format` or `Version` are provided. To make creating an `UnsignedPayload`
a bit more straightforward and easier, two helper functions have also been added:

```go
asn1Payload := rtu.NewVersion1ASN("TX_ID", time.Now().Add(time.Hour * 24), false)
jwtPayload := rtu.NewVersion1JWT("TX_ID", time.Now().Add(time.Hour * 24), false)
```

Both functions automatically create a `Version1` payload, and have all required fields for that version as parameters
for the function, ensuring the payload is immediately ready for signing.

`PackedRTU.Parse` tries to establish, what encoding was used. Since `JWT` has 2 '.' in the payload (JWS Compact), it
checks for those. It then calls `DecodeJWT` if they exist, otherwise `DecodeASN` is called.


Versions
--------

Every signed `RTU` carries a `Version`, an integer schema id that determines the payload layout, the supported
signature algorithms, the size limits, and the field validation rules. This keeps the wire format forward-compatible:
new schemas can be added without breaking existing verifiers.

```go
const (
	Version1 Version = 1
)
```

### Version 1

The first version of an IOSS-RTU. It supports only the `AlgorithmEcdsaP256` signature algorithm and requires the
`Algorithm` field inside `RTU` to be empty (the version default is implied). The payload layout and field constraints
are described in [Data Types](#data-types) and [ASN.1 Schema](#asn1-schema).

Size Limits
-----------

| Limit                       | Value | Description                                    |
|-----------------------------|-------|------------------------------------------------|
| Max payload (DER bytes)     | 750   | Max DER size of the `IOSSRTU` payload          |
| Max signed data (DER bytes) | 830   | Max DER size of the full `RTU` envelope        |

The 750-byte payload limit is enforced during signing and the 830-byte envelope limit during envelope validation
(`Unpack()` / `RawRTU.Parse()`). These limits keep the encoded credential within QR-code capacity. Exceeding either limit
returns a `*ValidationError`.

NOTE: Above size limits only apply to ASN1.DER encoded RTUs. JWT RTUs skip that validation

Errors
------

The SDK returns sentinel error values that can be matched with `errors.Is()`:

| Error                          | Returned when                                                                        |
|--------------------------------|--------------------------------------------------------------------------------------|
| `ErrValidation`                | A field fails its constraint (wrapped by `*ValidationError`)                         |
| `ErrEncoding` / `ErrDecoding`  | ASN.1 DER encoding or decoding fails or JWT decoding or json marshal/unmarshal fails |
| `ErrSignatureInvalid`          | Signature verification fails                                                         |
| `ErrSigning`                   | `PrivateKey` signing fails                                                           |
| `ErrUnknownSignatureAlgorithm` | The signature algorithm is unknown or unsupported                                    |
| `ErrNoSignatureAlgorithm`      | A signing operation is attempted with no algorithm set                               |
| `ErrCPKUnsupported`            | The compressed public key type is not supported                                      |
| `ErrKeyInvalid`                | A key cannot be parsed, is not EC, is not on P-256, or does not match the CPK        |
| `ErrUnknownVersion`            | The `RTU` version is not recognised                                                  |
| `ErrNoVersion`                 | The `RTU` version is empty                                                           |
| `ErrUnknownFormat`             | The `RTU` format is not recognised                                                   |
| `ErrNoFormat`                  | The `RTU` format is empty                                                            |
| `ErrEmptyInput`                | A required payload or signature argument is empty                                    |

Field-level validation failures are returned as `*ValidationError`, which carries the offending field name. Match it
with `errors.As()` or the new `errors.AsType[*rtu.ValidationError]()`:

```go
var verr *rtu.ValidationError
if errors.As(err, &verr) {
fmt.Printf("field %q: %s\n", verr.Field, verr.Message)
}
```

ASN.1 Schema
------------

Credentials with `FormatASN` are encoded as ASN.1 DER, a compact and unambiguous binary format that is well-suited to QR-code transport
and interoperable across implementations in any programming language. The wire format is DER-encoded according to the
following ASN.1 module:

```asn1
IOSSRTUModule DEFINITIONS IMPLICIT TAGS ::= BEGIN

CompressedPublicKey ::= OCTET STRING (SIZE(33))
ConsignmentID       ::= UTF8String (SIZE(1..35))
ConsignmentIDList   ::= SEQUENCE (SIZE(1..10)) OF ConsignmentID

IOSSRTU ::= SEQUENCE {
    cpk                 CompressedPublicKey,
    delegatedUse        BOOLEAN,
    sellerName          [0] UTF8String OPTIONAL,
    sellerAddress       [1] UTF8String OPTIONAL,
    transactionID       UTF8String,
    validUntil          INTEGER,
    limitDeliveryArea   UTF8String OPTIONAL,
    consignmentIDs      ConsignmentIDList OPTIONAL,
    limitConsignments   INTEGER OPTIONAL
}

SignedData ::= SEQUENCE {
    version     INTEGER,
    payload     OCTET STRING,
    signature   OCTET STRING,
    algorithm   UTF8String OPTIONAL
}

END
```

`sellerName` and `sellerAddress` use context-specific tags (`[0]` and `[1]`) because they are optional `UTF8String`
fields that precede another `UTF8String` field (`transactionID`). Without explicit tags, a decoder could not reliably
determine which field is present when one or both optional fields are omitted. The trailing optional fields each have
distinct ASN.1 types (`UTF8String`, `SEQUENCE`, and `INTEGER`) and are therefore unambiguous without additional
context-specific tags.

JWT Schema
----------

With the new `Format` feature, RTU credentials can now be encoded as a JWS Compact string

Credential protected header with CPK:
```json
{
  "alg": "ES256",
  "typ": "ioss-rtu+json",
  "v":   1,
  "cpk": "<base64url-encoded 33-byte compressed public key>"
}
```

Credential protected header with JWK:
```json
{
  "alg": "ES256",
  "typ": "ioss-rtu+json",
  "v":   1,
  "jwk": {
	  "crv": "P-256",
	  "kty": "EC",
	  "x": "lpkP1M5a_O-BfLgHcZEunTwiRgszUEFH2PVoGCgd0bI",
	  "y": "UHvpDIBwQz2Pdl7FCeHAFs7_iwgUGSHjyxi6FKx1XE0"
  }
}
```

Header claims:


| Claim | Description                                                                                                                                                                                                                                        |
|-------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `alg` | "ES256" — IANA-registered identifier for ECDSA with P-256 and SHA-256 (RFC 7518 §3.4). Maps to the existing AlgorithmEcdsaP256.`                                                                                                                   |
| `typ` | "ioss-rtu+json" — application-specific media type following the +json structured-syntax suffix convention (RFC 6839). Allows recipients to identify the token type before parsing the payload.`                                                    |
| `v`   | Schema version integer. Equivalent to rtu.Version. Placed in the header so envelope validators can dispatch without parsing the payload.`                                                                                                          |
| `cpk` | Base64url-encoded 33-byte compressed public key. Placing the CPK in the header makes it available to the verifier before payload decode, aligns with the JWK/JOSE key-in-header convention, and removes the 33-byte field from the signed payload. |
| `jwk` | IANA registered header for JWK keys (RFC 7515 §4.1.3)                                                                                                                                                                                              |

Credential payload:

```json
{
  "jti": "TX-2026-001",
  "exp": 1751155200,
  "du":  false,
  "sn":  "Acme Corp",
  "sa":  "Brussels, BE",
  "lda": "DE-BY",
  "cid": ["CNS001", "CNS002"]
}
```

Claim mapping:

| Claim | ASN1 Field Claim    | Notes                                                      |
|-------|---------------------|------------------------------------------------------------|
| `jti` | `TransactionID`     | RFC 7519 registered claim — transaction identifier         |
| `exp` | `ValidUntil`        | RFC 7519 registered claim — Unix timestamp                 |
| `du`  | `DelegatedUse`      | Private claim, boolean                                     |
| `sn`  | `SellerName`        | Private claim, string, optional                            |
| `sa`  | `SellerAddress`     | Private claim, string, optional                            |
| `lda` | `LimitDeliveryArea` | Private claim, string, optional                            |
| `cid` | `ConsignmentIDs`    | Private claim, array, optional; mutually exclusive with lc |
| `lc`  | `LimitConsignments` | Private claim, int, optional; mutually exclusive with cid  |


Building from Source
--------------------

The project builds with the standard Go toolchain — no code generation or external build tools are involved.

```bash
git clone https://github.com/MyNextID/ioss-rtu-go-sdk.git
cd ioss-rtu-go-sdk
go build ./...
```

```bash
go build ./...               # compile the library and examples
go vet ./...                 # static analysis
go test ./...                # run the test suite
go run ./internal/examples/signer   # run an example
```

Testing
-------

Run the full test suite from the repository root:

```bash
go test ./... -race
```

Run with benchmarks:

```bash
go test ./... -bench=. -benchmem
```

The test suite covers:

- ASN.1 encoding and decoding round-trips
- Field validation
- Signing and verification
- External / HSM signing workflows
- Key loading from PEM (SEC1 and PKCS#8)
- Compressed key operations
- Tamper detection
- Invalid and empty-input handling

All tests are parallel-safe. Go's `crypto/ecdsa` adds randomness to each signature (hedged nonces), so signatures differ
for the same input across invocations. All signatures cross-verify correctly with the Java and C SDKs.

License
-------

European Union Public Licence v. 1.2 — see [LICENCE](LICENCE) for terms.