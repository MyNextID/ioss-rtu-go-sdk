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
- Zero third-party dependencies — pure Go standard library

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
- **No third-party dependencies** — the SDK is built entirely on the Go standard library (`crypto/ecdsa`,
  `crypto/elliptic`, `crypto/x509`, `encoding/asn1`, `encoding/base64`). Nothing else is pulled into your module graph.

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

1. Load a P-256 private key into a `*rtu.PrivateKey` (see [Key Loading](#key-loading)).
2. Build a `*rtu.Payload` with `rtu.NewPayload()` and the chainable `Set*()` methods.
3. Call `rtu.SignV1()` to produce the signed `*rtu.RTU`, then `Pack()` it to a base64url token for QR encoding or transport.

`internal/examples/signer/main.go` is a self-contained starting point you can copy into your own project: it generates
a key, signs a credential, and prints the base64url token ready for QR encoding. Companion examples for verification and
the HSM workflow live alongside it in `internal/examples`. Run any of them straight from the source tree:

```bash
go run ./internal/examples/signer
```

```go
package main

import (
	"fmt"
	"os"
	"time"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

func main() {
	// 1. Load a P-256 private key (SEC1 or PKCS#8 PEM).
	pem, err := os.ReadFile("private-key.pem")
	if err != nil {
		panic(err)
	}
	key, err := rtu.LoadPrivateKeyPEM(pem)
	if err != nil {
		panic(err)
	}

	// 2. Populate the credential.
	payload := rtu.NewPayload("tx-001", time.Now().Add(24*time.Hour)).
		SetDelegatedUse(false)

	// 3. Sign and pack to a base64url token, ready for a QR code.
	signed, err := rtu.SignV1(payload, key)
	if err != nil {
		panic(err)
	}
	token, err := signed.Pack()
	if err != nil {
		panic(err)
	}

	fmt.Println(token) // base64url credential, ready for a QR code
}
```

For verification and the external/HSM signing workflow, see [Signing Workflows](#signing-workflows).

API Overview
------------

The SDK returns errors as values rather than panicking — signing, verification, validation, and key loading all return
an `error` that callers are expected to handle, because silent failures are unacceptable in customs and tax contexts.
Sentinel errors can be matched with `errors.Is()`, and field-level failures are returned as `*rtu.ValidationError`; see
[Errors](#errors) for the full list.

The typical call sequence follows one of the signing workflows described in [Signing Workflows](#signing-workflows).

The table below is a quick reference to the SDK's exported API — the functions and methods you call directly. Every
symbol is documented in full, with examples, on [pkg.go.dev](https://pkg.go.dev/github.com/MyNextID/ioss-rtu-go-sdk) or
locally via `go doc`. The **Receiver** column shows where each entry lives: `package` marks a package-level function
(called as `rtu.SignV1(...)`), while a type such as `*RTU` or `PackedRTU` marks a method on a value of that type
(called as `signed.Pack()`). All receiver and parameter types are described in [Data Types](#data-types).

| Receiver          | Function            | Parameters                                           | Returns                                | Purpose                                                        |
|-------------------|---------------------|------------------------------------------------------|----------------------------------------|----------------------------------------------------------------|
| `package`         | `NewPayload`        | `txID string, validUntil time.Time`                  | `*Payload`                             | Create a credential payload                                    |
| `package`         | `LoadPrivateKeyPEM` | `pemBytes []byte`                                    | `*PrivateKey, error`                   | Load a P-256 private key from PEM (SEC1 or PKCS#8)             |
| `package`         | `NewECPrivateKey`   | `priv *ecdsa.PrivateKey`                             | `*PrivateKey, error`                   | Wrap a raw P-256 private key                                   |
| `package`         | `NewECPublicKey`    | `pub *ecdsa.PublicKey`                               | `PublicKey, error`                     | Wrap a raw P-256 public key (for external signing)             |
| `package`         | `SignV1`            | `payload *Payload, key *PrivateKey`                  | `*RTU, error`                          | Validate, derive CPK, sign                                     |
| `package`         | `Sign`              | `version Version, payload *Payload, key *PrivateKey` | `PackedRTU, error`                     | Validate and sign for a given version                          |
| `*RTU`            | `Parse`             | `withValidations bool`                               | `*Payload, error`                      | Verify signature, validate fields, return the payload          |
| `*RTU`            | `Pack`              | —                                                    | `PackedRTU, error`                     | ASN.1 DER-encode then base64url-encode                         |
| `PackedRTU`       | `Unpack`            | —                                                    | `*RTU, error`                          | Decode and validate the envelope                               |
| `*ExternalSigner` | `ComputeDigest`     | `data *Payload`                                      | `digest []byte, payload []byte, error` | Encode payload and return its SHA-256 digest (for HSM signing) |
| `*ExternalSigner` | `ConstructSigned`   | `payload []byte, signature []byte`                   | `PackedRTU, error`                     | Assemble a `PackedRTU` from payload and external signature     |
| `PrivateKey`      | `GetCPK`            | —                                                    | `CPK`                                  | Derive the 33-byte compressed public key                       |
| `PrivateKey`      | `GetPublicKey`      | —                                                    | `crypto.PublicKey`                     | Return the raw public key                                      |
| `CPK`             | `Parse`             | `algorithm SignatureAlgorithm`                       | `PublicKey, error`                     | Recover a `PublicKey` from a compressed public key             |

Data Types
----------

### Payload

The credential payload. Build instances with `NewPayload()` and the chainable `Set*()` methods; the `cpk` field is set
automatically by the signer — do not set it manually. Instances must pass validation before they can be signed.

```go
payload := rtu.NewPayload("TX-001", time.Now().Add(24*time.Hour)). // transactionID (1–50 bytes), validUntil (future)
	SetDelegatedUse(false).               // required
	SetSellerName("Acme Corp").           // optional, max 100 bytes
	SetSellerAddress("Brussels").         // optional, max 100 bytes
	SetLimitDeliverArea("DE-BY").         // optional, pattern: [A-Z]{2}-[A-Z0-9]{1,4}
	SetConsignments([]string{"CNS001"}).  // optional, max 10 entries, each 1–35 bytes, no duplicates
	SetLimitConsignments(50)              // optional, 1–100; mutually exclusive with consignments
```

| Field               | Type        | Required  | Constraints                                                                  |
|---------------------|-------------|-----------|------------------------------------------------------------------------------|
| `CPK`               | `CPK`       | internal  | Set automatically by the signer; value derived from the `SignatureAlgorithm` |
| `DelegatedUse`      | `bool`      | yes       | No constraints                                                               |
| `SellerName`        | `string`    | no        | Max 100 bytes                                                                |
| `SellerAddress`     | `string`    | no        | Max 100 bytes                                                                |
| `TransactionID`     | `string`    | yes       | 1–50 bytes                                                                   |
| `ValidUntil`        | `time.Time` | yes       | Unix timestamp strictly in the future                                        |
| `LimitDeliverArea`  | `string`    | no        | Must match `^[A-Z]{2}-[A-Z0-9]{1,4}$`                                        |
| `ConsignmentIDs`    | `[]string`  | no (excl) | Max 10 entries; each 1–35 bytes; no duplicates                               |
| `LimitConsignments` | `int`       | no (excl) | 1–100 when set                                                               |

`ConsignmentIDs` and `LimitConsignments` are mutually exclusive — setting both returns a `*ValidationError` on
`LimitConsignments`.

### RTU

The wire-format envelope wrapping a DER-encoded `Payload` together with its ECDSA-SHA256 signature and a version tag.
It corresponds to the `SignedData` ASN.1 structure. Callers do not normally build `RTU` by hand — it is produced by
`SignV1()` / `Sign()` and `ExternalSigner`, and consumed via `Parse()`.

```go
type RTU struct {
	Version   Version            // schema id; determines how Payload is parsed
	Payload   []byte             // DER-encoded IOSSRTU payload (the bytes that were signed)
	Signature []byte             // raw signature bytes
	Algorithm SignatureAlgorithm // optional; empty means the version's default algorithm
}
```

The envelope has two encoded forms. `RawRTU` is the ASN.1 DER encoding of `RTU`; `PackedRTU` is the base64url encoding
of a `RawRTU`. The IOSS-RTU Deposit service requires the `PackedRTU` form over its API.

### Key types

P-256 keys are wrapped in `PrivateKey` and `PublicKey`, which bind a raw `crypto` key to its `SignatureAlgorithm` and a
precomputed CPK. Keys on any curve other than P-256 (secp256r1) are rejected with `ErrKeyInvalid`.

The compressed public key (CPK) embedded in the payload is 33 bytes: a one-byte prefix (`0x02` for even Y, `0x03` for
odd Y) followed by the 32-byte X coordinate. Use `PublicKey.GetCPK()` to obtain the compressed form and `CPK.Parse()` to
recover a `PublicKey` from it.

Signing Workflows
-----------------

The following examples show how to use the SDK to produce and consume credentials. Use **internal signing** when the
private key is available in-process, or **external signing** when the key is managed by an HSM or signing service.

### Internal signing

Use `SignV1()` when the private key is available in-process (or `Sign()` to select the version explicitly). The function:

1. Derives the compressed public key (CPK) from `key` and embeds it in the payload.
2. Validates all fields in the `Payload` (see [Data Types](#data-types) for constraints).
3. ASN.1 DER-encodes the `IOSSRTU` payload.
4. Computes a SHA-256 digest of the encoded payload.
5. Produces a DER-encoded ECDSA P-256 signature over the digest.
6. Wraps payload and signature into an `RTU` envelope.

```go
key, err := rtu.LoadPrivateKeyPEM(pemBytes)
if err != nil {
	panic(err)
}

payload := rtu.NewPayload("TX-2026-001", time.Now().Add(48*time.Hour)).
	SetDelegatedUse(false)

signed, err := rtu.SignV1(payload, key)
if err != nil {
	panic(err)
}

// Pack the RTU to its base64url form for QR code or API transport:
token, err := signed.Pack()
if err != nil {
	panic(err)
}
```
Do not set the CPK on the payload manually before calling `SignV1()` — the signer derives it from `key` and overwrites
any value you set.

### Verification

Use `PackedRTU.Unpack()` to decode and validate the envelope, then `RTU.Parse(true)` to verify the signature and validate
the credential payload:

```go
var packed rtu.PackedRTU = "...base64url_encoded_rtu..."

signed, err := packed.Unpack()
if err != nil {
	// envelope is not valid base64url, not valid DER, or fails envelope validation
	// (unknown version, size out of range, unsupported algorithm)
	panic(err)
}

payload, err := signed.Parse(true)
if err != nil {
	// signature verification failed, or a payload field is invalid
	panic(err)
}

// payload is a *rtu.Payload — decoded, signature-verified, and fully validated.
```

`Parse(true)` performs the following checks in order: parse the `IOSSRTU` payload, validate all fields, recover the
public key from the embedded CPK, and verify the ECDSA signature over the payload. Any failure returns a typed error
(`ErrDecoding`, `ErrSignatureInvalid`, or a `*ValidationError`).

If the source is trusted, validation can be skipped for performance by parsing with `withValidations` set to `false`.
This is not recommended unless you control the source — see the lower-level `PackedRTU.Raw()`, `RawRTU.Parse()`, and
`Version.Parse()` methods.

### External / HSM signing

Use `ExternalSigner` when the private key is held in a hardware security module (HSM) or a remote signing service. The
signer needs only the version and the `PublicKey` of the external key.

**Step 1 — compute the digest:**

`ComputeDigest()` embeds the CPK, encodes the payload, and returns both the payload bytes and the SHA-256 digest to sign
externally:

```go
signer := rtu.NewExternalSigner(rtu.Version1, publicKey)

payload := rtu.NewPayload("TX-HSM-001", time.Now().Add(48*time.Hour)).
	SetDelegatedUse(false)

digest, rawPayload, err := signer.ComputeDigest(payload)
if err != nil {
	panic(err)
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
	panic(err)
}

// token is the base64url PackedRTU, ready for the deposit service.
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
	panic(err)
}
key, err := rtu.LoadPrivateKeyPEM(pem)
```

To wrap an in-memory `*ecdsa.PrivateKey` (for example one returned by an HSM client), use `NewECPrivateKey()`; for a
public key only, use `NewECPublicKey()`.

### Compressed public key

Convert between a `PublicKey` and the 33-byte compressed SEC1 form:

```go
cpk := publicKey.GetCPK()             // PublicKey → 33-byte CPK
recovered, err := cpk.Parse(rtu.AlgorithmEcdsaP256) // CPK → PublicKey
```

### Deriving the public key from a private key

A `PrivateKey` embeds its `PublicKey`, so the public material is always available without recomputation:

```go
pub := key.GetPublicKey() // crypto.PublicKey
cpk := key.GetCPK()       // 33-byte compressed form
```

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

Errors
------

The SDK returns sentinel error values that can be matched with `errors.Is()`:

| Error                          | Returned when                                                                  |
|--------------------------------|--------------------------------------------------------------------------------|
| `ErrValidation`                | A field fails its constraint (wrapped by `*ValidationError`)                   |
| `ErrEncoding` / `ErrDecoding`  | ASN.1 DER encoding or decoding fails                                           |
| `ErrSignatureInvalid`          | Signature verification fails                                                   |
| `ErrSigning`                   | ECDSA signing fails                                                            |
| `ErrSignatureAlgorithmInvalid` | The signature algorithm is unknown or unsupported                             |
| `ErrNoSignatureAlgorithm`      | A signing operation is attempted with no algorithm set                         |
| `ErrCPKUnsupported`            | The compressed public key type is not supported                                |
| `ErrKeyInvalid`                | A key cannot be parsed, is not EC, is not on P-256, or does not match the CPK   |
| `ErrUnknownVersion`            | The `RTU` version is not recognised                                            |
| `ErrEmptyInput`                | A required payload or signature argument is empty                              |

Field-level validation failures are returned as `*ValidationError`, which carries the offending field name. Match it
with `errors.As()`:

```go
var verr *rtu.ValidationError
if errors.As(err, &verr) {
	fmt.Printf("field %q: %s\n", verr.Field, verr.Message)
}
```

`*ValidationError` unwraps to `ErrValidation`, so `errors.Is(err, rtu.ErrValidation)` also matches any field error.

ASN.1 Schema
------------

Credentials are encoded as ASN.1 DER, a compact and unambiguous binary format that is well-suited to QR-code transport
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