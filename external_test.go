package rtu_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"testing"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
	"github.com/MyNextID/ioss-rtu-go-sdk/internal/helpers"
)

// externalSign simulates an HSM or remote signing service.
// It signs the digest using raw ECDSA, independent of any SDK signing path.
func externalSign(t *testing.T, privKey *ecdsa.PrivateKey, digest []byte) []byte {
	t.Helper()

	sig, err := ecdsa.SignASN1(rand.Reader, privKey, digest)
	if err != nil {
		t.Fatalf("externalSign: ecdsa.SignASN1 unexpected error: %v", err)
	}

	return sig
}

func makeVersion1ExternalSigner(tb testing.TB, pubKey *ecdsa.PublicKey) *rtu.ExternalSigner {
	out, err := rtu.NewExternalSigner(rtu.Version1, rtu.AlgorithmEcdsaP256, pubKey)
	if err != nil {
		tb.Fatal(err)
	}
	return out
}

// =============================================================================
// ComputeDigest
// =============================================================================

func TestComputeDigest_ValidRTU_ReturnsDigestAndPayload(t *testing.T) {
	t.Parallel()

	rtu := helpers.MinimalRTU()
	signer := makeVersion1ExternalSigner(t, &helpers.GenerateKey(t).PublicKey)

	digest, payload, err := signer.ComputeDigest(rtu)
	if err != nil {
		t.Fatalf("ComputeDigest() unexpected error: %v", err)
	}
	if len(digest) != 32 {
		t.Errorf("digest must be 32 bytes, got %d", len(digest))
	}
	if len(payload) == 0 {
		t.Error("payload must not be empty")
	}
}

func TestComputeDigest_DigestMatchesSHA256OfPayload(t *testing.T) {
	t.Parallel()

	rtu := helpers.MinimalRTU()
	signer := makeVersion1ExternalSigner(t, &helpers.GenerateKey(t).PublicKey)

	digest, payload, err := signer.ComputeDigest(rtu)
	if err != nil {
		t.Fatalf("ComputeDigest() unexpected error: %v", err)
	}

	// The digest must equal sha256(payload) — this is what the external signer
	// will receive and sign.
	expected := signer.SignatureAlgorithm().Digest(payload)
	if string(digest) != string(expected[:]) {
		t.Error("digest does not match correct hash value of payload")
	}
}

func TestComputeDigest_PayloadDecodesBackToOriginalRTU(t *testing.T) {
	t.Parallel()

	original := helpers.FullRTU()
	signer := makeVersion1ExternalSigner(t, &helpers.GenerateKey(t).PublicKey)

	_, payload, err := signer.ComputeDigest(original)
	if err != nil {
		t.Fatalf("ComputeDigest() unexpected error: %v", err)
	}

	// validation turned to false, as we are just checking, if payload is valid
	decoded, err := signer.Version().Parse(payload, false)
	if err != nil {
		t.Fatalf("Version.Parse on payload unexpected error: %v", err)
	}

	helpers.AssertPayloadEqual(t, original, decoded)
}

// =============================================================================
// ConstructSigned
// =============================================================================

func TestConstructSigned_ValidInputs_ProducesDecodableSignedData(t *testing.T) {
	t.Parallel()

	privKey := helpers.GenerateKey(t)
	original := helpers.MinimalRTU()
	signer := makeVersion1ExternalSigner(t, &privKey.PublicKey)

	digest, payload, err := signer.ComputeDigest(original)
	if err != nil {
		t.Fatalf("ComputeDigest() unexpected error: %v", err)
	}

	sig := externalSign(t, privKey, digest)

	signedBytes, err := signer.ConstructSigned(payload, sig)
	if err != nil {
		t.Fatalf("ConstructSigned() unexpected error: %v", err)
	}

	if len(signedBytes) == 0 {
		t.Fatal("ConstructSigned() returned empty bytes")
	}

	parsedRtu, err := signedBytes.Parse(true)
	if err != nil {
		t.Fatalf("PackedRTU.Unpack() unexpected error: %v", err)
	}
	if parsedRtu.Version != signer.Version() {
		t.Errorf("Version: got %d, want %d", parsedRtu.Version, signer.Version())
	}

	if !bytes.Equal(parsedRtu.Payload, payload) {
		t.Errorf("Payload: got %v, want %v", parsedRtu.Payload, payload)
	}
}

func TestConstructSigned_EmptyPayload_ReturnsErrEmptyInput(t *testing.T) {
	t.Parallel()

	privKey := helpers.GenerateKey(t)
	sig := externalSign(t, privKey, make([]byte, 32))
	signer := makeVersion1ExternalSigner(t, &privKey.PublicKey)

	_, err := signer.ConstructSigned([]byte{}, sig)
	if err == nil {
		t.Fatal("ConstructSigned() expected error for empty payload, got nil")
	}
	if !errors.Is(err, rtu.ErrEmptyInput) {
		t.Errorf("expected ErrEmptyInput, got %v", err)
	}
}

func TestConstructSigned_EmptySignature_ReturnsErrEmptyInput(t *testing.T) {
	t.Parallel()

	privKey := helpers.GenerateKey(t)
	original := helpers.MinimalRTU()
	signer := makeVersion1ExternalSigner(t, &privKey.PublicKey)

	_, payload, err := signer.ComputeDigest(original)
	if err != nil {
		t.Fatalf("ComputeDigest() unexpected error: %v", err)
	}

	_, err = signer.ConstructSigned(payload, []byte{})
	if err == nil {
		t.Fatal("ConstructSigned() expected error for empty signature, got nil")
	}
	if !errors.Is(err, rtu.ErrEmptyInput) {
		t.Errorf("expected ErrEmptyInput, got %v", err)
	}
}

func TestConstructSigned_InvalidSignatureEncoding_ReturnsErrSignatureInvalid(t *testing.T) {
	t.Parallel()

	original := helpers.MinimalRTU()
	signer := makeVersion1ExternalSigner(t, &helpers.GenerateKey(t).PublicKey)

	_, payload, err := signer.ComputeDigest(original)
	if err != nil {
		t.Fatalf("ComputeDigest() unexpected error: %v", err)
	}

	// Raw r‖s bytes are not valid ASN.1 DER — ConstructSigned must reject them.
	rawSig := make([]byte, 64)
	if _, err = rand.Read(rawSig); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	_, err = signer.ConstructSigned(payload, rawSig)
	if err == nil {
		t.Fatal("ConstructSigned() expected error for non-DER signature, got nil")
	}
	if !errors.Is(err, rtu.ErrSignatureInvalid) {
		t.Errorf("expected ErrSignatureInvalid, got %v", err)
	}
}

// =============================================================================
// Full external-signing round-trip
// =============================================================================

func TestExternalSigning_RoundTrip_VerifySucceeds(t *testing.T) {
	t.Parallel()

	privKey := helpers.GenerateKey(t)
	original := helpers.FullRTU()
	signer := makeVersion1ExternalSigner(t, &privKey.PublicKey)

	// Step 1: compute digest and payload (what the API would return to the caller).
	digest, payload, err := signer.ComputeDigest(original)
	if err != nil {
		t.Fatalf("ComputeDigest() unexpected error: %v", err)
	}

	// Step 2: caller signs the digest with their external key (HSM simulation).
	sig := externalSign(t, privKey, digest)

	// Step 3: caller submits the stored payload + signature back.
	signedBytes, err := signer.ConstructSignedObj(payload, sig)
	if err != nil {
		t.Fatalf("ConstructSigned() unexpected error: %v", err)
	}

	// Step 4: verifier validates the full SignedData.
	recovered, err := signedBytes.Parse(true)
	if err != nil {
		t.Fatalf("RTU.Parse() unexpected error: %v", err)
	}

	helpers.AssertPayloadEqual(t, original, recovered)
}

func TestExternalSigning_WrongKeyAtVerify_ReturnsErrSignatureInvalid(t *testing.T) {
	t.Parallel()

	signingKey := helpers.GenerateKey(t)
	otherKey := helpers.GenerateKey(t)

	signer := makeVersion1ExternalSigner(t, &signingKey.PublicKey)
	otherSigner := makeVersion1ExternalSigner(t, &otherKey.PublicKey)

	digest, payload, err := signer.ComputeDigest(helpers.MinimalRTU())
	if err != nil {
		t.Fatalf("ComputeDigest() unexpected error: %v", err)
	}

	sig := externalSign(t, signingKey, digest)

	_, err = otherSigner.ConstructSigned(payload, sig)
	if err == nil {
		t.Fatalf("ConstructSigned() expected error for wrong public key, got nil")
	}
	if !errors.Is(err, rtu.ErrKeyInvalid) {
		t.Errorf("expected ErrKeyInvalid, got %v", err)
	}
}

func TestExternalSigning_TamperedPayloadAfterConstruct_ReturnsError(t *testing.T) {
	t.Parallel()

	privKey := helpers.GenerateKey(t)
	signer := makeVersion1ExternalSigner(t, &privKey.PublicKey)

	digest, payload, err := signer.ComputeDigest(helpers.MinimalRTU())
	if err != nil {
		t.Fatalf("ComputeDigest() unexpected error: %v", err)
	}

	sig := externalSign(t, privKey, digest)

	signedObj, err := signer.ConstructSignedObj(payload, sig)
	if err != nil {
		t.Fatalf("ConstructSigned() unexpected error: %v", err)
	}

	// Tamper with the middle of the signed blob.
	tampered := make([]byte, len(signedObj.Payload))
	copy(tampered, signedObj.Payload)
	tampered[len(tampered)/2] ^= 0xFF

	signedObj.Payload = tampered

	_, err = signedObj.Parse(true)
	if err == nil {
		t.Fatal("Verify() expected error for tampered signed data, got nil")
	}
	validationErr := &rtu.ValidationError{}
	if !errors.Is(err, rtu.ErrSignatureInvalid) &&
		!errors.Is(err, rtu.ErrDecoding) && !errors.As(err, &validationErr) {
		t.Errorf("expected ErrSignatureInvalid or ErrDecoding, got %v", err)
	}
}

// TestExternalSigning_InvalidSignatureRejectedByConstruct confirms that
// ConstructSigned rejects a syntactically valid but cryptographically invalid
// ASN.1 DER ECDSA signature. Cryptographic verification against the CPK
// embedded in the RTU is performed as part of construction.
func TestExternalSigning_InvalidSignatureRejectedByConstruct(t *testing.T) {
	t.Parallel()

	signingKey := helpers.GenerateKey(t)
	otherKey := helpers.GenerateKey(t)

	signer := makeVersion1ExternalSigner(t, &signingKey.PublicKey)

	digest, payload, err := signer.ComputeDigest(helpers.MinimalRTU())
	if err != nil {
		t.Fatalf("ComputeDigest() unexpected error: %v", err)
	}

	// sign the signature with another key, syntax of the signature is correct, but incorrect signature
	dummySig := externalSign(t, otherKey, digest)

	// ConstructSigned must reject a signature that does not verify against the CPK.
	_, err = signer.ConstructSigned(payload, dummySig)
	if !errors.Is(err, rtu.ErrSignatureInvalid) {
		t.Errorf("ConstructSigned() expected ErrSignatureInvalid for invalid signature, got: %v", err)
	}
}
