package rtu_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
	"github.com/MyNextID/ioss-rtu-go-sdk/internal/helpers"
)

// =====================================================
// AlgorithmEcdsaP256 test-suite
// =====================================================
func TestAlgorithmEcdsaP256_Digest(t *testing.T) {
	t.Parallel()

	payload := []byte{0}
	hash := sha256.Sum256(payload)
	expectedResult := hash[:]

	result := rtu.AlgorithmEcdsaP256.Digest(payload)

	if !bytes.Equal(result, expectedResult) {
		t.Fatalf("Digest() result does not match expected result")
	}
}

func TestAlgorithmEcdsaP256_VerifyValidSignature(t *testing.T) {
	t.Parallel()

	priv, err := rtu.NewECPrivateKey(helpers.GenerateKey(t))
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte{0}

	rtuType := helpers.GetASN1Type()

	signature, err := priv.Sign(rtuType, rand.Reader, payload)
	if err != nil {
		t.Fatal(err)
	}

	err = priv.Public().Verify(rtuType, payload, signature)
	if err != nil {
		t.Errorf("Verify() unexepected error, got %v", err)
	}
}

func TestAlgorithmEcdsaP256_VerifyInvalidSignature(t *testing.T) {
	t.Parallel()

	priv, err := rtu.NewECPrivateKey(helpers.GenerateKey(t))
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte{0}

	rtuType := helpers.GetASN1Type()

	signature, err := priv.Sign(rtuType, rand.Reader, payload)
	if err != nil {
		t.Fatal(err)
	}

	// tamper with signature
	signature[len(signature)/2] ^= 0xFF

	err = priv.Public().Verify(rtuType, payload, signature)
	if err == nil {
		t.Errorf("Verify() expected error")
	}
}
