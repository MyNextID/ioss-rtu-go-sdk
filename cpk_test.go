package rtu_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
	"github.com/MyNextID/ioss-rtu-go-sdk/internal/helpers"
)

func getCPK(tb testing.TB) rtu.CPK {
	out, _ := getCPKAndSignatureAlgorithm(tb)
	return out
}

func getCPKAndSignatureAlgorithm(tb testing.TB) (rtu.CPK, rtu.SignatureAlgorithm) {
	tb.Helper()
	priv := helpers.GenerateRTUPrivateKey(tb)
	return priv.Public().CPK(), priv.Public().Algorithm()
}

func TestCPK_Parse(t *testing.T) {
	cpk := getCPK(t)
	_, err := cpk.Parse(rtu.AlgorithmEcdsaP256)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCPK_Pack(t *testing.T) {
	cpk := getCPK(t)

	packedCpk := cpk.Pack()

	if len(packedCpk) == 0 {
		t.Fatalf("Pack() unexpected length of PackedCPK: %v", len(packedCpk))
	}

	raw, err := base64.RawURLEncoding.DecodeString(string(packedCpk))
	if err != nil {
		t.Fatalf("Pack() failed to decode PackedCPK: %v", err)
	}

	if !bytes.Equal(raw, cpk) {
		t.Fatalf("Pack() decoded raw CPK does not match initial packed CPK")
	}
}

func TestPackedCPK_CPK(t *testing.T) {
	cpk := getCPK(t)
	packedCpk := cpk.Pack()

	parsedCpk, err := packedCpk.CPK()
	if err != nil {
		t.Fatalf("PackedCPK.CPK() failed: %v", err)
	}

	if !bytes.Equal(parsedCpk, cpk) {
		t.Fatalf("PackedCPK.CPK() returned CPK does not match original CPK")
	}
}

func TestPackedCPK_PublicKey(t *testing.T) {
	cpk, alg := getCPKAndSignatureAlgorithm(t)

	packedCpk := cpk.Pack()

	publicKey, err := packedCpk.PublicKey(alg)
	if err != nil {
		t.Fatalf("PackedCPK.PublicKey() failed: %v", err)
	}

	if !bytes.Equal(publicKey.CPK(), cpk) {
		t.Fatalf("PackedCPK.PublicKey() returned CPK does not match original CPK")
	}
}
