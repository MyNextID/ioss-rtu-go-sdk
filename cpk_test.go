package rtu_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

func generateCPK(t *testing.T) (*ecdsa.PrivateKey, rtu.CPK) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cpk := rtu.CPK(elliptic.MarshalCompressed(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y))
	return priv, cpk
}

func TestNewCPK(t *testing.T) {
	generateCPK(t)
}

func TestCPK_Parse(t *testing.T) {
	priv, cpk := generateCPK(t)
	pub, err := cpk.Parse(rtu.AlgorithmEcdsaP256)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.PublicKey.Equal(pub) {
		t.Fatal("invalid public key")
	}
}
