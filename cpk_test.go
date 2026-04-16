package rtu_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

func generatePrivateKey(t *testing.T) *ecdsa.PrivateKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func generateCPK(priv *ecdsa.PrivateKey, t *testing.T) rtu.CPK {
	return elliptic.MarshalCompressed(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y)
}

func TestCPK_Parse(t *testing.T) {
	priv := generatePrivateKey(t)
	cpk := generateCPK(priv, t)
	pub, err := cpk.Parse(rtu.AlgorithmEcdsaP256)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.PublicKey.Equal(pub) {
		t.Fatal("invalid public key")
	}
}
