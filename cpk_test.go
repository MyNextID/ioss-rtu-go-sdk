package rtu_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

func generatePrivateKey(t *testing.T) *rtu.PrivateKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	out, err := rtu.NewECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCPK_Parse(t *testing.T) {
	priv := generatePrivateKey(t)
	cpk := priv.GetCPK()
	_, err := cpk.Parse(rtu.AlgorithmEcdsaP256)
	if err != nil {
		t.Fatal(err)
	}
}
