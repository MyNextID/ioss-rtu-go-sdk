package rtu

import (
	"fmt"
)

type SignatureAlgorithm string

const (
	AlgorithmNone      SignatureAlgorithm = ""
	AlgorithmEcdsaP256 SignatureAlgorithm = "ecdsa-p256"
)

func (s SignatureAlgorithm) Verify(pubKey any, payload []byte, signature []byte) (bool, error) {
	verify, ok := verifierRegistry[s]
	if !ok {
		return false, fmt.Errorf("unknown signature algorithm: %s", s)
	}
	return verify(pubKey, payload, signature)
}
