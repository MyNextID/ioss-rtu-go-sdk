package rtu

import (
	"crypto/sha256"
)

type SignatureAlgorithm string

const (
	AlgorithmNone      SignatureAlgorithm = ""
	AlgorithmEcdsaP256 SignatureAlgorithm = "ecdsa-p256"
)

// Digest returns the hash version of payload based on the SignatureAlgorithm given.
// if returned value is nil, it should be treated the same as an ErrSignatureAlgorithmInvalid.
func (s SignatureAlgorithm) Digest(payload []byte) []byte {
	switch s {
	case AlgorithmNone:
		return nil
	case AlgorithmEcdsaP256:
		hash := sha256.Sum256(payload)
		return hash[:]
	default:
		return nil
	}
}
