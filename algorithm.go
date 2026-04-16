package rtu

import (
	"crypto/ecdsa"
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

// Verify verifies the signature, based on the given pubKey and payload.
// payload must not already be digested, as this function takes care of that.
// pubKey can be a CPK, in which case this method will parse the CPK and get the correct key
func (s SignatureAlgorithm) Verify(pubKey any, payload []byte, signature []byte) (bool, error) {
	// if pubKey received is CPK, we can parse it here
	if cpk, ok := pubKey.(CPK); ok {
		var err error
		pubKey, err = cpk.Parse(s)
		if err != nil {
			return false, err
		}
	}
	switch s {
	case AlgorithmEcdsaP256:
		if key, ok := pubKey.(*ecdsa.PublicKey); ok {
			return ecdsa.VerifyASN1(key, s.Digest(payload), signature), nil
		} else {
			return false, ErrKeyInvalid
		}
	default:
		return false, ErrSignatureAlgorithmInvalid
	}
}
