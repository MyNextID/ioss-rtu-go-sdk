package rtu

import (
	"crypto/sha256"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
)

type SignatureAlgorithm string

func ParseJwa(alg jwa.SignatureAlgorithm) (SignatureAlgorithm, error) {
	switch alg {
	case jwa.ES256():
		return AlgorithmEcdsaP256, nil
	default:
		return AlgorithmNone, fmt.Errorf("%w: unknown jwa algorithm: %s", ErrSignatureAlgorithmInvalid, alg)
	}
}

const (
	AlgorithmNone      SignatureAlgorithm = ""
	AlgorithmEcdsaP256 SignatureAlgorithm = "ecdsa-p256"
)

// Digest returns the hash version of payload based on the SignatureAlgorithm given.
// if returned value is nil, it should be treated the same as an ErrSignatureAlgorithmInvalid.
func (s SignatureAlgorithm) Digest(payload []byte) []byte {
	switch s {
	case AlgorithmEcdsaP256:
		hash := sha256.New()
		hash.Write(payload)
		return hash.Sum(nil)
	default:
		return nil
	}
}

func (s SignatureAlgorithm) Validate() error {
	switch s {
	case AlgorithmEcdsaP256:
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrSignatureAlgorithmInvalid, s)
	}
}

// ToJWA returns the JSON Web Token Algorithm string for the given SignatureAlgorithm
func (s SignatureAlgorithm) ToJWA() (jwa.SignatureAlgorithm, error) {
	switch s {
	case AlgorithmEcdsaP256:
		return jwa.ES256(), nil
	default:
		return jwa.EmptySignatureAlgorithm(), fmt.Errorf("%w: %s", ErrSignatureAlgorithmInvalid, s)
	}
}
