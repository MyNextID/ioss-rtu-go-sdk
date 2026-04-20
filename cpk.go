package rtu

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
)

// CPK - Compressed Public Key is a binary representation of a public key.
// Together with a SignatureAlgorithm, it should be possible to get a public key
// from this value.
type CPK []byte

// NewCPK creates a CPK representation of the given pubKey and SignatureAlgorithm.
func NewCPK(pubKey any, algorithm SignatureAlgorithm) (CPK, error) {
	switch algorithm {
	case AlgorithmEcdsaP256:
		if key, ok := pubKey.(*ecdsa.PublicKey); ok {
			if key.Curve.Params().BitSize != 256 {
				return nil, fmt.Errorf("%s expects ecdsa.GetPublicKey from P-256 curve, not %s: %w", algorithm, key.Curve, ErrCPKUnsupported)
			}
			return elliptic.MarshalCompressed(key.Curve, key.X, key.Y), nil
		} else {
			return nil, fmt.Errorf("%s expects *ecdsa.GetPublicKey: %w", algorithm, ErrKeyInvalid)
		}
	default:
		return nil, fmt.Errorf("unknown signature algorithm: %s: %w", algorithm, ErrCPKUnsupported)
	}
}

// Parse tries to parse a public key, based on SignatureAlgorithm
func (c CPK) Parse(algorithm SignatureAlgorithm) (PublicKey, error) {
	switch algorithm {
	case AlgorithmEcdsaP256:
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), c)
		if x == nil {
			return PublicKey{}, fmt.Errorf("%s failed to unmarshal cpk: %w", algorithm, ErrKeyInvalid)
		}
		return newPublicKey(&ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}, algorithm, c)
	default:
		return PublicKey{}, fmt.Errorf("unknown signature algorithm: %s: %w", algorithm, ErrCPKUnsupported)
	}
}
