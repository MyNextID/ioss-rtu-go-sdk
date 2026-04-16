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

func NewCPK(pubKey any, algorithm SignatureAlgorithm) (CPK, error) {
	switch algorithm {
	case AlgorithmEcdsaP256:
		if key, ok := pubKey.(*ecdsa.PublicKey); ok {
			if key.Curve.Params().BitSize != 256 {
				return nil, fmt.Errorf("%s expects ecdsa.PublicKey from P-256 curve, not %s: %w", algorithm, key.Curve, ErrCPKUnsupported)
			}
			return elliptic.MarshalCompressed(key.Curve, key.X, key.Y), nil
		} else {
			return nil, fmt.Errorf("%s expects *ecdsa.PublicKey: %w", algorithm, ErrKeyInvalid)
		}
	default:
		return nil, fmt.Errorf("unknown signature algorithm: %s: %w", algorithm, ErrCPKUnsupported)
	}
}

// Parse tries to parse a public key, based on SignatureAlgorithm
func (c CPK) Parse(algorithm SignatureAlgorithm) (any, error) {
	switch algorithm {
	case AlgorithmEcdsaP256:
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), c)
		if x == nil {
			return nil, fmt.Errorf("%s failed to unmarshal cpk: %w", algorithm, ErrKeyInvalid)
		}
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}, nil
	default:
		return nil, fmt.Errorf("unknown signature algorithm: %s: %w", algorithm, ErrCPKUnsupported)
	}
}
