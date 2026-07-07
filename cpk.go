package rtu

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
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
		}
		return nil, fmt.Errorf("%s expects *ecdsa.GetPublicKey: %w", algorithm, ErrKeyInvalid)
	default:
		return nil, fmt.Errorf("unknown signature algorithm: %s: %w", algorithm, ErrCPKUnsupported)
	}
}

// Parse tries to parse a public key, based on SignatureAlgorithm
func (c CPK) Parse(algorithm SignatureAlgorithm) (PublicKey, error) {
	return validateCPK(algorithm, c)
}

func (c CPK) Pack() PackedCPK {
	return PackedCPK(base64.RawURLEncoding.EncodeToString(c))
}

type PackedCPK string

func (p PackedCPK) CPK() (CPK, error) {
	out, err := base64.RawURLEncoding.DecodeString(string(p))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode PackedCPK", ErrDecoding)
	}
	return out, nil
}

func (p PackedCPK) PublicKey(algorithm SignatureAlgorithm) (PublicKey, error) {
	temp, err := p.CPK()
	if err != nil {
		return nil, err
	}
	return temp.Parse(algorithm)
}
