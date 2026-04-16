package rtu

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
)

/*
	This file registers all signature algorithm verifiers
*/

func init() {
	RegisterSignatureAlgorithm(AlgorithmEcdsaP256, func(pubKey any, payload []byte, signature []byte) (bool, error) {
		if pub, ok := pubKey.(*ecdsa.PublicKey); !ok {
			return false, ErrKeyInvalid
		} else {
			hash := sha256.Sum256(payload)
			return ecdsa.VerifyASN1(pub, hash[:], signature), nil
		}
	}, func(bytes CPK) (any, error) {
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), bytes)
		if x == nil || y == nil {
			return nil, ErrKeyInvalid
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	})
}
