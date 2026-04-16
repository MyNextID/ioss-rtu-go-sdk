package rtu

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
)

// SignV1 signs the given Payload object with ECDSA-P256 and creates a Version1 RTU object
func SignV1(payload *Payload, privKey *ecdsa.PrivateKey) (*RTU, error) {
	raw, err := Version1.Make(payload.SetCPK(elliptic.MarshalCompressed(privKey.Curve, privKey.X, privKey.Y)))
	if err != nil {
		return nil, err
	}
	out := &RTU{
		RawVersion: int32(Version1),
		Payload:    raw,
		Signature:  nil,
		// Algorithm not set, as Version1 defines that algorithm is ommited (can only be ECDSA-P256)
	}
	hash := sha256.Sum256(raw)
	signature, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, err
	}
	out.Signature = signature
	return out, nil
}
