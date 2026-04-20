package rtu

import (
	"crypto/rand"
	"fmt"
)

type Signer func(payload *Payload, key *PrivateKey) (*RTU, error)

// Sign uses the given Version to generate an RTU object, then packs it and returns a PackedRTU
func Sign(version Version, payload *Payload, key *PrivateKey) (PackedRTU, error) {
	signer, err := version.Signer()
	if err != nil {
		return "", err
	}
	obj, err := signer(payload, key)
	if err != nil {
		return "", err
	}
	return obj.Pack()
}

// SignV1 signs the given Payload object with ECDSA-P256 and creates a
// Version1 RTU object.
func SignV1(payload *Payload, key *PrivateKey) (*RTU, error) {
	if key.Algorithm() != AlgorithmEcdsaP256 {
		return nil, fmt.Errorf("version 1 only support ecdsa-p256 private keys: %w", ErrKeyInvalid)
	}
	raw, err := Version1.Make(payload.SetCPK(key.GetCPK()))
	if err != nil {
		return nil, err
	}
	out := &RTU{
		Version:   Version1,
		Payload:   raw,
		Signature: nil,
		Algorithm: AlgorithmNone,
	}
	signature, err := key.Sign(rand.Reader, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSigning, err)
	}
	out.Signature = signature
	return out, nil
}
