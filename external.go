package rtu

import (
	"bytes"
	"fmt"
)

type ExternalSigner struct {
	version   Version
	publicKey PublicKey
}

func NewExternalSigner(version Version, publicKey PublicKey) *ExternalSigner {
	return &ExternalSigner{
		version:   version,
		publicKey: publicKey,
	}
}

func (e *ExternalSigner) Version() Version {
	return e.version
}

func (e *ExternalSigner) SignatureAlgorithm() SignatureAlgorithm {
	return e.publicKey.Algorithm()
}

func (e *ExternalSigner) ComputeDigest(data *Payload) (digest []byte, payload []byte, err error) {
	payload, err = e.version.Make(data.SetCPK(e.publicKey.GetCPK()))
	if err != nil {
		return nil, nil, err
	}
	return e.SignatureAlgorithm().Digest(payload), payload, nil
}

func (e *ExternalSigner) ConstructSignedRaw(payload []byte, signature []byte) (RawRTU, error) {
	obj, err := e.ConstructSignedObj(payload, signature)
	if err != nil {
		return nil, err
	}
	return obj.Raw()
}

func (e *ExternalSigner) ConstructSigned(payload []byte, signature []byte) (PackedRTU, error) {
	raw, err := e.ConstructSignedRaw(payload, signature)
	if err != nil {
		return "", err
	}
	return raw.Pack(), nil
}

func (e *ExternalSigner) ConstructSignedObj(payload []byte, signature []byte) (*RTU, error) {
	if len(payload) == 0 {
		return nil, ErrEmptyInput
	}
	if len(signature) == 0 {
		return nil, ErrEmptyInput
	}
	parsedPayload, err := e.version.Parse(payload, true)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(parsedPayload.CPK(), e.publicKey.GetCPK()) {
		return nil, fmt.Errorf("payload CPK is not equal to our public key: %w", ErrKeyInvalid)
	}
	// verify received signature with our public key
	ok, err := e.publicKey.Verify(payload, signature)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrSignatureInvalid
	}
	alg := e.SignatureAlgorithm()
	if alg == e.version.DefaultSignatureAlgorithm() {
		// do not set algorithm, if it is the same as default,
		// as Algorithm is an optional field in RTU
		alg = AlgorithmNone
	}
	return &RTU{
		Version:   e.version,
		Payload:   payload,
		Signature: signature,
		Algorithm: alg,
	}, nil
}
