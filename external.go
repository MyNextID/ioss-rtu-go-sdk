package rtu

import (
	"bytes"
	"fmt"
)

type ExternalSigner struct {
	version            Version
	signatureAlgorithm SignatureAlgorithm
	pubKey             any

	computedCPK CPK
}

func NewExternalSigner(version Version, signatureAlgorithm SignatureAlgorithm, pubKey any) (*ExternalSigner, error) {
	out := &ExternalSigner{
		version:            version,
		signatureAlgorithm: signatureAlgorithm,
		pubKey:             pubKey,
	}
	var err error
	out.computedCPK, err = NewCPK(pubKey, signatureAlgorithm)
	return out, err
}

func (e *ExternalSigner) Version() Version {
	return e.version
}

func (e *ExternalSigner) SignatureAlgorithm() SignatureAlgorithm {
	return e.signatureAlgorithm
}

func (e *ExternalSigner) ComputeDigest(data *Payload) (digest []byte, payload []byte, err error) {
	payload, err = e.version.Make(data.SetCPK(e.computedCPK))
	if err != nil {
		return nil, nil, err
	}
	return e.signatureAlgorithm.Digest(payload), payload, nil
}

func (e *ExternalSigner) ConstructSigned(payload []byte, signature []byte) (RawRTU, error) {
	obj, err := e.ConstructSignedObj(payload, signature)
	if err != nil {
		return nil, err
	}
	return obj.Raw()
}

func (e *ExternalSigner) ConstructSignedPacked(payload []byte, signature []byte) (PackedRTU, error) {
	raw, err := e.ConstructSigned(payload, signature)
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
	if !bytes.Equal(parsedPayload.CPK(), e.computedCPK) {
		return nil, fmt.Errorf("payload CPK is not equal to our public key: %w", ErrKeyInvalid)
	}
	// verify received signature with our public key
	ok, err := e.signatureAlgorithm.Verify(e.pubKey, payload, signature)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrSignatureInvalid
	}
	alg := e.signatureAlgorithm
	if e.signatureAlgorithm == e.version.DefaultSignatureAlgorithm() {
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
