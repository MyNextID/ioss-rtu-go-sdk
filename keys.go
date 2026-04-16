package rtu

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

type PrivateKey struct {
	privKey any
	alg     SignatureAlgorithm

	computedCPK CPK
}

func NewECPrivateKey(priv *ecdsa.PrivateKey) (*PrivateKey, error) {
	if priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: key must use P-256 curve", ErrKeyInvalid)
	}
	cpk, err := NewCPK(&priv.PublicKey, AlgorithmEcdsaP256)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		privKey:     priv,
		alg:         AlgorithmEcdsaP256,
		computedCPK: cpk,
	}, nil
}

// LoadPrivateKeyPEM parses a PEM-encoded EC private key.
// Accepts both PKCS#8 ("PRIVATE KEY") and SEC1 ("EC PRIVATE KEY") formats.
func LoadPrivateKeyPEM(pemBytes []byte) (*PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", ErrKeyInvalid)
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse PKCS#8 key: %w", ErrKeyInvalid, err)
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: PKCS#8 key is not ECDSA", ErrKeyInvalid)
		}
		return NewECPrivateKey(ecKey)

	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse SEC1 key: %w", ErrKeyInvalid, err)
		}
		return NewECPrivateKey(key)

	default:
		return nil, fmt.Errorf("%w: unsupported PEM block type %q", ErrKeyInvalid, block.Type)
	}
}

// Algorithm returns the SignatureAlgorithm that this PrivateKey uses
func (p *PrivateKey) Algorithm() SignatureAlgorithm {
	return p.alg
}

// GetCPK returns the CPK for this PrivateKey
func (p *PrivateKey) GetCPK() CPK {
	return p.computedCPK
}

// Sign allows this private key to sign the given payload, by digesting it with SignatureAlgorithm
// and based on the same algorithm apply the correct signature function, outputting signature and any
// errors that happened while signing.
func (p *PrivateKey) Sign(rand io.Reader, payload []byte) ([]byte, error) {
	switch p.alg {
	case AlgorithmNone:
		return nil, ErrNoSignatureAlgorithm
	case AlgorithmEcdsaP256:
		return ecdsa.SignASN1(rand, p.privKey.(*ecdsa.PrivateKey), p.alg.Digest(payload))
	default:
		return nil, ErrSignatureAlgorithmInvalid
	}
}
