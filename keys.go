package rtu

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

type PublicKey struct {
	pubKey crypto.PublicKey
	alg    SignatureAlgorithm

	computedCPK CPK
}

func newPublicKey(pubKey any, alg SignatureAlgorithm, computedCpk CPK) (PublicKey, error) {
	if computedCpk == nil {
		var err error
		computedCpk, err = NewCPK(pubKey, alg)
		if err != nil {
			return PublicKey{}, err
		}
	}
	return PublicKey{
		pubKey:      pubKey,
		alg:         alg,
		computedCPK: computedCpk,
	}, nil
}

func NewECPublicKey(pub *ecdsa.PublicKey) (PublicKey, error) {
	if pub.Curve != elliptic.P256() {
		return PublicKey{}, fmt.Errorf("%w: key must use P-256 curve", ErrKeyInvalid)
	}
	return newPublicKey(pub, AlgorithmEcdsaP256, nil)
}

// Algorithm returns the SignatureAlgorithm that this PublicKey uses
func (p PublicKey) Algorithm() SignatureAlgorithm {
	return p.alg
}

// GetCPK returns the CPK for this PublicKey
func (p PublicKey) GetCPK() CPK {
	return p.computedCPK
}

// GetPublicKey returns the raw publicKey of this PublicKey structure
func (p PublicKey) GetPublicKey() crypto.PublicKey {
	return p.pubKey
}

// Verify verifies the signature, based on the given pubKey and payload.
// payload must not already be digested, as this function takes care of that.
// pubKey can be a CPK, in which case this method will parse the CPK and get the correct key
func (p PublicKey) Verify(payload []byte, signature []byte) (bool, error) {
	switch p.alg {
	case AlgorithmEcdsaP256:
		if key, ok := p.pubKey.(*ecdsa.PublicKey); ok {
			return ecdsa.VerifyASN1(key, p.alg.Digest(payload), signature), nil
		} else {
			return false, ErrKeyInvalid
		}
	default:
		return false, ErrSignatureAlgorithmInvalid
	}
}

// PrivateKey is a helper structure, that wraps a private key with a SignatureAlgorithm.
// It also generates its own CPK and exposes a common Sign method, for easier integration
// with potential other SignatureAlgorithms down the line.
type PrivateKey struct {
	privKey any

	PublicKey
}

// NewECPrivateKey only accepts P-256 private keys for now (because only AlgorithmEcdsaP256 is added)
func NewECPrivateKey(priv *ecdsa.PrivateKey) (*PrivateKey, error) {
	pub, err := NewECPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		privKey:   priv,
		PublicKey: pub,
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
