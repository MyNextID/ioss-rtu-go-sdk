package rtu

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

type Verifier interface {
	// Verify verifies the signature, based on the given pubKey and payload.
	// payload must not already be digested, as this function takes care of that.
	// Type is needed, to correctly prepare the verification of the signature
	// (jwt signature != asn1 signature formats)
	Verify(rtuType Type, payload, signature []byte) error
}

type PublicKey interface {
	Verifier
	// CPK returns the rtu.CPK of this PublicKey
	CPK() CPK
	// Algorithm returns the SignatureAlgorithm of this PublicKey
	Algorithm() SignatureAlgorithm
	// Raw returns the raw publicKey (from go stdlib) of this PublicKey structure
	Raw() crypto.PublicKey
	// Equal returns if the public key is equal to the other (not same pointer, but same public key internally)
	Equal(other PublicKey) bool
}

type PublicKeyJWK interface {
	PublicKey
	// JWK returns the jwk.Key of this PublicKey.
	// If a PublicKey implements this interface, JWT RTUs will have the "jwk" header instead of "cpk"
	JWK() jwk.Key
}

type publicKeyMetadata struct {
	cpk CPK
	alg SignatureAlgorithm
}

func newPublicKeyMetadata(cpk CPK, alg SignatureAlgorithm) publicKeyMetadata {
	return publicKeyMetadata{
		cpk: cpk,
		alg: alg,
	}
}

func (p publicKeyMetadata) CPK() CPK {
	return p.cpk
}

func (p publicKeyMetadata) Algorithm() SignatureAlgorithm {
	return p.alg
}

func (p publicKeyMetadata) Verify(payload, signature []byte) error {
	// this should be called with every implementation of publicKeyMetadata. This only verifies the inputs
	if len(payload) == 0 {
		return ErrPayloadIsNil
	}
	if len(signature) == 0 {
		return ErrSignatureIsNil
	}
	return nil
}

type ecdsaPublicKey struct {
	publicKeyMetadata
	key *ecdsa.PublicKey
}

// NewECPublicKey creates a PublicKey from an *ecdsa.PublicKey
func NewECPublicKey(pub *ecdsa.PublicKey) (PublicKey, error) {
	alg := AlgorithmNone
	switch pub.Curve {
	case elliptic.P256():
		alg = AlgorithmEcdsaP256
	}
	if alg == AlgorithmNone {
		return nil, fmt.Errorf("%w: key must use P-256 curve", ErrKeyInvalid)
	}
	cpk, err := NewCPK(pub, alg)
	if err != nil {
		return nil, err
	}
	return &ecdsaPublicKey{
		publicKeyMetadata: newPublicKeyMetadata(cpk, alg),
		key:               pub,
	}, nil
}

func (p *ecdsaPublicKey) Verify(rtuType Type, payload, signature []byte) error {
	if err := p.publicKeyMetadata.Verify(payload, signature); err != nil {
		return err
	}
	switch rtuType.Format() {
	case JWT:
		r := new(big.Int)
		s := new(big.Int)
		if len(signature) != 64 {
			return fmt.Errorf("%w: invalid signature length", ErrSignatureInvalid)
		}
		r.SetBytes(signature[:32])
		s.SetBytes(signature[32:])
		ecdsa.Verify(p.key, p.alg.Digest(payload), r, s)
	default:
		if !ecdsa.VerifyASN1(p.key, p.alg.Digest(payload), signature) {
			return fmt.Errorf("%w: ECDSA signature verification failed", ErrSignatureInvalid)
		}
	}
	return nil
}

func (p *ecdsaPublicKey) Equal(other PublicKey) bool {
	return p.key.Equal(other.Raw())
}

func (p *ecdsaPublicKey) Raw() crypto.PublicKey {
	return p.key
}

type jwkPublicKey struct {
	jwk     jwk.Key
	wrapped PublicKey
}

// NewJWKPublicKey creates a PublicKeyJWK from the given jwk.Key. Only jwk.ECDSAPublicKey is currently supported
func NewJWKPublicKey(key jwk.Key) (PublicKeyJWK, error) {
	switch pub := key.(type) {
	case jwk.ECDSAPublicKey:
		exportedEcKey := new(ecdsa.PublicKey)
		if err := jwk.Export(pub, exportedEcKey); err != nil {
			return nil, err
		}
		out, err := NewECPublicKey(exportedEcKey)
		if err != nil {
			return nil, err
		}
		return &jwkPublicKey{
			jwk:     key,
			wrapped: out,
		}, nil
	default:
		return nil, fmt.Errorf("%w: unsupported key type %s", ErrKeyInvalid, key.KeyType())
	}
}

// AddJWKToPublicKey wraps PublicKey and creates a PublicKeyJWK.
// Can be used when building an ExternalSigner, to ensure the JWT encoded RTUs will have a 'jwk' header.
func AddJWKToPublicKey(key PublicKey) (PublicKeyJWK, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: public key cannot be nil", ErrKeyInvalid)
	}
	if out, ok := key.(PublicKeyJWK); ok {
		return out, nil
	}
	temp, err := jwk.Import(key.Raw())
	if err != nil {
		return nil, err
	}
	return NewJWKPublicKey(temp)
}

func (j *jwkPublicKey) Verify(rtuType Type, payload, signature []byte) error {
	return j.wrapped.Verify(rtuType, payload, signature)
}

func (j *jwkPublicKey) CPK() CPK {
	return j.wrapped.CPK()
}

func (j *jwkPublicKey) Algorithm() SignatureAlgorithm {
	return j.wrapped.Algorithm()
}

func (j *jwkPublicKey) Raw() crypto.PublicKey {
	return j.wrapped.Raw()
}

func (j *jwkPublicKey) Equal(other PublicKey) bool {
	return j.wrapped.Equal(other)
}

func (j *jwkPublicKey) JWK() jwk.Key {
	return j.jwk
}

// PrivateKey is a helper structure, that wraps a private key with a SignatureAlgorithm.
// It also generates its own CPK and exposes a common Sign method, for easier integration
// with potential other SignatureAlgorithms down the line.
type PrivateKey interface {
	Public() PublicKey
	Raw() crypto.PrivateKey
	// Sign allows this private key to sign the given payload, by digesting it with SignatureAlgorithm
	// and based on the same algorithm apply the correct signature function, outputting signature and any
	// errors that happened while signing.
	Sign(rtuType Type, rand io.Reader, payload []byte) ([]byte, error)
}

type withJwkPrivateKey struct {
	priv             PrivateKey
	publicKeyWithJWK PublicKeyJWK
}

// AddJWKToPrivateKey builds a PrivateKey, which returns a PublicKeyJWK when Public() method is called
func AddJWKToPrivateKey(key PrivateKey) (PrivateKey, error) {
	if _, ok := key.Public().(PublicKeyJWK); ok {
		return key, nil
	}
	pub, err := AddJWKToPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	return &withJwkPrivateKey{
		priv:             key,
		publicKeyWithJWK: pub,
	}, nil
}

func (w *withJwkPrivateKey) Public() PublicKey {
	return w.publicKeyWithJWK
}

func (w *withJwkPrivateKey) Raw() crypto.PrivateKey {
	return w.priv.Raw()
}

func (w *withJwkPrivateKey) Sign(rtuType Type, rand io.Reader, payload []byte) ([]byte, error) {
	return w.priv.Sign(rtuType, rand, payload)
}

type privateKeyMetadata struct {
	publicKey PublicKey
}

func newPrivateKeyMetadata(publicKey PublicKey) privateKeyMetadata {
	return privateKeyMetadata{
		publicKey: publicKey,
	}
}

func (p privateKeyMetadata) Public() PublicKey {
	return p.publicKey
}

func (p privateKeyMetadata) Sign(rtuType Type, rand io.Reader, payload []byte) ([]byte, error) {
	// this should be called with every implementation of privateKeyMetadata. This only verifies the inputs
	if rand == nil {
		return nil, fmt.Errorf("%w: rand is nil", ErrSigning)
	}
	if err := rtuType.Format().Validate(); err != nil {
		return nil, err
	}
	if err := rtuType.Version().Validate(); err != nil {
		return nil, err
	}
	if len(payload) == 0 {
		return nil, ErrPayloadIsNil
	}
	return nil, nil
}

type ecdsaPrivateKey struct {
	privateKeyMetadata
	key *ecdsa.PrivateKey
}

// NewECPrivateKey only accepts P-256 private keys for now (because only AlgorithmEcdsaP256 is added)
func NewECPrivateKey(priv *ecdsa.PrivateKey) (PrivateKey, error) {
	pub, err := NewECPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &ecdsaPrivateKey{
		privateKeyMetadata: newPrivateKeyMetadata(pub),
		key:                priv,
	}, nil
}

func (p *ecdsaPrivateKey) Raw() crypto.PrivateKey {
	return p.key
}

func (p *ecdsaPrivateKey) Sign(rtuType Type, rand io.Reader, payload []byte) ([]byte, error) {
	if _, err := p.privateKeyMetadata.Sign(rtuType, rand, payload); err != nil {
		return nil, err
	}
	switch rtuType.Format() {
	case JWT:
		r, s, err := ecdsa.Sign(rand, p.key, p.Public().Algorithm().Digest(payload))
		if err != nil {
			return nil, fmt.Errorf("%w: ecdsa JWT signing failed, reason: %s", ErrSigning, err.Error())
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil
	default:
		sig, err := ecdsa.SignASN1(rand, p.key, p.Public().Algorithm().Digest(payload))
		if err != nil {
			return nil, fmt.Errorf("%w: ecdsa ASN1 signing failed, reason: %s", ErrSigning, err.Error())
		}
		return sig, nil
	}
}

// LoadPrivateKeyPEM parses a PEM-encoded EC private key.
// Accepts both PKCS#8 ("PRIVATE KEY") and SEC1 ("EC PRIVATE KEY") formats.
func LoadPrivateKeyPEM(pemBytes []byte) (PrivateKey, error) {
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
