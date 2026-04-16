package rtu

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
)

// RTU is the final signed structure of every Import One-Stop Shop Right To Use (IOSS-RTU) token.
// Payload is parsed based on Version in this object. Signature and Payload.CPK are defined by Algorithm.
// If there is no Algorithm, the default SignatureAlgorithm of the given Version is used.
type RTU struct {
	// ContentType is the type of this signed rtu (schema id). It determines what type of payload we should expect
	Version Version `json:"version" asn1:""`
	// Payload is the raw byte array of the RTU payload
	Payload []byte `json:"payload" asn1:""`
	// Signature is the raw byte array of the signature
	Signature []byte `json:"signature" asn1:""`
	// Algorithm is the signature algorithm for the Signature of the given Payload in this Signed structure
	Algorithm SignatureAlgorithm `json:"algorithm" asn1:",utf8,optional"`
}

// GetSignatureAlgorithm returns the valid SignatureAlgorithm for this RTU. If Algorithm == AlgorithmNone,
// then the Version's default algorithm should have been used
func (r *RTU) GetSignatureAlgorithm() SignatureAlgorithm {
	if r.Algorithm == AlgorithmNone {
		return r.Version.DefaultSignatureAlgorithm()
	}
	return r.Algorithm
}

// Parse gets the Payload from this RTU signed structure.
// if withValidations is set, it will validate the payload and verify the signature in this RTU
// to skip signature verification (if RTU is recieved from a trusted source etc.), you can just use:
// RTU.Version().Parse
func (r *RTU) Parse(withValidations bool) (*Payload, error) {
	out, err := r.Version.Parse(r.Payload, withValidations)
	if err != nil {
		return nil, err
	}
	if withValidations {
		// check signature with payload
		algorithm := r.GetSignatureAlgorithm()
		var pubKey any
		pubKey, err = out.CPK().Parse(algorithm)
		if err != nil {
			return nil, err
		}
		var ok bool
		ok, err = algorithm.Verify(pubKey, r.Payload, r.Signature)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrSignatureInvalid
		}
	}
	return out, nil
}

// Raw encodes RTU into an ASN.1 DER encoded byte array (RawRTU)
func (r *RTU) Raw() (RawRTU, error) {
	der, err := asn1.Marshal(*r)
	if err != nil {
		return nil, fmt.Errorf("asn1.Marshal failed to encode RTU: %w", ErrEncoding)
	}
	return der, nil
}

// Pack transforms this RTU structure to a PackedRTU => base64url(RawRTU)
func (r *RTU) Pack() (PackedRTU, error) {
	der, err := r.Raw()
	if err != nil {
		return "", err
	}
	return der.Pack(), nil
}

// RawRTU should always be an ASN.1 DER encoded RTU object
type RawRTU []byte

// parse only parses and returns the RTU object
func (r RawRTU) parse() (*RTU, error) {
	var out RTU
	_, err := asn1.Unmarshal(r, &out)
	if err != nil {
		return nil, fmt.Errorf("error parsing RawRTU to RTU: %w", err)
	}
	return &out, nil
}

// Parse parses this RawRTU into an RTU object. If withValidation is true,
// the parsing will also check, based on the Version inside RTU, if the size
// of this document and/or payload size are within specs.
func (r RawRTU) Parse(withValidation bool) (*RTU, error) {
	out, err := r.parse()
	if err != nil {
		return nil, err
	}
	if withValidation {
		err = out.Version.Validate(out, len(r))
	}
	return out, err
}

// Pack just base64url encodes this RawRTU and returns it as PackedRTU
func (r RawRTU) Pack() PackedRTU {
	return PackedRTU(base64.RawURLEncoding.EncodeToString(r))
}

// PackedRTU is a base64-url encoded RawRTU
type PackedRTU string

// Raw decodes this PackedRTU and returns the encoded RawRTU
func (p PackedRTU) Raw() (RawRTU, error) {
	der, err := base64.RawURLEncoding.DecodeString(string(p))
	if err != nil {
		return nil, fmt.Errorf("failed to decode PackedRTU to RawRTU: %w", ErrDecoding)
	}
	return der, nil
}

// Unpack decodes the PackedRTU and returns a RTU object.
// RawRTU.Parse validates by default using this method. If this is not needed, to increase
// performance, you can always call Raw, then on the RawRTU call Parse(false).
func (p PackedRTU) Unpack() (*RTU, error) {
	raw, err := p.Raw()
	if err != nil {
		return nil, err
	}
	return raw.Parse(true)
}
