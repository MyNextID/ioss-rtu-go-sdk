package rtu

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
)

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

func (r *RTU) GetSignatureAlgorithm() SignatureAlgorithm {
	if r.Algorithm == "" {
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

func (r *RTU) Raw() (RawRTU, error) {
	der, err := asn1.Marshal(*r)
	if err != nil {
		return nil, fmt.Errorf("asn1.Marshal failed to encode RTU: %w", ErrEncoding)
	}
	return der, nil
}

// Pack transforms this RTU structure to a PackedRTU
func (r *RTU) Pack() (PackedRTU, error) {
	der, err := r.Raw()
	if err != nil {
		return "", err
	}
	return der.Pack(), nil
}

// RawRTU should always be an ASN.1 DER encoded RTU object
type RawRTU []byte

func (r RawRTU) parse() (*RTU, error) {
	var out RTU
	_, err := asn1.Unmarshal(r, &out)
	if err != nil {
		return nil, fmt.Errorf("error parsing RawRTU to RTU: %w", err)
	}
	return &out, nil
}

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

func (r RawRTU) Pack() PackedRTU {
	return PackedRTU(base64.RawURLEncoding.EncodeToString(r))
}

// PackedRTU is a base64-url encoded RTU object, marshalled via ASN.1 DER encoding
type PackedRTU string

func (p PackedRTU) Raw() (RawRTU, error) {
	der, err := base64.RawURLEncoding.DecodeString(string(p))
	if err != nil {
		return nil, fmt.Errorf("failed to decode PackedRTU to RawRTU: %w", ErrDecoding)
	}
	return der, nil
}

// Unpack decodes the PackedRTU and returns a RTU object
func (p PackedRTU) Unpack() (*RTU, error) {
	raw, err := p.Raw()
	if err != nil {
		return nil, err
	}
	return raw.Parse(true)
}
