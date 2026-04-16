package rtu

import (
	"encoding/asn1"
	"encoding/base64"
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

// Pack transforms this RTU structure to a PackedRTU
func (r *RTU) Pack() (PackedRTU, error) {
	der, err := asn1.Marshal(*r)
	if err != nil {
		return "", ErrASN1Encoding
	}
	return PackedRTU(base64.RawURLEncoding.EncodeToString(der)), nil
}

// PackedRTU is a base64-url encoded RTU object, marshalled via ASN.1 DER encoding
type PackedRTU string

// Unpack decodes the PackedRTU and returns a RTU object
func (p PackedRTU) Unpack() (*RTU, error) {
	der, err := base64.RawURLEncoding.DecodeString(string(p))
	if err != nil {
		return nil, ErrBase64Decoding
	}
	var out RTU
	_, err = asn1.Unmarshal(der, &out)
	if err != nil {
		return nil, ErrASN1Decoding
	}
	return &out, nil
}
