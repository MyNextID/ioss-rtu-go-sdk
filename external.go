package rtu

import (
	"fmt"
)

type ExternalSigner struct {
	version   Version
	format    Format
	publicKey PublicKey
}

func NewExternalSigner(format Format, version Version, publicKey PublicKey) (*ExternalSigner, error) {
	out := &ExternalSigner{
		version:   version,
		format:    format,
		publicKey: publicKey,
	}
	// these checks ensure version, format and publicKey are valid
	if err := out.version.Validate(); err != nil {
		return nil, err
	}
	if err := out.format.Validate(); err != nil {
		return nil, err
	}
	if out.publicKey == nil {
		return nil, fmt.Errorf("%w: key is nil", ErrKeyInvalid)
	}
	// this check validates the SignatureAlgorithm, ensuring .Digest() will never return nil
	if err := out.publicKey.Algorithm().Validate(); err != nil {
		return nil, err
	}
	return out, nil
}

func (e *ExternalSigner) Version() Version {
	return e.version
}

func (e *ExternalSigner) Format() Format {
	return e.format
}

func (e *ExternalSigner) PublicKey() PublicKey {
	return e.publicKey
}

func (e *ExternalSigner) validatePayload(data Payload) error {
	// check correct parsed version
	if data.Version() != e.Version() {
		return fmt.Errorf("%w: version %d is not %d", ErrUnknownVersion, data.Version(), e.Version())
	}

	// check correct parsed format
	if data.Format() != e.Format() {
		return fmt.Errorf("%w: format %s is not %s", ErrUnknownFormat, data.Format(), e.Format())
	}

	return nil
}

func (e *ExternalSigner) ComputeDigest(data UnsignedPayload) (digest []byte, payload []byte, err error) {
	// ensure the given payload is the correct format and version of rtu.Payload
	if err = e.validatePayload(data); err != nil {
		return nil, nil, err
	}
	// set the public key
	temp, err := data.SetPublicKey(e.publicKey)
	if err != nil {
		return nil, nil, err
	}
	// marshal and generate the payload to be signed
	payload, err = temp.Marshal()
	if err != nil {
		return nil, nil, err
	}
	// return the digest of the public key algorithm and the signed payload
	return e.PublicKey().Algorithm().Digest(payload), payload, nil
}

func (e *ExternalSigner) ConstructSigned(payload []byte, signature []byte) (PackedRTU, error) {
	raw, err := e.ConstructSignedObj(payload, signature)
	if err != nil {
		return "", err
	}
	return raw.Pack()
}

func (e *ExternalSigner) ConstructSignedObj(payload []byte, signature []byte) (RTU, error) {
	// check input fields are not empty or nil
	if len(payload) == 0 {
		return nil, fmt.Errorf("%w: payload", ErrEmptyInput)
	}
	if len(signature) == 0 {
		return nil, fmt.Errorf("%w: signature", ErrEmptyInput)
	}

	// verify received signature with our public key
	err := e.publicKey.Verify(e.Format(), payload, signature)
	if err != nil {
		return nil, err
	}
	// make the RTU
	parsedRTU, err := makeRTU(e, payload, signature)
	if err != nil {
		return nil, err
	}

	// validate the constructed RTU is a valid RTU (within constraints)
	if err = ValidateRTU(parsedRTU); err != nil {
		return nil, err
	}

	// parse the payload from RTU
	parsedPayload, parsedPublicKey, err := parsedRTU.Parse()
	if err != nil {
		return nil, err
	}

	// check the format and versions are correct
	if err = e.validatePayload(parsedPayload); err != nil {
		return nil, err
	}

	// check the public key in parsed payload equal to our public key (one is verifying the signature (so we know the
	// private key that signed this is correct... another is what the public key inside is set to (CPK, Jwk etc.))
	if !e.publicKey.Equal(parsedPublicKey) {
		return nil, fmt.Errorf("%w: externally signed public key is not the same as ours", ErrKeyInvalid)
	}
	// Validate the parsed payload, ensuring the received payload is also valid
	if err = ValidatePayload(parsedPayload); err != nil {
		return nil, err
	}

	return parsedRTU, nil
}
