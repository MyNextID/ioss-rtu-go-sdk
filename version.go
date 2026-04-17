package rtu

import (
	"fmt"
)

// Version is an integer (should be uint32, but int32 is used for asn1), that defines
// the schema for a given RTU. It is used by the RTU to parse its payload to return
// the common Payload structure.
type Version int32

const (
	Version1 Version = 1
)

// Validate gets the RTU object and len(RawRTU), when RawRTU is parsing. It can checks
// the given data, WITHOUT validating Payload or anything like that. This validation is
// used purely, to check the final signed RTU's size, version, payload size etc.
func (v Version) Validate(rtu *RTU, sizeOfRaw int) error {
	switch v {
	case Version1:
		return validateV1RTU(rtu, sizeOfRaw)
	default:
		return &ValidationError{
			Field:   ValidationFieldVersion,
			Message: fmt.Sprintf("invalid version: %d", v),
		}
	}
}

// parseSchemaPayload parses the raw payload from RTU.Payload and returns a SchemaPayload,
// based on the version
func (v Version) parseSchemaPayload(payload []byte) (SchemaPayload, error) {
	switch v {
	case Version1:
		return parseV1RTU(payload)
	default:
		return nil, ErrUnknownVersion
	}
}

// Parse only parses the raw payload with this Version. withValidation calls the SchemaPayload.Validate
// method, to allow each version structure to define its own validation
func (v Version) Parse(payload []byte, withValidation bool) (*Payload, error) {
	// get new variable of the correct type
	raw, err := v.parseSchemaPayload(payload)
	if err != nil {
		return nil, err
	}
	// validate structure, if withValidation is given
	if withValidation {
		if err = raw.Validate(); err != nil {
			return nil, err
		}
	}
	// get *Payload from structure
	return raw.Payload()
}

// Make transforms the common Payload structure into the versions specific structure.
// It then encodes it to its encoding type (like asn.1) and outputs the raw byte array.
func (v Version) Make(payload *Payload) ([]byte, error) {
	switch v {
	case Version1:
		return buildV1RTU(payload)
	default:
		return nil, ErrUnknownVersion
	}
}

// DefaultSignatureAlgorithm returns the default signature algorithm for this version
// if AlgorithmNone is returned, it means either the version does not exist and/or
// there is no default for that version. Please use other methods, to validate if
// version exists
func (v Version) DefaultSignatureAlgorithm() SignatureAlgorithm {
	switch v {
	case Version1:
		return AlgorithmEcdsaP256
	default:
		return AlgorithmNone
	}
}
