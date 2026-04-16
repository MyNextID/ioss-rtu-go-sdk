package rtu

import (
	"fmt"
)

type Version int32

const (
	Version1 Version = 1
)

func (v Version) Validate(rtu *RTU, sizeOfRaw int) error {
	switch v {
	case Version1:
		return validateV1RTU(rtu, sizeOfRaw)
	default:
		return &ValidationError{
			Field:   "Version",
			Message: fmt.Sprintf("invalid version: %d", v),
		}
	}
}

func (v Version) parseSchemaPayload(payload []byte) (SchemaPayload, error) {
	switch v {
	case Version1:
		return parseV1RTU(payload)
	default:
		return nil, ErrUnknownVersion
	}
}

// Parse only parses the raw payload with this Version.
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

func (v Version) Make(payload *Payload) ([]byte, error) {
	switch v {
	case Version1:
		return buildV1RTU(payload)
	default:
		return nil, ErrUnknownVersion
	}
}

func (v Version) DefaultSignatureAlgorithm() SignatureAlgorithm {
	switch v {
	case Version1:
		return AlgorithmEcdsaP256
	default:
		return AlgorithmNone
	}
}
