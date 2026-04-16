package rtu

import (
	"encoding/asn1"
	"errors"

	"github.com/go-playground/validator/v10"
)

type Version uint16

const (
	Version1 Version = 1
)

// Parse only parses the raw payload with this Version.
func (v Version) Parse(payload []byte, withValidation bool) (*Payload, error) {
	// get generator for the structure of this version
	parser, ok := parserRegistry[v]
	if !ok {
		return nil, errors.New("invalid version")
	}
	// get new variable of the correct type
	raw, err := parser(payload)
	if err != nil {
		return nil, err
	}
	// validate structure, if withValidation is given
	if withValidation {
		validatorInstance, ok := validatorRegistry[v]
		if !ok {
			return nil, errors.New("invalid version")
		}
		if err := validatorInstance.Struct(raw); err != nil {
			return nil, err
		}
	}
	// get *Payload from structure
	return raw.Payload()
}

func (v Version) Make(payload *Payload) ([]byte, error) {
	// get version object builder
	builder, ok := builderRegistry[v]
	if !ok {
		return nil, errors.New("invalid version")
	}
	// generate payload object for this version from *Payload
	raw, err := builder(payload)
	if err != nil {
		return nil, err
	}
	// build ASN.1¸DER byte array (payload)
	return asn1.Marshal(raw)
}

func (v Version) DefaultSignatureAlgorithm() SignatureAlgorithm {
	switch v {
	case Version1:
		return AlgorithmEcdsaP256
	default:
		return AlgorithmNone
	}
}

type SchemaParser func(asn1der []byte) (SchemaPayload, error)
type SchemaBuilder func(values *Payload) (raw SchemaPayload, err error)

// version registries
var parserRegistry = map[Version]SchemaParser{}
var validatorRegistry = map[Version]*validator.Validate{}
var builderRegistry = map[Version]SchemaBuilder{}

func RegisterVersion(id Version, parser SchemaParser, builder SchemaBuilder) {
	parserRegistry[id] = parser
	builderRegistry[id] = builder
	validatorRegistry[id] = validator.New()
}
