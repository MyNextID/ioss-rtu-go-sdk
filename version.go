package rtu

import (
	"encoding/asn1"
)

type Version int32

const (
	Version1 Version = 1
)

// Parse only parses the raw payload with this Version.
func (v Version) Parse(payload []byte, withValidation bool) (*Payload, error) {
	// get generator for the structure of this version
	parser, ok := parserRegistry[v]
	if !ok {
		return nil, ErrUnknownVersion
	}
	// get new variable of the correct type
	raw, err := parser(payload)
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
	// get version object builder
	builder, ok := builderRegistry[v]
	if !ok {
		return nil, ErrUnknownVersion
	}
	// generate payload object for this version from *Payload
	raw, err := builder(payload)
	if err != nil {
		return nil, err
	}
	// build ASN.1¸DER byte array (payload)
	out, err := asn1.Marshal(raw)
	if err != nil {
		return nil, ErrASN1Encoding
	}
	return out, nil
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
var builderRegistry = map[Version]SchemaBuilder{}

func RegisterVersion(id Version, parser SchemaParser, builder SchemaBuilder) {
	parserRegistry[id] = parser
	builderRegistry[id] = builder
}
