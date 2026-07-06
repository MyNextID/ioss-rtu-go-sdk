package rtu

import (
	"fmt"
)

type RTU interface {
	Format() Format
	Version() Version

	Parse() (Payload, PublicKey, error)

	Payload() []byte
	Signature() []byte
	Size() int64

	Pack() (PackedRTU, error)
}

type makeRTUMetadata interface {
	Format() Format
	Version() Version

	PublicKey() PublicKey
}

// makeRTU is an internal make function, to create RTU interfaces. it does the bare minimum validation.
// Format and Version are "validated" because they need a function, to handle them (in case of unknowns, it returns error)
func makeRTU(metadata makeRTUMetadata, payload, signature []byte) (RTU, error) {
	switch metadata.Format() {
	case ASN1:
		return newAsn1RtuObject(metadata, payload, signature)
	case JWT:
		return newJwtRtu(metadata, payload, signature)
	default:
		return nil, fmt.Errorf("%w %s", ErrUnknownFormat, metadata.Format())
	}
}

// PackedRTU is the signed base64url encoded IOSS-RTU
type PackedRTU string

func (p PackedRTU) Parse() (RTU, error) {
	out, err := DecodeJWT(p)
	if err != nil {
		return DecodeASN1(p)
	}
	return out, nil
}
