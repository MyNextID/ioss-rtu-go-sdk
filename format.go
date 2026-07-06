package rtu

import (
	"fmt"

	"github.com/MyNextID/ioss-rtu-go-sdk/internal/utils"
)

type Format string

const (
	FormatNone Format = ""
	ASN1       Format = "asn1"
	JWT        Format = "jwt"
)

func (f Format) getFieldAliasMap() utils.Alias[string] {
	switch f {
	case ASN1:
		return asn1FieldMap
	case JWT:
		return jwtFieldMap
	default:
		return nil
	}
}

func (f Format) Validate() error {
	switch f {
	case ASN1, JWT:
		return nil
	case FormatNone:
		return NewValidationError(ValidationFieldFormat, ErrFieldRequired)
	default:
		return NewValidationError(ValidationFieldFormat, fmt.Errorf("%w %s", ErrUnknownFormat, f))
	}
}
