package rtu

import (
	"fmt"
)

type Format string

const (
	FormatNone Format = ""
	ASN1       Format = "asn1"
	JWT        Format = "jwt"
)

func (f Format) Validate() error {
	switch f {
	case ASN1, JWT:
		return nil
	case FormatNone:
		return ErrNoFormat
	default:
		return fmt.Errorf("%w %s", ErrUnknownFormat, f)
	}
}
