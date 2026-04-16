package rtu

import (
	"errors"
	"fmt"
)

var (
	ErrValidation                = errors.New("validation error")
	ErrEncoding                  = errors.New("asn1 encoding error")
	ErrDecoding                  = errors.New("asn1 decoding error")
	ErrSignatureAlgorithmInvalid = errors.New("invalid signature algorithm")
	ErrNoSignatureAlgorithm      = errors.New("no signature algorithm")
	ErrCPKUnsupported            = errors.New("unsupported CPK type")
	ErrSigning                   = errors.New("signing error")
	ErrSignatureInvalid          = errors.New("signature invalid")
	ErrKeyInvalid                = errors.New("invalid key")
	ErrUnknownVersion            = errors.New("unknown version")
	ErrEmptyInput                = errors.New("empty input")
)

// ValidationError carries per-field details
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error: field %q: %s", e.Field, e.Message)
}

func (e *ValidationError) Unwrap() error {
	return ErrValidation
}
