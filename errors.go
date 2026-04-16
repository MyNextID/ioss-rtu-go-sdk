package rtu

import (
	"errors"
	"fmt"
)

var (
	ErrValidation                = errors.New("validation error")
	ErrASN1Encoding              = errors.New("asn1 encoding error")
	ErrASN1Decoding              = errors.New("asn1 decoding error")
	ErrBase64Decoding            = errors.New("base64 decoding error")
	ErrSignatureAlgorithmInvalid = errors.New("invalid signature algorithm")
	ErrSigning                   = errors.New("signing error")
	ErrSignatureInvalid          = errors.New("signature invalid")
	ErrKeyInvalid                = errors.New("invalid key")
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
