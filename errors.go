package rtu

import (
	"errors"
	"fmt"
)

var (
	ErrValidation     = errors.New("validation error")
	ErrEncoding       = errors.New("encoding error")
	ErrDecoding       = errors.New("decoding error")
	ErrCPKUnsupported = errors.New("unsupported CPK type")

	// jwt format speicifc errors
	ErrPackedRTUNotJWT = errors.New("packed RTU not JWT")

	ErrFieldRequired = errors.New("field is required")

	ErrSigning          = errors.New("signing error")
	ErrSignatureInvalid = errors.New("signature invalid")
	ErrSignatureIsNil   = errors.New("signature is empty")
	ErrPayloadIsNil     = errors.New("payload is empty")

	ErrKeyInvalid                = errors.New("invalid key")
	ErrUnknownSignatureAlgorithm = errors.New("unknown signature algorithm")
	ErrNoSignatureAlgorithm      = errors.New("no signature algorithm")
	ErrUnknownVersion            = errors.New("unknown version")
	ErrNoVersion                 = errors.New("no version")
	ErrUnknownFormat             = errors.New("unknown format")
	ErrNoFormat                  = errors.New("no format")
	ErrEmptyInput                = errors.New("empty input")

	ErrInvalidIDLength   = errors.New("invalid ID length")
	ErrUnknownRefVersion = errors.New("unknown ref version")
)

// ValidationError carries per-field details
type ValidationError struct {
	Field   string
	Message error
}

func NewValidationError(field string, err error) *ValidationError {
	if err == nil {
		return nil
	}
	if out, ok := errors.AsType[*ValidationError](err); ok {
		if field != "" {
			out.Field = field
		}
		return out
	}
	return &ValidationError{
		Field:   field,
		Message: err,
	}
}

// ValidationFields valid values
const (
	// Validations for RTU object
	ValidationFieldPayload   = "Payload"
	ValidationFieldSignature = "Signature"
	ValidationFieldAlgorithm = "Algorithm"
	ValidationFieldVersion   = "Version"
	ValidationFieldFormat    = "Format"
	ValidationFieldRTU       = "RTU"

	// Validations for rtu.Payload
	ValidationFieldTransactionID     = "TransactionID"
	ValidationFieldValidUntil        = "ValidUntil"
	ValidationFieldCPK               = "CPK"
	ValidationFieldDelegatedUse      = "DelegatedUse"
	ValidationFieldSellerName        = "SellerName"
	ValidationFieldSellerAddress     = "SellerAddress"
	ValidationFieldLimitDeliveryArea = "LimitDeliveryArea"
	ValidationFieldConsignmentIDs    = "ConsignmentIDs"
	ValidationFieldLimitConsignments = "LimitConsignments"
)

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error '%q': %s", e.Field, e.Message.Error())
}

func (e *ValidationError) Unwrap() error {
	return e.Message
}
