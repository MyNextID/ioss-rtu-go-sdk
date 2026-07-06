package rtu

import (
	"errors"
	"fmt"

	"github.com/MyNextID/ioss-rtu-go-sdk/internal/utils"
)

var (
	ErrValidation     = errors.New("validation error")
	ErrEncoding       = errors.New("encoding error")
	ErrDecoding       = errors.New("decoding error")
	ErrCPKUnsupported = errors.New("unsupported CPK type")

	// jwt format speicifc errors
	ErrPackedRTUNotJWT = errors.New("packed RTU not JWT")

	ErrFieldRequired = errors.New("field is required")

	ErrSigning                   = errors.New("signing error")
	ErrSignatureAlgorithmInvalid = errors.New("invalid signature algorithm")
	ErrNoSignatureAlgorithm      = errors.New("no signature algorithm")
	ErrSignatureInvalid          = errors.New("signature invalid")
	ErrSignatureIsNil            = errors.New("signature is empty")
	ErrPayloadIsNil              = errors.New("payload is empty")

	ErrKeyInvalid     = errors.New("invalid key")
	ErrUnknownVersion = errors.New("unknown version")
	ErrUnknownFormat  = errors.New("unknown format")
	ErrEmptyInput     = errors.New("empty input")
)

// ValidationError carries per-field details
type ValidationError struct {
	Field string
	error error
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
		Field: field,
		error: err,
	}
}

func NewValidationErrorForField(format Format, field string, err error) *ValidationError {
	return NewValidationError(format.getFieldAliasMap().Get(field), err)
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
	return fmt.Sprintf("validation error '%q': %s", e.Field, e.error.Error())
}

func (e *ValidationError) Unwrap() error {
	return e.error
}

type ValidationErrorBuilder struct {
	alias utils.Alias[string]
}

func NewValidationErrorBuilder(format Format) *ValidationErrorBuilder {
	return &ValidationErrorBuilder{
		alias: format.getFieldAliasMap(),
	}
}

func (b *ValidationErrorBuilder) Build(field string, err error) error {
	return NewValidationError(b.alias.Get(field), err)
}
