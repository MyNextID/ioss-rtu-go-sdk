package rtu

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"regexp"
	"time"
)

const (
	ecdsaP256CpkLength                    = 33
	version1MaxNumberOfConsignmentIDs     = 10
	version1MaxAddressCharacterSize       = 100
	version1MaxSellerNameCharacterSize    = 100
	version1MaxConsignmentIDCharacterSize = 35
	version1MaxEncodedRTUBytesASN1        = 750
	version1MaxEncodedSignedDataBytesASN1 = 830
)

var (
	version1LimitDeliveryAreaRegex = regexp.MustCompile(`^[A-Z]{2}-[A-Z0-9]{1,4}$`)
)

func validateEcdsaP256CPK(cpk CPK) (PublicKey, error) {
	if len(cpk) != ecdsaP256CpkLength {
		return nil, NewValidationError(ValidationFieldCPK, fmt.Errorf("must be exactly %d bytes, got %d", ecdsaP256CpkLength, len(cpk)))
	}

	first := cpk[0]
	if first != 0x02 && first != 0x03 {
		return nil, NewValidationError(ValidationFieldCPK, fmt.Errorf("first byte must be 0x02 or 0x03 (compressed point prefix), got 0x%02x", first))
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), cpk)
	if x == nil || y == nil {
		return nil, NewValidationError(ValidationFieldCPK, fmt.Errorf("failed to unmarshal elliptic compressed public key for P-256 curve"))
	}

	return NewECPublicKey(&ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	})
}

func ValidateCPK(algorithm SignatureAlgorithm, cpk CPK) (PublicKey, error) {
	switch algorithm {
	case AlgorithmEcdsaP256:
		return validateEcdsaP256CPK(cpk)
	default:
		return nil, NewValidationError(ValidationFieldCPK, fmt.Errorf("unsupported signature algorithm: %s", algorithm))
	}
}

func ValidateTransactionID(payload Payload) error {
	return validateTransactionID(payload, NewValidationErrorBuilder(payload.Format()))
}

func validateTransactionID(payload Payload, builder *ValidationErrorBuilder) error {
	transactionID := payload.TransactionID()
	if transactionID == nil {
		return builder.Build(ValidationFieldTransactionID, ErrFieldRequired)
	}
	l := len(*transactionID)
	if l < 1 || l > 50 {
		return builder.Build(ValidationFieldTransactionID, fmt.Errorf("must be between 1 and 50 characters, got %d", l))
	}
	return nil
}

func ValidateValidUntil(payload Payload) error {
	return validateValidUntil(payload, NewValidationErrorBuilder(payload.Format()))
}

func validateValidUntil(payload Payload, builder *ValidationErrorBuilder) error {
	validUntil := payload.ValidUntil()
	if validUntil.IsZero() {
		return builder.Build(ValidationFieldTransactionID, ErrFieldRequired)
	}
	if validUntil.Before(time.Now()) {
		return builder.Build(ValidationFieldTransactionID, fmt.Errorf("must be a Unix timestamp strictly in the future"))
	}

	return nil
}

func ValidateDelegatedUse(payload Payload) error {
	return validateDelegatedUse(payload, NewValidationErrorBuilder(payload.Format()))
}

func validateDelegatedUse(payload Payload, builder *ValidationErrorBuilder) error {
	delegatedUse := payload.DelegatedUse()

	if delegatedUse == nil {
		return builder.Build(ValidationFieldDelegatedUse, ErrFieldRequired)
	}

	return nil
}

func ValidateLimitDeliveryArea(payload Payload) error {
	return validateLimitDeliveryArea(payload, NewValidationErrorBuilder(payload.Format()))
}

func validateLimitDeliveryArea(payload Payload, builder *ValidationErrorBuilder) error {
	limitDeliveryArea := payload.LimitDeliveryArea()
	if limitDeliveryArea == nil {
		return nil
	}

	if !version1LimitDeliveryAreaRegex.MatchString(*limitDeliveryArea) {
		return builder.Build(ValidationFieldTransactionID, fmt.Errorf("must match ^[A-Z]{2}-[A-Z0-9]{1,4}$, got %q", *limitDeliveryArea))
	}

	return nil
}

func ValidateConsignmentIDs(payload Payload) error {
	return validateConsignmentIDs(payload, NewValidationErrorBuilder(payload.Format()))
}

func validateConsignmentIDs(payload Payload, builder *ValidationErrorBuilder) error {
	consignmentIDs := payload.Consignments()
	if consignmentIDs == nil {
		return nil
	}

	if len(consignmentIDs) > version1MaxNumberOfConsignmentIDs {
		return builder.Build(ValidationFieldConsignmentIDs, fmt.Errorf("must contain at most 10 items, got %d", len(consignmentIDs)))
	}

	seen := make(map[string]struct{}, len(consignmentIDs))
	for i, id := range consignmentIDs {
		if len(id) > version1MaxConsignmentIDCharacterSize {
			return builder.Build(ValidationFieldConsignmentIDs, fmt.Errorf("item %d exceeds 35 characters (got %d)", i, len(id)))
		}

		if len(id) == 0 {
			return builder.Build(ValidationFieldConsignmentIDs, fmt.Errorf("item %d is an empty string", i))
		}

		if _, exists := seen[id]; exists {
			return builder.Build(ValidationFieldConsignmentIDs, fmt.Errorf("duplicate consignment ID %q", id))
		}
		seen[id] = struct{}{}
	}

	return nil
}

func ValidateLimitConsignments(payload Payload) error {
	return validateLimitConsignments(payload, NewValidationErrorBuilder(payload.Format()))
}

func validateLimitConsignments(payload Payload, builder *ValidationErrorBuilder) error {
	limitConsignments := payload.LimitConsignments()
	// limitConsignments is optional
	if limitConsignments == nil {
		return nil
	}

	if *limitConsignments < 1 || *limitConsignments > 100 {
		return builder.Build(ValidationFieldLimitConsignments, fmt.Errorf("must be between 1 and 100, got %d", *limitConsignments))
	}

	return nil
}

func ValidateConsignments(payload Payload) error {
	return validateConsignments(payload, NewValidationErrorBuilder(payload.Format()))
}

func validateConsignments(payload Payload, builder *ValidationErrorBuilder) error {
	if len(payload.Consignments()) > 0 {
		if payload.LimitConsignments() != nil {
			return builder.Build(ValidationFieldLimitConsignments, fmt.Errorf("rtu has ConsignmentIDs, LimitConsignments should be 0, got %d", *payload.LimitConsignments()))
		}
		return validateConsignmentIDs(payload, builder)
	}
	return validateLimitConsignments(payload, builder)
}

func ValidateSellerName(payload Payload) error {
	return validateSellerName(payload, NewValidationErrorBuilder(payload.Format()))
}

func validateSellerName(payload Payload, builder *ValidationErrorBuilder) error {
	sellerName := payload.SellerName()
	if sellerName == nil {
		return nil
	}

	if len(*sellerName) > version1MaxSellerNameCharacterSize {
		return builder.Build(ValidationFieldSellerName, fmt.Errorf("must not exceed 100 characters, got %d", len(*sellerName)))
	}

	return nil
}

func ValidateSellerAddress(payload Payload) error {
	return validateSellerAddress(payload, NewValidationErrorBuilder(payload.Format()))
}

func validateSellerAddress(payload Payload, builder *ValidationErrorBuilder) error {
	sellerAddress := payload.SellerAddress()
	if sellerAddress == nil {
		return nil
	}

	if len(*sellerAddress) > version1MaxAddressCharacterSize {
		return builder.Build(ValidationFieldSellerName, fmt.Errorf("must not exceed 100 characters, got %d", len(*sellerAddress)))
	}

	return nil
}

func ValidatePayload(payload Payload) error {
	builder := NewValidationErrorBuilder(payload.Format())
	if err := validateValidUntil(payload, builder); err != nil {
		return err
	}

	if err := validateTransactionID(payload, builder); err != nil {
		return err
	}

	if err := validateDelegatedUse(payload, builder); err != nil {
		return err
	}

	if err := validateSellerName(payload, builder); err != nil {
		return err
	}

	if err := validateSellerAddress(payload, builder); err != nil {
		return err
	}

	if err := validateLimitDeliveryArea(payload, builder); err != nil {
		return err
	}

	if err := validateConsignments(payload, builder); err != nil {
		return err
	}

	return nil
}

func ValidateRTU(rtu RTU) error {
	if err := rtu.Format().Validate(); err != nil {
		return err
	}
	errBuilder := NewValidationErrorBuilder(rtu.Format())
	switch rtu.Version() {
	case VersionNone:
		return errBuilder.Build(ValidationFieldVersion, ErrFieldRequired)
	case Version1:
		switch rtu.Format() {
		case ASN1:
			if rtu.Size() > version1MaxEncodedSignedDataBytesASN1 {
				return errBuilder.Build(ValidationFieldRTU, fmt.Errorf("asn.1 rtu is too large (%d bytes)", rtu.Size()))
			}
			if len(rtu.Payload()) > version1MaxEncodedRTUBytesASN1 {
				return errBuilder.Build(ValidationFieldRTU, fmt.Errorf("payload is too large (%d bytes)", len(rtu.Payload())))
			}
		case JWT:
			return nil
		}
	default:
		return errBuilder.Build(ValidationFieldVersion, fmt.Errorf("%w %d", ErrUnknownVersion, rtu.Version()))
	}
	return nil
}
