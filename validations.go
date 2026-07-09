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

/*
	Validations for CPK types (and parsing)
*/

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

/*
	Validations of Payload fields. Since Payload has Version and Format information, it can be implemented differently based on Version and/or Format inside the function
*/

func ValidateTransactionID(payload Payload) error {
	transactionID := payload.TransactionID()
	if transactionID == nil {
		return NewValidationError(ValidationFieldTransactionID, ErrFieldRequired)
	}
	l := len(*transactionID)
	if l < 1 || l > 50 {
		return NewValidationError(ValidationFieldTransactionID, fmt.Errorf("must be between 1 and 50 characters, got %d", l))
	}
	return nil
}

func ValidateValidUntil(payload Payload) error {
	validUntil := payload.ValidUntil()
	if validUntil.IsZero() {
		return NewValidationError(ValidationFieldValidUntil, ErrFieldRequired)
	}
	if validUntil.Before(time.Now()) {
		return NewValidationError(ValidationFieldValidUntil, fmt.Errorf("must be a Unix timestamp strictly in the future"))
	}

	return nil
}

func ValidateDelegatedUse(payload Payload) error {
	delegatedUse := payload.DelegatedUse()

	if delegatedUse == nil {
		return NewValidationError(ValidationFieldDelegatedUse, ErrFieldRequired)
	}

	return nil
}

func ValidateLimitDeliveryArea(payload Payload) error {
	limitDeliveryArea := payload.LimitDeliveryArea()
	if limitDeliveryArea == nil {
		return nil
	}

	if !version1LimitDeliveryAreaRegex.MatchString(*limitDeliveryArea) {
		return NewValidationError(ValidationFieldLimitDeliveryArea, fmt.Errorf("must match ^[A-Z]{2}-[A-Z0-9]{1,4}$, got %q", *limitDeliveryArea))
	}

	return nil
}

func ValidateConsignmentIDs(payload Payload) error {
	consignmentIDs := payload.Consignments()
	if consignmentIDs == nil {
		return nil
	}

	if len(consignmentIDs) > version1MaxNumberOfConsignmentIDs {
		return NewValidationError(ValidationFieldConsignmentIDs, fmt.Errorf("must contain at most 10 items, got %d", len(consignmentIDs)))
	}

	seen := make(map[string]struct{}, len(consignmentIDs))
	for i, id := range consignmentIDs {
		if len(id) > version1MaxConsignmentIDCharacterSize {
			return NewValidationError(ValidationFieldConsignmentIDs, fmt.Errorf("item %d exceeds 35 characters (got %d)", i, len(id)))
		}

		if len(id) == 0 {
			return NewValidationError(ValidationFieldConsignmentIDs, fmt.Errorf("item %d is an empty string", i))
		}

		if _, exists := seen[id]; exists {
			return NewValidationError(ValidationFieldConsignmentIDs, fmt.Errorf("duplicate consignment ID %q", id))
		}
		seen[id] = struct{}{}
	}

	return nil
}

func ValidateLimitConsignments(payload Payload) error {
	limitConsignments := payload.LimitConsignments()
	// limitConsignments is optional
	if limitConsignments == nil {
		return nil
	}

	if *limitConsignments < 1 || *limitConsignments > 100 {
		return NewValidationError(ValidationFieldLimitConsignments, fmt.Errorf("must be between 1 and 100, got %d", *limitConsignments))
	}

	return nil
}

func ValidateConsignments(payload Payload) error {
	if len(payload.Consignments()) > 0 {
		if payload.LimitConsignments() != nil {
			return NewValidationError(ValidationFieldLimitConsignments, fmt.Errorf("rtu has ConsignmentIDs, LimitConsignments should be 0, got %d", *payload.LimitConsignments()))
		}
		return ValidateConsignmentIDs(payload)
	}
	return ValidateLimitConsignments(payload)
}

func ValidateSellerName(payload Payload) error {
	sellerName := payload.SellerName()
	if sellerName == nil {
		return nil
	}

	if len(*sellerName) > version1MaxSellerNameCharacterSize {
		return NewValidationError(ValidationFieldSellerName, fmt.Errorf("must not exceed 100 characters, got %d", len(*sellerName)))
	}

	return nil
}

func ValidateSellerAddress(payload Payload) error {
	sellerAddress := payload.SellerAddress()
	if sellerAddress == nil {
		return nil
	}

	if len(*sellerAddress) > version1MaxAddressCharacterSize {
		return NewValidationError(ValidationFieldSellerAddress, fmt.Errorf("must not exceed 100 characters, got %d", len(*sellerAddress)))
	}

	return nil
}

// ValidatePayload calls every field validation on Payload, and returns the first sign of an error.
func ValidatePayload(payload Payload) error {

	if err := ValidateValidUntil(payload); err != nil {
		return err
	}

	if err := ValidateTransactionID(payload); err != nil {
		return err
	}

	if err := ValidateDelegatedUse(payload); err != nil {
		return err
	}

	if err := ValidateSellerName(payload); err != nil {
		return err
	}

	if err := ValidateSellerAddress(payload); err != nil {
		return err
	}

	if err := ValidateLimitDeliveryArea(payload); err != nil {
		return err
	}

	if err := ValidateConsignments(payload); err != nil {
		return err
	}

	return nil
}

// ValidateRTU validates the RTUs metadata (in case of ASN, validates the final RTU byte size is within perameters)
func ValidateRTU(rtu RTU) error {
	if err := rtu.Format().Validate(); err != nil {
		return err
	}
	switch rtu.Version() {
	case VersionNone:
		return NewValidationError(ValidationFieldVersion, ErrFieldRequired)
	case Version1:
		switch rtu.Format() {
		case ASN1:
			if rtu.Size() > version1MaxEncodedSignedDataBytesASN1 {
				return NewValidationError(ValidationFieldRTU, fmt.Errorf("asn.1 rtu is too large (%d bytes)", rtu.Size()))
			}
			if len(rtu.Payload()) > version1MaxEncodedRTUBytesASN1 {
				return NewValidationError(ValidationFieldRTU, fmt.Errorf("payload is too large (%d bytes)", len(rtu.Payload())))
			}
		case JWT:
			return nil
		}
	default:
		return NewValidationError(ValidationFieldVersion, fmt.Errorf("%w %d", ErrUnknownVersion, rtu.Version()))
	}
	return nil
}
