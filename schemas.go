package rtu

import (
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"regexp"
	"time"
)

/*
	This file contains all schema definitions for IOSS-RTUs that this library supports.

	To add a version of RTUs, the verification, validation and parsing should go into this
	file. Signer/Builder of the new version should go into signers.go
*/

// SchemaPayload is an interface for valid version structures to implement, allowing the parser
// to get a Payload object from the structures.
type SchemaPayload interface {
	// Payload creates a Payload object from this SchemaPayload
	Payload() (*Payload, error)
	// Validate validates the fields inside the schema payload.
	// it should almost always return a *ValidationError,
	// unless validation is not field specific
	Validate() error
}

const (
	version1CpkByteLength                 = 33
	version1MaxNumberOfConsignmentIDs     = 10
	version1MaxAddressCharacterSize       = 100
	version1MaxSellerNameCharacterSize    = 100
	version1MaxConsignmentIDCharacterSize = 35
	version1MaxEncodedRTUBytes            = 750
	version1MaxEncodedSignedDataBytes     = 830
)

var (
	version1LimitDeliveryAreaRegex = regexp.MustCompile(`^[A-Z]{2}-[A-Z0-9]{1,4}$`)
)

// ioss01Struct is the payload structure for Version1
type ioss01Struct struct {
	CPK []byte

	DelegatedUse      bool
	SellerName        string `asn1:"optional,utf8,tag:0"`
	SellerAddress     string `asn1:"optional,utf8,tag:1"`
	TransactionID     string `asn1:"utf8"`
	ValidUntil        int64
	LimitDeliveryArea string   `asn1:"optional,utf8"`
	ConsignmentIDs    []string `asn1:"optional"`
	LimitConsignments int      `asn1:"optional"`
}

func (i ioss01Struct) validateCPK() error {
	if len(i.CPK) != version1CpkByteLength {
		return &ValidationError{
			Field:   "CPK",
			Message: fmt.Sprintf("must be exactly %d bytes, got %d", version1CpkByteLength, len(i.CPK)),
		}
	}

	first := i.CPK[0]
	if first != 0x02 && first != 0x03 {
		return &ValidationError{
			Field:   "CPK",
			Message: fmt.Sprintf("first byte must be 0x02 or 0x03 (compressed point prefix), got 0x%02x", first),
		}
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), i.CPK)
	if x == nil || y == nil {
		return &ValidationError{
			Field:   "CPK",
			Message: "could not decompress compressed public key (cpk)",
		}
	}

	return nil
}

func (i ioss01Struct) validateTransactionID() error {
	l := len(i.TransactionID)
	if l < 1 || l > 50 {
		return &ValidationError{
			Field:   "TransactionID",
			Message: fmt.Sprintf("must be between 1 and 50 characters, got %d", l),
		}
	}

	return nil
}

func (i ioss01Struct) validateValidUntil() error {
	if i.ValidUntil <= time.Now().Unix() {
		return &ValidationError{
			Field:   "ValidUntil",
			Message: "must be a Unix timestamp strictly in the future",
		}
	}

	return nil
}

func (i ioss01Struct) validateLimitDeliveryArea() error {
	if i.LimitDeliveryArea == "" {
		return nil
	}

	if !version1LimitDeliveryAreaRegex.MatchString(i.LimitDeliveryArea) {
		return &ValidationError{
			Field:   "LimitDeliveryArea",
			Message: fmt.Sprintf("must match ^[A-Z]{2}-[A-Z0-9]{1,4}$, got %q", i.LimitDeliveryArea),
		}
	}

	return nil
}

func (i ioss01Struct) validateConsignments() error {
	if len(i.ConsignmentIDs) > 0 {
		if i.LimitConsignments != 0 {
			return &ValidationError{
				Field:   "LimitConsignments",
				Message: fmt.Sprintf("rtu has ConsignmentIDs, LimitConsignments should be 0, got %d", i.LimitConsignments),
			}
		}
		return i.validateConsignmentIDs()
	}
	return i.validateLimitConsignments()
}

func (i ioss01Struct) validateConsignmentIDs() error {
	if len(i.ConsignmentIDs) == 0 {
		return nil
	}

	if len(i.ConsignmentIDs) > version1MaxNumberOfConsignmentIDs {
		return &ValidationError{
			Field:   "ConsignmentIDs",
			Message: fmt.Sprintf("must contain at most 10 items, got %d", len(i.ConsignmentIDs)),
		}
	}

	seen := make(map[string]struct{}, len(i.ConsignmentIDs))
	for i, id := range i.ConsignmentIDs {
		if len(id) > version1MaxConsignmentIDCharacterSize {
			return &ValidationError{
				Field:   "ConsignmentIDs",
				Message: fmt.Sprintf("item %d exceeds 35 characters (got %d)", i, len(id)),
			}
		}

		if len(id) == 0 {
			return &ValidationError{
				Field:   "ConsignmentIDs",
				Message: fmt.Sprintf("item %d is an empty string", i),
			}
		}

		if _, exists := seen[id]; exists {
			return &ValidationError{
				Field:   "ConsignmentIDs",
				Message: fmt.Sprintf("duplicate consignment ID %q", id),
			}
		}
		seen[id] = struct{}{}
	}

	return nil
}

func (i ioss01Struct) validateLimitConsignments() error {
	// limitConsignments is optional
	if i.LimitConsignments == 0 {
		return nil
	}

	if i.LimitConsignments < 1 || i.LimitConsignments > 100 {
		return &ValidationError{
			Field:   "LimitConsignments",
			Message: fmt.Sprintf("must be between 1 and 100, got %d", i.LimitConsignments),
		}
	}

	return nil
}

func (i ioss01Struct) validateSellerName() error {
	if len(i.SellerName) > version1MaxSellerNameCharacterSize {
		return &ValidationError{
			Field:   "SellerName",
			Message: fmt.Sprintf("must not exceed 100 characters, got %d", len(i.SellerName)),
		}
	}

	return nil
}

func (i ioss01Struct) validateSellerAddress() error {
	if len(i.SellerAddress) > version1MaxAddressCharacterSize {
		return &ValidationError{
			Field:   "SellerAddress",
			Message: fmt.Sprintf("must not exceed 100 characters, got %d", len(i.SellerAddress)),
		}
	}

	return nil
}

func (i ioss01Struct) Validate() error {

	if err := i.validateCPK(); err != nil {
		return err
	}

	if err := i.validateTransactionID(); err != nil {
		return err
	}

	if err := i.validateValidUntil(); err != nil {
		return err
	}

	if err := i.validateLimitDeliveryArea(); err != nil {
		return err
	}

	if err := i.validateConsignments(); err != nil {
		return err
	}

	if err := i.validateSellerName(); err != nil {
		return err
	}

	if err := i.validateSellerAddress(); err != nil {
		return err
	}

	return nil
}

func (i ioss01Struct) Payload() (*Payload, error) {
	payload := NewPayload(i.TransactionID, time.Unix(i.ValidUntil, 0)).
		SetCPK(i.CPK).SetDelegatedUse(i.DelegatedUse)
	if i.SellerName != "" {
		payload.SetSellerName(i.SellerName)
	}
	if i.SellerAddress != "" {
		payload.SetSellerAddress(i.SellerAddress)
	}
	if len(i.ConsignmentIDs) > 0 {
		payload.SetConsignments(i.ConsignmentIDs)
	} else if i.LimitConsignments != 0 {
		payload.SetLimitConsignments(i.LimitConsignments)
	}
	if i.LimitDeliveryArea != "" {
		payload.SetLimitDeliverArea(i.LimitDeliveryArea)
	}
	return payload, nil
}

func parseV1RTU(raw []byte) (ioss01Struct, error) {
	var temp ioss01Struct
	if _, err := asn1.Unmarshal(raw, &temp); err != nil {
		return ioss01Struct{}, fmt.Errorf("failed to decode struct version %d from payload: %w", Version1, err)
	}
	return temp, nil
}

func buildV1RTU(values *Payload) (raw []byte, err error) {
	temp := ioss01Struct{
		CPK:           values.CPK(),
		ValidUntil:    values.ValidUntil().Unix(),
		TransactionID: values.TransactionID(),
	}
	if err = temp.validateCPK(); err != nil {
		return nil, err
	}
	if err = temp.validateValidUntil(); err != nil {
		return nil, err
	}
	if err = temp.validateTransactionID(); err != nil {
		return nil, err
	}
	if delegatedUse := values.DelegatedUse(); delegatedUse != nil {
		temp.DelegatedUse = *delegatedUse
	} else {
		return nil, &ValidationError{
			Field:   "DelegatedUse",
			Message: fmt.Sprintf("delegated use is not set"),
		}
	}
	if sellerName := values.SellerName(); sellerName != nil {
		temp.SellerName = *sellerName
		if err = temp.validateSellerName(); err != nil {
			return nil, err
		}
	}
	if sellerAddress := values.SellerAddress(); sellerAddress != nil {
		temp.SellerAddress = *sellerAddress
		if err = temp.validateSellerAddress(); err != nil {
			return nil, err
		}
	}
	if consignments := values.Consignments(); consignments != nil {
		temp.ConsignmentIDs = consignments
		if err = temp.validateConsignmentIDs(); err != nil {
			return nil, err
		}
	} else if limitConsignments := values.LimitConsignments(); limitConsignments != nil {
		temp.LimitConsignments = *limitConsignments
		if err = temp.validateLimitConsignments(); err != nil {
			return nil, err
		}
	}
	if deliveryArea := values.LimitDeliverArea(); deliveryArea != nil {
		temp.LimitDeliveryArea = *deliveryArea
		if err = temp.validateLimitDeliveryArea(); err != nil {
			return nil, err
		}
	}
	// structure built, marshal it and return
	raw, err = asn1.Marshal(temp)
	if err != nil {
		return nil, fmt.Errorf("failed to encode version %d struct with asn.1: %w", Version1, ErrEncoding)
	}
	return raw, nil
}

func validateV1RTU(rtu *RTU, sizeOfRaw int) error {
	if sizeOfRaw > version1MaxEncodedSignedDataBytes {
		return &ValidationError{
			Field:   "$",
			Message: fmt.Sprintf("signedRtu is too large (%d bytes)", sizeOfRaw),
		}
	}
	if len(rtu.Payload) > version1MaxEncodedRTUBytes {
		return &ValidationError{
			Field:   "Payload",
			Message: fmt.Sprintf("payload is too large (%d bytes)", len(rtu.Payload)),
		}
	}
	return nil
}
