package rtu

import (
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

type SchemaPayload interface {
	Payload() (*Payload, error)
}

type ioss01LimitDeliveryArea string

// limitDeliveryAreaRegexp is the regexp for PayloadLimitDeliveryArea
var limitDeliveryAreaRegexp = regexp.MustCompile("^[A-Z]{2}-[A-Za-z0-9]{1,4}$")

// Validate is called when validating Payload.
func (i ioss01LimitDeliveryArea) Validate() error {
	if !limitDeliveryAreaRegexp.MatchString(string(i)) {
		return fmt.Errorf("invalid payload limit delivery area %s", string(i))
	}
	return nil
}

type ioss01Struct struct {
	// Compressed secp256r1 public key (33 bytes)
	CPK CPK `asn1:"" validate:"required,len=33"`

	// Indicates whether this RTU can be delegated to another party
	DelegatedUse bool `asn1:""`

	// Legal/official name of the seller or business entity
	SellerName string `asn1:"optional,utf8,tag:0" validate:"omitempty,max=100"`

	// Complete business address of the seller
	SellerAddress string `asn1:"optional,utf8,tag:1" validate:"omitempty,max=100"`

	// Unique transaction identifier assigned by merchant/seller
	TransactionID string `asn1:"utf8" validate:"required,min=1,max=50"`

	// Unix timestamp (seconds) when this RTU expires
	ValidUntil int64 `asn1:"" validate:"required,gt=0"`

	// Optional geographic restriction for delivery (ISO 3166-1 alpha-2 + region)
	LimitDeliveryArea ioss01LimitDeliveryArea `asn1:"utf8,optional" validate:"omitempty,validateFn"`

	// Optional list of consignment/shipment identifiers (max 10)
	ConsignmentIDs []string `asn1:"set,optional" validate:"omitempty,max=10,unique,dive,max=35"`

	// Optional limit on total number of consignments (1-100)
	LimitConsignments int `asn1:"optional,default:0" validate:"omitempty,min=1,max=100"`
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
		payload.SetLimitDeliverArea(string(i.LimitDeliveryArea))
	}
	return payload, nil
}

func init() {
	RegisterVersion(Version1, func(asn1der []byte) (SchemaPayload, error) {
		var temp ioss01Struct
		_, err := asn1.Unmarshal(asn1der, &temp)
		return &temp, err
	}, func(values *Payload) (raw SchemaPayload, err error) {
		temp := ioss01Struct{
			CPK:           values.CPK(),
			ValidUntil:    values.ValidUntil().Unix(),
			TransactionID: values.TransactionID(),
		}
		if delegatedUse := values.DelegatedUse(); delegatedUse != nil {
			temp.DelegatedUse = *delegatedUse
		} else {
			return nil, fmt.Errorf("missing delegated use")
		}
		if sellerName := values.SellerName(); sellerName != nil {
			temp.SellerName = *sellerName
		}
		if sellerAddress := values.SellerAddress(); sellerAddress != nil {
			temp.SellerAddress = *sellerAddress
		}
		if consignments := values.Consignments(); consignments != nil {
			temp.ConsignmentIDs = consignments
		} else if limitConsignments := values.LimitConsignments(); limitConsignments != nil {
			temp.LimitConsignments = *limitConsignments
		}
		if deliveryArea := values.LimitDeliverArea(); deliveryArea != nil {
			temp.LimitDeliveryArea = ioss01LimitDeliveryArea(*deliveryArea)
		}
		return temp, nil
	})
}
