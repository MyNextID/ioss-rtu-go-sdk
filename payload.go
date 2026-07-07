package rtu

import (
	"fmt"
	"time"
)

// Type is an interface, that allows PrivateKey.Sign and PublicKey.Verify to know the metadata for their signature.
type Type interface {
	Format() Format
	Version() Version
}

// Payload is an interface allowing reading of the RTU payload
type Payload interface {
	Type

	ValidUntil() time.Time
	TransactionID() *string
	DelegatedUse() *bool
	SellerName() *string
	SellerAddress() *string
	LimitDeliveryArea() *string
	Consignments() []string
	LimitConsignments() *int
}

type UnsignedPayload interface {
	Payload
	// Marshal creates a byte array of this payload (to be signed)
	Marshal() ([]byte, error)

	PublicKey() PublicKey
	SetPublicKey(pk PublicKey) (UnsignedPayload, error)
	SetValidUntil(t time.Time) UnsignedPayload
	SetTransactionID(transactionID string) UnsignedPayload
	SetDelegatedUse(d bool) UnsignedPayload
	SetSellerName(s string) UnsignedPayload
	SetSellerAddress(s string) UnsignedPayload
	SetLimitDeliveryArea(s string) UnsignedPayload
	SetConsignmentIDs(ids []string) UnsignedPayload
	SetLimitConsignments(l int) UnsignedPayload
}

func New(format Format, version Version) (UnsignedPayload, error) {
	switch format {
	case JWT:
		return newJWT(version), nil
	case ASN1:
		return newASN1(version), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownFormat, format)
	}
}
