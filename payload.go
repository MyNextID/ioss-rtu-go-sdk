package rtu

import (
	"time"
)

// Payload is the structureless data container for all versions of RTU
type Payload struct {
	// required info across all versions rtus
	validUntil    time.Time
	transactionID string

	// cpk not nil means, this payload was signed.
	// it should be set by signers, before Version.Make is called
	cpk CPK

	// optional keys
	delegatedUse      *bool
	sellerName        *string
	sellerAddr        *string
	limitDeliverArea  *string
	consignmentIDs    []string
	limitConsignments *int
}

// NewPayload creates an empty payload, with TransactionID and ValidUntil set (the bare minimum)
func NewPayload(txID string, validUntil time.Time) *Payload {
	return &Payload{
		validUntil:    validUntil.UTC().Truncate(time.Second),
		transactionID: txID,
	}
}

func (p *Payload) TransactionID() string {
	return p.transactionID
}

func (p *Payload) CPK() CPK {
	return p.cpk
}

func (p *Payload) SetCPK(cpk CPK) *Payload {
	p.cpk = cpk
	return p
}

func (p *Payload) IsExpired() bool {
	return p.validUntil.Before(time.Now())
}

func (p *Payload) ValidUntil() time.Time {
	return p.validUntil
}

func (p *Payload) DelegatedUse() *bool {
	return p.delegatedUse
}

func (p *Payload) SetDelegatedUse(delegatedUse bool) *Payload {
	p.delegatedUse = &delegatedUse
	return p
}

func (p *Payload) SellerName() *string {
	return p.sellerName
}

func (p *Payload) SetSellerName(sellerName string) *Payload {
	p.sellerName = &sellerName
	return p
}

func (p *Payload) SellerAddress() *string {
	return p.sellerAddr
}

func (p *Payload) SetSellerAddress(sellerAddr string) *Payload {
	p.sellerAddr = &sellerAddr
	return p
}

func (p *Payload) LimitDeliverArea() *string {
	return p.limitDeliverArea
}

func (p *Payload) SetLimitDeliverArea(limitDeliverArea string) *Payload {
	p.limitDeliverArea = &limitDeliverArea
	return p
}

func (p *Payload) LimitConsignments() *int {
	return p.limitConsignments
}

func (p *Payload) SetLimitConsignments(limitConsignments int) *Payload {
	p.limitConsignments = &limitConsignments
	return p
}

func (p *Payload) Consignments() []string {
	return p.consignmentIDs
}

func (p *Payload) SetConsignments(consignmentIDs []string) *Payload {
	p.consignmentIDs = consignmentIDs
	return p
}
