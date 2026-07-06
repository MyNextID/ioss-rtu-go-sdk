package rtu

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/MyNextID/ioss-rtu-go-sdk/internal/utils"
)

func asn1OmittableString(val string) *string {
	if val == "" {
		return nil
	}
	return &val
}

func asn1OmittableInt(val int) *int {
	if val == 0 {
		return nil
	}
	return &val
}

type asn1PayloadObj struct {
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

type asn1UnsignedPayload struct {
	obj asn1PayloadObj
	ver Version
	pub PublicKey
}

func NewASN1(version Version) UnsignedPayload {
	return &asn1UnsignedPayload{
		ver: version,
		obj: asn1PayloadObj{},
	}
}

func (a *asn1UnsignedPayload) Format() Format {
	return ASN1
}

func (a *asn1UnsignedPayload) Version() Version {
	return a.ver
}

func (a *asn1UnsignedPayload) ValidUntil() time.Time {
	return time.Unix(a.obj.ValidUntil, 0)
}

func (a *asn1UnsignedPayload) TransactionID() *string {
	return &a.obj.TransactionID
}

func (a *asn1UnsignedPayload) DelegatedUse() *bool {
	return &a.obj.DelegatedUse
}

func (a *asn1UnsignedPayload) SellerName() *string {
	return asn1OmittableString(a.obj.SellerName)
}

func (a *asn1UnsignedPayload) SellerAddress() *string {
	return asn1OmittableString(a.obj.SellerAddress)
}

func (a *asn1UnsignedPayload) LimitDeliveryArea() *string {
	return asn1OmittableString(a.obj.LimitDeliveryArea)
}

func (a *asn1UnsignedPayload) Consignments() []string {
	return a.obj.ConsignmentIDs
}

func (a *asn1UnsignedPayload) LimitConsignments() *int {
	return asn1OmittableInt(a.obj.LimitConsignments)
}

func (a *asn1UnsignedPayload) Marshal() ([]byte, error) {
	return asn1.Marshal(a.obj)
}

func (a *asn1UnsignedPayload) PublicKey() PublicKey {
	return a.pub
}

func (a *asn1UnsignedPayload) SetPublicKey(pk PublicKey) (UnsignedPayload, error) {
	a.pub = pk
	a.obj.CPK = pk.CPK()
	return a, nil
}

func (a *asn1UnsignedPayload) SetValidUntil(t time.Time) UnsignedPayload {
	a.obj.ValidUntil = t.Unix()
	return a
}

func (a *asn1UnsignedPayload) SetTransactionID(transactionID string) UnsignedPayload {
	a.obj.TransactionID = transactionID
	return a
}

func (a *asn1UnsignedPayload) SetDelegatedUse(d bool) UnsignedPayload {
	a.obj.DelegatedUse = d
	return a
}

func (a *asn1UnsignedPayload) SetSellerName(s string) UnsignedPayload {
	a.obj.SellerName = s
	return a
}

func (a *asn1UnsignedPayload) SetSellerAddress(s string) UnsignedPayload {
	a.obj.SellerAddress = s
	return a
}

func (a *asn1UnsignedPayload) SetLimitDeliveryArea(s string) UnsignedPayload {
	a.obj.LimitDeliveryArea = s
	return a
}

func (a *asn1UnsignedPayload) SetConsignmentIDs(ids []string) UnsignedPayload {
	a.obj.ConsignmentIDs = ids
	return a
}

func (a *asn1UnsignedPayload) SetLimitConsignments(l int) UnsignedPayload {
	a.obj.LimitConsignments = l
	return a
}

type asn1RtuObject struct {
	// Version is the type of this signed rtu (schema id). It determines what type of payload we should expect
	Version Version `json:"version" asn1:""`
	// Payload is the raw byte array of the RTU payload
	Payload []byte `json:"payload" asn1:""`
	// Signature is the raw byte array of the signature
	Signature []byte `json:"signature" asn1:""`
	// Algorithm is the signature algorithm for the Signature of the given Payload in this Signed structure
	Algorithm SignatureAlgorithm `json:"algorithm" asn1:",utf8,optional"`
}

type asn1Rtu struct {
	size int64
	obj  asn1RtuObject
}

func newAsn1RtuObject(metadata makeRTUMetadata, payload, signature []byte) (RTU, error) {
	switch metadata.Version() {
	case Version1:
		return newAsn1RtuObjectVersion1(metadata, payload, signature)
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownVersion, metadata.Version())
	}
}

func newAsn1RtuObjectVersion1(metadata makeRTUMetadata, payload, signature []byte) (RTU, error) {
	pubKey := metadata.PublicKey()
	if pubKey == nil {
		return nil, fmt.Errorf("%w: no public key given for creating ASN.1 RTU", ErrKeyInvalid)
	}
	alg := pubKey.Algorithm()
	if alg != AlgorithmEcdsaP256 {
		return nil, fmt.Errorf("%w: unsupported algorithm", ErrSignatureAlgorithmInvalid)
	}
	out := asn1RtuObject{
		Version:   metadata.Version(),
		Payload:   payload,
		Signature: signature,
		Algorithm: AlgorithmNone,
	}
	raw, err := asn1.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to marshal ASN.1 RTU object", ErrEncoding)
	}

	return asn1Rtu{
		size: int64(len(raw)),
		obj: asn1RtuObject{
			Version:   metadata.Version(),
			Payload:   payload,
			Signature: signature,
			Algorithm: AlgorithmNone,
		},
	}, nil
}

func (a asn1Rtu) Format() Format {
	return ASN1
}

func (a asn1Rtu) Version() Version {
	return a.obj.Version
}

func (a asn1Rtu) Parse() (Payload, PublicKey, error) {
	var payloadObj asn1PayloadObj
	if _, err := asn1.Unmarshal(a.obj.Payload, &payloadObj); err != nil {
		return nil, nil, fmt.Errorf("asn1 %w: %s", ErrDecoding, err.Error())
	}
	alg := a.obj.Algorithm
	if alg.Validate() != nil {
		alg = a.Version().DefaultSignatureAlgorithm()
	}
	if err := alg.Validate(); err != nil {
		return nil, nil, fmt.Errorf("asn1 %w: %s", ErrValidation, err.Error())
	}
	publicKey, err := CPK(payloadObj.CPK).Parse(alg)
	if err != nil {
		return nil, nil, fmt.Errorf("asn1 failed to decode cpk: %w", err)
	}
	return &asn1UnsignedPayload{
		obj: payloadObj,
		ver: a.obj.Version,
		pub: publicKey,
	}, publicKey, nil
}

func (a asn1Rtu) Payload() []byte {
	return a.obj.Payload
}

func (a asn1Rtu) Signature() []byte {
	return a.obj.Signature
}

func (a asn1Rtu) Size() int64 {
	return a.size
}

func (a asn1Rtu) Pack() (PackedRTU, error) {
	der, err := asn1.Marshal(a.obj)
	if err != nil {
		return "", fmt.Errorf("asn1 %w: %s", ErrEncoding, err.Error())
	}
	return PackedRTU(base64.RawURLEncoding.EncodeToString(der)), nil
}

func DecodeASN1(packed PackedRTU) (RTU, error) {
	der, err := base64.RawURLEncoding.DecodeString(string(packed))
	if err != nil {
		return nil, fmt.Errorf("asn1 %w: packed RTU is not base64url encoded", ErrDecoding)
	}
	var out asn1RtuObject
	_, err = asn1.Unmarshal(der, &out)
	if err != nil {
		return nil, fmt.Errorf("asn1 %w: packed RTU is not asn1 encoded", ErrDecoding)
	}
	return asn1Rtu{
		size: int64(len(der)),
		obj:  out,
	}, nil
}

var (
	asn1FieldMap = utils.Alias[string]{}
)
