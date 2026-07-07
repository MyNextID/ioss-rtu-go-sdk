package rtu

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type jwtUnsignedPayload struct {
	header  jwtRtuHeader
	payload jwtRtuPayload
	pub     PublicKey
}

func newJWT(version Version) UnsignedPayload {
	return &jwtUnsignedPayload{
		header: jwtRtuHeader{
			V:   version,
			Typ: "ioss-rtu+json",
		},
		payload: jwtRtuPayload{},
	}
}

func NewVersion1JWT(txId string, validUntil time.Time, delegatedUse bool) UnsignedPayload {
	return newJWT(Version1).SetTransactionID(txId).SetValidUntil(validUntil).SetDelegatedUse(delegatedUse)
}

func (j *jwtUnsignedPayload) Format() Format {
	return JWT
}

func (j *jwtUnsignedPayload) Version() Version {
	return j.header.V
}

func (j *jwtUnsignedPayload) ValidUntil() time.Time {
	if j.payload.Exp == nil {
		return time.Time{}
	}
	return time.Unix(*j.payload.Exp, 0)
}

func (j *jwtUnsignedPayload) TransactionID() *string {
	return j.payload.Jti
}

func (j *jwtUnsignedPayload) DelegatedUse() *bool {
	return j.payload.Du
}

func (j *jwtUnsignedPayload) SellerName() *string {
	return j.payload.Sn
}

func (j *jwtUnsignedPayload) SellerAddress() *string {
	return j.payload.Sa
}

func (j *jwtUnsignedPayload) LimitDeliveryArea() *string {
	return j.payload.Lda
}

func (j *jwtUnsignedPayload) Consignments() []string {
	return j.payload.Cid
}

func (j *jwtUnsignedPayload) LimitConsignments() *int {
	return j.payload.Lc
}

func (j *jwtUnsignedPayload) Marshal() ([]byte, error) {
	header, err := json.Marshal(j.header)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(j.payload)
	if err != nil {
		return nil, err
	}
	return []byte(
		base64.RawURLEncoding.EncodeToString(header) + "." +
			base64.RawURLEncoding.EncodeToString(payload)), nil
}

func (j *jwtUnsignedPayload) PublicKey() PublicKey {
	return j.pub
}

func (j *jwtUnsignedPayload) SetPublicKey(pk PublicKey) (UnsignedPayload, error) {
	alg, err := pk.Algorithm().ToJWA()
	if err != nil {
		return nil, err
	}
	j.pub = pk
	j.header.Alg = alg
	if withJwk, ok := pk.(PublicKeyJWK); ok {
		j.header.Jwk, err = json.Marshal(withJwk.JWK())
		if err != nil {
			return nil, err
		}
	} else {
		j.header.Cpk = new(pk.CPK().Pack())
	}
	return j, nil
}

func (j *jwtUnsignedPayload) SetValidUntil(t time.Time) UnsignedPayload {
	j.payload.Exp = new(t.UTC().Unix())
	return j
}

func (j *jwtUnsignedPayload) SetTransactionID(transactionID string) UnsignedPayload {
	j.payload.Jti = &transactionID
	return j
}

func (j *jwtUnsignedPayload) SetDelegatedUse(d bool) UnsignedPayload {
	j.payload.Du = &d
	return j
}

func (j *jwtUnsignedPayload) SetSellerName(s string) UnsignedPayload {
	j.payload.Sn = &s
	return j
}

func (j *jwtUnsignedPayload) SetSellerAddress(s string) UnsignedPayload {
	j.payload.Sa = &s
	return j
}

func (j *jwtUnsignedPayload) SetLimitDeliveryArea(s string) UnsignedPayload {
	j.payload.Lda = &s
	return j
}

func (j *jwtUnsignedPayload) SetConsignmentIDs(ids []string) UnsignedPayload {
	j.payload.Cid = ids
	return j
}

func (j *jwtUnsignedPayload) SetLimitConsignments(l int) UnsignedPayload {
	j.payload.Lc = &l
	return j
}

type jwtRtuHeader struct {
	// Alg => "ES256" — IANA-registered identifier for ECDSA with P-256 and SHA-256 (RFC 7518 §3.4). Maps to the existing AlgorithmEcdsaP256.
	Alg jwa.SignatureAlgorithm `json:"alg"`
	// "ioss-rtu+json" — application-specific media type following the +json structured-syntax suffix convention (RFC 6839). Allows recipients to identify the token type before parsing the payload.
	Typ string `json:"typ"`
	// Schema version integer. Equivalent to RTU.Version. Placed in the header so envelope validators can dispatch without parsing the payload.
	V Version `json:"v"`
	// Cpk is a PackedCPK, if given
	Cpk *PackedCPK `json:"cpk,omitempty"`
	// Jwk is a jwk key, and can be added instead of Cpk (XOR requirement)
	Jwk json.RawMessage `json:"jwk,omitempty"`
}

func (h jwtRtuHeader) PublicKey() (out PublicKey, err error) {
	var alg SignatureAlgorithm
	alg, err = ParseJwa(h.Alg)
	if err != nil {
		return nil, err
	}
	if h.Cpk != nil {
		out, err = h.Cpk.PublicKey(alg)
	} else if h.Jwk != nil {
		var key jwk.Key
		key, err = jwk.ParseKey(h.Jwk)
		if err != nil {
			return nil, err
		}
		out, err = NewJWKPublicKey(key)
	} else {
		return nil, fmt.Errorf("%w: no public key found", ErrKeyInvalid)
	}
	if err != nil {
		return nil, err
	}
	if out.Algorithm() != alg {
		return nil, fmt.Errorf("%w: invalid algorithm %s is not %s", ErrKeyInvalid, out.Algorithm(), alg)
	}
	return out, nil
}

type jwtRtuPayload struct {
	// RFC 7519 registered claim — transaction identifier
	Jti *string `json:"jti,omitempty"`
	// RFC 7519 registered claim — Unix timestamp (used for validUntil)
	Exp *int64 `json:"exp,omitempty"`
	// Private claim - DelegatedUse
	Du *bool `json:"du,omitempty"`
	// Private claim - SellerName
	Sn *string `json:"sn,omitempty"`
	// Private claim - SellerAddress
	Sa *string `json:"sa,omitempty"`
	// Private claim - LimitDeliveryArea
	Lda *string `json:"lda,omitempty"`
	// Private claim - ConsignmentIDs - mutually exclusive with lc
	Cid []string `json:"cid,omitempty"`
	// Private claim - LimitConsignments - mutually exclusive with cid; omit when not used
	Lc *int `json:"lc,omitempty"`
}

type jwtRTU struct {
	header    json.RawMessage
	payload   json.RawMessage
	signature []byte
}

func newJwtRtu(metadata makeRTUMetadata, payload, signature []byte) (RTU, error) {
	switch metadata.Version() {
	case Version1:
		return newJwtRtuVersion1(metadata, payload, signature)
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownVersion, metadata.Version())
	}
}

func newJwtRtuVersion1(metadata makeRTUMetadata, payload, signature []byte) (RTU, error) {
	temp := bytes.Split(payload, []byte("."))
	if len(temp) != 2 {
		return nil, fmt.Errorf("%w: raw payload is not JWT", ErrDecoding)
	}
	headerVal, err := base64.RawURLEncoding.DecodeString(string(temp[0]))
	if err != nil {
		return nil, fmt.Errorf("%w: header is not base64url", ErrDecoding)
	}
	payloadVal, err := base64.RawURLEncoding.DecodeString(string(temp[1]))
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64url", ErrDecoding)
	}
	return &jwtRTU{
		header:    headerVal,
		payload:   payloadVal,
		signature: signature,
	}, nil
}

func (j *jwtRTU) Format() Format {
	return JWT
}

func (j *jwtRTU) Version() Version {
	return Version1
}

func (j *jwtRTU) Parse() (Payload, PublicKey, error) {

	var out jwtUnsignedPayload

	if err := json.Unmarshal(j.payload, &out.payload); err != nil {
		return nil, nil, fmt.Errorf("%w header: %s", ErrDecoding, err)
	}

	if err := json.Unmarshal(j.header, &out.header); err != nil {
		return nil, nil, fmt.Errorf("%w payload: %s", ErrDecoding, err)
	}

	pub, err := out.header.PublicKey()
	if err != nil {
		return nil, nil, err
	}

	return &out, pub, nil
}

func (j *jwtRTU) Payload() []byte {
	return []byte(base64.RawURLEncoding.EncodeToString(j.header) + "." +
		base64.RawURLEncoding.EncodeToString(j.payload))
}

func (j *jwtRTU) Signature() []byte {
	return j.signature
}

func (j *jwtRTU) Size() int64 {
	return int64(len(j.header)+len(j.payload)+len(j.signature)) + 2
}

func (j *jwtRTU) Pack() (PackedRTU, error) {
	return PackedRTU(j.Payload()) + "." +
		PackedRTU(base64.RawURLEncoding.EncodeToString(j.Signature())), nil

}

func DecodeJWT(packed PackedRTU) (RTU, error) {
	temp := strings.Split(string(packed), ".")
	if len(temp) != 3 {
		return nil, ErrPackedRTUNotJWT
	}
	header, err := base64.RawURLEncoding.DecodeString(temp[0])
	if err != nil {
		return nil, fmt.Errorf("jwt %w: header is not base64url", ErrEncoding)
	}
	payload, err := base64.RawURLEncoding.DecodeString(temp[1])
	if err != nil {
		return nil, fmt.Errorf("jwt %w: payload is not base64url", ErrEncoding)
	}
	signature, err := base64.RawURLEncoding.DecodeString(temp[2])
	if err != nil {
		return nil, fmt.Errorf("jwt %w: signature is not base64url", ErrEncoding)
	}
	return &jwtRTU{
		header:    header,
		payload:   payload,
		signature: signature,
	}, nil
}
