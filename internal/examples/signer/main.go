package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

type jwtRtuHeader struct {
	// Alg => "ES256" — IANA-registered identifier for ECDSA with P-256 and SHA-256 (RFC 7518 §3.4). Maps to the existing AlgorithmEcdsaP256.
	Alg jwa.SignatureAlgorithm `json:"alg"`
	// "ioss-rtu+json" — application-specific media type following the +json structured-syntax suffix convention (RFC 6839). Allows recipients to identify the token type before parsing the payload.
	Typ string `json:"typ"`
	// Schema version integer. Equivalent to RTU.Version. Placed in the header so envelope validators can dispatch without parsing the payload.
	V int `json:"v"`
	// Cpk is a PackedCPK, if given
	Cpk *string `json:"cpk,omitempty"`
	// Jwk is a jwk key, and can be added instead of Cpk (XOR requirement)
	Jwk json.RawMessage `json:"jwk,omitempty"`
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

/*

	ASCII(
		BASE64URL(
			UTF8(JWS Protected Header)
		) || '.' || BASE64URL(JWS Payload))
*/

func main() {
	externalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	// build a rtu.PublicKey for our *rtu.ExternalSigner
	pubKey, err := rtu.NewECPublicKey(&externalKey.PublicKey)
	if err != nil {
		panic(err)
	}

	pub, err := rtu.ConvertPublicKeyToJWK(pubKey)
	if err != nil {
		panic(err)
	}

	rawPub, err := json.Marshal(pub.JWK())
	if err != nil {
		panic(err)
	}

	header := jwtRtuHeader{
		Jwk: rawPub,
		V:   1,
		Alg: jwa.ES256(),
	}

	payload := jwtRtuPayload{
		Jti: new("tx-id"),
		Exp: new(time.Now().Unix()),
		Du:  new(false),
	}

	headerJson, err := json.Marshal(header)
	if err != nil {
		panic(err)
	}

	payloadJson, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}

	fmt.Println("header:", string(headerJson))
	fmt.Println("payload:", string(payloadJson))

	toSign := base64.RawURLEncoding.EncodeToString(headerJson) + "." + base64.RawURLEncoding.EncodeToString(payloadJson)
	hash := sha256.New()
	hash.Write([]byte(toSign))

	signature, err := ecdsa.SignASN1(rand.Reader, externalKey, hash.Sum(nil))
	if err != nil {
		panic(err)
	}

	fmt.Println(base64.RawURLEncoding.EncodeToString(headerJson) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJson) + "." +
		base64.RawURLEncoding.EncodeToString(signature))
}
