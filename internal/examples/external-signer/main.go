package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"time"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

func signJwt(digest []byte, priv *ecdsa.PrivateKey) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

func main() {
	// generate an example ecdsa.PrivateKey (you would use your valid IOSS private key here)
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

	// create your RTU payload
	txID := "tx-id"
	validUntil := time.Now().Add(time.Hour * 24 * 30)
	payload := rtu.NewJWT(rtu.Version1).SetTransactionID(txID).SetValidUntil(validUntil).
		SetDelegatedUse(false).
		SetSellerName("Acme Corp")
	// we create our external signer, only the publicKey is needed
	signer, err := rtu.NewExternalSigner(rtu.JWT, rtu.Version1, pub)
	if err != nil {
		panic(err)
	}
	digest, rawPayload, err := signer.ComputeDigest(payload)
	if err != nil {
		panic(err)
	}
	// we sign digest with our private key (can be external service)
	signature, err := signJwt(digest, externalKey)
	if err != nil {
		panic(err)
	}
	// we return the signature along with the rawPayload back to our rtu.ExternalSigner
	packedRtu, err := signer.ConstructSigned(rawPayload, signature)
	if err != nil {
		panic(err)
	}
	// output your signed rtu
	fmt.Println(packedRtu)
}
