package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"time"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

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
	// create your RTU payload
	txID := "tx-id"
	validUntil := time.Now().Add(time.Hour * 24 * 30)
	payload := rtu.NewPayload(txID, validUntil).
		SetDelegatedUse(false).
		SetSellerName("Acme Corp")
	// we create our external signer, only the publicKey is needed
	signer := rtu.NewExternalSigner(rtu.Version1, pubKey)
	digest, rawPayload, err := signer.ComputeDigest(payload)
	if err != nil {
		panic(err)
	}
	// we sign digest with our private key (can be external service)
	signature, err := ecdsa.SignASN1(rand.Reader, externalKey, digest)
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
