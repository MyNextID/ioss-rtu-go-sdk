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
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	// build a rtu.PrivateKey
	privKey, err := rtu.NewECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	// create your RTU payload
	txID := "tx-id"
	validUntil := time.Now().Add(time.Hour * 24 * 30)
	payload := rtu.NewPayload(txID, validUntil).
		SetDelegatedUse(false).
		SetSellerName("Acme Corp")

	// Sign the payload and generate the signed *rtu.PackedRTU object with Version 1
	packedRtu, err := rtu.Sign(rtu.Version1, payload, privKey)
	if err != nil {
		panic(err)
	}

	// output your signed rtu
	fmt.Println(packedRtu)
}
