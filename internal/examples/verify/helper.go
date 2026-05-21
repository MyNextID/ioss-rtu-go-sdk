package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"time"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

// A helper function to generate the PackedRTU to parse in this example
func generateAValidPackedRTU() rtu.PackedRTU {
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
	// Sign the payload and generate the signed *rtu.RTU object with Version 1
	signedObj, err := rtu.SignV1(payload, privKey)
	if err != nil {
		panic(err)
	}
	// pack the signedObj to get the final base64-url encoded IOSSRTU
	packedRtu, err := signedObj.Pack()
	if err != nil {
		panic(err)
	}
	return packedRtu
}
