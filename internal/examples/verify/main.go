package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"time"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

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

func main() {
	// get your IOSSRTU from a source, in this example we generate a valid one
	var packedRtu rtu.PackedRTU = generateAValidPackedRTU()

	signedObj, err := packedRtu.Unpack()
	if err != nil {
		/*
			If this error occurs, the rtu.PackedRTU is:
				1. not a valid base64-url encoded value
				2. not a valid ASN.1 DER encoded *rtu.RTU structure
				3. is not properly validated (incorrect version, size too big or too small, unknown algorithm etc.)
		*/
		panic(err)
	}
	// parse the payload from the signedObj. WithValidations should always be set to true, unless
	// you trust your source (it checks the signature and validates the constraints on the payload fields)
	payload, err := signedObj.Parse(true)
	if err != nil {
		// If this error occurs, signature verification or structure validation failed
		panic(err)
	}
	// valid IOSSRTU :)!
	// should output your RTU's TransactionID value (in our case "tx-id")
	fmt.Println(payload.TransactionID())
}
