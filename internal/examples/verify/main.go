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
	payload := rtu.NewVersion1JWT(txID, validUntil, false).
		SetSellerName("Acme Corp")

	// Sign the payload and generate the packed *rtu.PackedRTU object with Version 1
	packedRtu, err := rtu.Sign(payload, privKey)
	if err != nil {
		panic(err)
	}

	return packedRtu
}

func main() {
	// get your IOSSRTU from a source, in this example we generate a valid one
	var packedRtu = generateAValidPackedRTU()

	payload, _, err := rtu.Verify(packedRtu)
	if err != nil {
		panic(err)
	}
	// valid IOSSRTU :)!
	// should output your RTU's TransactionID value (in our case "tx-id")
	fmt.Println(*payload.TransactionID())
}
