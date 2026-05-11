package main

import (
	"fmt"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

/*
This example gets a packedRtu (rtu.PackedRTU) and parses it (verify signature and validate structure) to get rtu.Payload
*/
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
