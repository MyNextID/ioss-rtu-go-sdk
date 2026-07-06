package rtu

import (
	"crypto/rand"
)

// Sign uses the UnsignedPayload given, and signs it with the PrivateKey (setting the private key's publicKey into the payload before signing)
// It return the final PackedRTU
func Sign(payload UnsignedPayload, key PrivateKey) (PackedRTU, error) {
	// set the PublicKey to the payload
	finalPayload, err := payload.SetPublicKey(key.Public())
	if err != nil {
		return "", err
	}
	// Marshal and output the raw bytes of the payload (to be signed)
	raw, err := finalPayload.Marshal()
	if err != nil {
		return "", err
	}
	// use the PrivateKey to sign the payload with the given format
	signature, err := key.Sign(payload.Format(), rand.Reader, raw)
	if err != nil {
		return "", err
	}
	// create the RTU object
	obj, err := makeRTU(finalPayload, raw, signature)
	if err != nil {
		return "", err
	}
	// pack the object into a string
	return obj.Pack()
}
