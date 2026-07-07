package rtu

import (
	"crypto/rand"
)

// Sign uses the UnsignedPayload given, and signs it with the PrivateKey (setting the private key's publicKey into the payload before signing)
// It return the final PackedRTU
func Sign(payload UnsignedPayload, key PrivateKey, opts ...SignOption) (PackedRTU, error) {
	// set the PublicKey to the payload
	finalPayload, err := payload.SetPublicKey(key.Public())
	if err != nil {
		return "", err
	}
	if !hasSignOption[*signWithoutValidating](opts) {
		err = ValidatePayload(finalPayload)
		if err != nil {
			return "", err
		}
	}
	// Marshal and output the raw bytes of the payload (to be signed)
	raw, err := finalPayload.Marshal()
	if err != nil {
		return "", err
	}
	// use the PrivateKey to sign the payload with the given format
	signature, err := key.Sign(payload, rand.Reader, raw)
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

type SignOption interface {
	optArgs() any
}

type signWithoutValidating struct{}

func (*signWithoutValidating) optArgs() any { return nil }

func WithoutSignValidation() SignOption {
	return &signWithoutValidating{}
}

func hasSignOption[T any](opts []SignOption) bool {
	return getSignOption[T](opts) != nil
}

func getSignOption[T any](opts []SignOption) SignOption {
	for _, opt := range opts {
		if _, ok := opt.(T); ok {
			return opt
		}
	}
	return nil
}
