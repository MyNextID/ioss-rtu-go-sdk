package rtu

import (
	"crypto/rand"
)

// Sign wraps SignRaw, but returns the PackedRTU instead of the RTU object
func Sign(payload UnsignedPayload, key PrivateKey, opts ...SignOption) (PackedRTU, error) {
	obj, err := SignRaw(payload, key, opts...)
	if err != nil {
		return "", err
	}
	// pack the object into a string
	return obj.Pack()
}

// SignRaw uses the UnsignedPayload given and signs it with the PrivateKey
// (it also sets the publicKey to the payload, validates the payload (unless WithoutSignValidation is given as an option)
// and returns the signed RTU object
func SignRaw(payload UnsignedPayload, key PrivateKey, opts ...SignOption) (RTU, error) {
	// set the PublicKey to the payload
	finalPayload, err := payload.SetPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	if !hasSignOption[*signWithoutValidating](opts) {
		err = ValidatePayload(finalPayload)
		if err != nil {
			return nil, err
		}
	}
	// Marshal and output the raw bytes of the payload (to be signed)
	raw, err := finalPayload.Marshal()
	if err != nil {
		return nil, err
	}
	// use the PrivateKey to sign the payload with the given format
	signature, err := key.Sign(payload, rand.Reader, raw)
	if err != nil {
		return nil, err
	}
	// create the RTU object
	obj, err := makeRTU(finalPayload, raw, signature)
	if err != nil {
		return nil, err
	}
	return obj, nil
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
