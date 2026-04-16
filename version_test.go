package rtu_test

import (
	"testing"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

func generateExampleV1RTU(payload *rtu.Payload, t *testing.T) *rtu.RTU {
	if payload == nil {
		payload = generatePayload("").SetDelegatedUse(false)
	}
	obj, err := rtu.SignV1(payload, generatePrivateKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return obj
}

func TestVersion1(t *testing.T) {
	payload := generatePayload("test_v1").SetDelegatedUse(false)
	obj := generateExampleV1RTU(payload, t)
	out, err := obj.Pack()
	if err != nil {
		t.Fatal(err)
	}

	// out is the value that should be sent to other services

	unpackedRtu, err := out.Unpack()
	if err != nil {
		t.Fatal(err)
	}
	parsedPayload, err := unpackedRtu.Parse(true)
	if err != nil {
		t.Fatal(err)
	}

	if parsedPayload.TransactionID() != payload.TransactionID() {
		t.Error("TransactionID mismatch")
	}
}
