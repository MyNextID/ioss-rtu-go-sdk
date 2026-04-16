package rtu_test

import (
	"testing"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
	"github.com/MyNextID/ioss-rtu-go-sdk/internal/helpers"
)

func generateExampleV1RTU(payload *rtu.Payload, t *testing.T) *rtu.RTU {
	if payload == nil {
		payload = helpers.MinimalRTU()
	}
	obj, err := rtu.SignV1(payload, generatePrivateKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return obj
}

var supportedVersions = map[rtu.Version]func(payload *rtu.Payload, t *testing.T) *rtu.RTU{
	rtu.Version1: generateExampleV1RTU,
}

func TestVersions(t *testing.T) {
	for version, fn := range supportedVersions {
		payload := helpers.MinimalRTU()
		obj := fn(payload, t)
		out, err := obj.Pack()
		if err != nil {
			t.Fatal(version, err)
		}

		// out is the value that should be sent to other services

		unpackedRtu, err := out.Unpack()
		if err != nil {
			t.Fatal(version, err)
		}
		parsedPayload, err := unpackedRtu.Parse(true)
		if err != nil {
			t.Fatal(version, err)
		}

		if parsedPayload.TransactionID() != payload.TransactionID() {
			t.Error("TransactionID mismatch")
		}
	}
}
