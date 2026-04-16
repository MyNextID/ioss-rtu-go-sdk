package rtu_test

import (
	"bytes"
	"testing"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

func TestVersion1(t *testing.T) {
	priv, cpk := generateCPK(t)
	payload := generatePayload(t).SetDelegatedUse(true)
	obj, err := rtu.SignV1(payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload.CPK(), cpk) {
		t.Fatal("cpk not set by signer")
	}
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
