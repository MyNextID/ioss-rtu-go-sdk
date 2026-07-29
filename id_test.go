package rtu_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
	"github.com/MyNextID/ioss-rtu-go-sdk/internal/helpers"
)

func TestNewID(t *testing.T) {
	obj := helpers.SignedRawRTU(t)

	id := rtu.NewID(obj)

	if id == nil {
		t.Fatalf("ID is nil")
	}

	if len(id) != 32 {
		t.Fatalf("incorrect ID length: %d", len(id))
	}

	h := sha256.New()
	h.Write(obj.Payload())
	if !bytes.Equal(h.Sum(nil), id) {
		t.Fatalf("ID is invalid (not sha256)")
	}
}

func TestID_AsRef(t *testing.T) {
	obj := helpers.SignedRawRTU(t)
	id := rtu.NewID(obj)

	v1, err := id.AsRef(rtu.RefV1)
	if err != nil {
		t.Fatalf("AsRef() for RefV1 failed: %v", err)
	}

	if v1 != rtu.NewRefV1(obj) {
		t.Fatalf("AsRef() for RefV1 returned wrong ref")
	}

	v2, err := id.AsRef(rtu.RefV2)
	if err != nil {
		t.Fatalf("AsRef() for RefV2 failed: %v", err)
	}

	actualV2 := rtu.NewRefV2(obj)
	if v2 != actualV2 {
		t.Fatalf("AsRef() for RefV2 returned wrong ref, %s != %s", v2, actualV2)
	}

	if !v1.Equals(v2) {
		t.Fatalf("AsRef() for RefV1 returned ref, that is not for the same RTU as RefV2")
	}
}
