package rtu_test

import (
	"bytes"
	"testing"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
	"github.com/MyNextID/ioss-rtu-go-sdk/internal/helpers"
)

func TestNewRefV1(t *testing.T) {
	obj := helpers.SignedRawRTU(t)
	ref := rtu.NewRefV1(obj)
	if ref == "" {
		t.Fatalf("NewRefV1() returned an empty string")
	}
	_, err := ref.ParseID()
	if err != nil {
		t.Fatalf("Parse() returned an error: %s", err.Error())
	}
	if v := ref.Version(); v != rtu.RefV1 {
		t.Fatalf("Version() returned a wrong version: %d", v)
	}
}

func TestNewRefV2(t *testing.T) {
	obj := helpers.SignedRawRTU(t)
	ref := rtu.NewRefV2(obj)
	if ref == "" {
		t.Fatalf("NewRefV2() returned an empty string")
	}
	_, err := ref.ParseID()
	if err != nil {
		t.Fatalf("Parse() returned an error: %s", err.Error())
	}
	if v := ref.Version(); v != rtu.RefV2 {
		t.Fatalf("Version() returned a wrong version: %d", v)
	}
}

func TestNewRefID(t *testing.T) {
	obj := helpers.SignedRawRTU(t)
	ref := rtu.NewRefID(obj)
	if ref == "" {
		t.Fatalf("NewRefID() returned an empty string")
	}
	val, err := ref.ParseID()
	if err != nil {
		t.Fatalf("Parse() returned an error: %s", err.Error())
	}
	if v := ref.Version(); v != rtu.RefID {
		t.Fatalf("Version() returned a wrong version: %d", v)
	}
	if !bytes.Equal(val, rtu.NewID(obj)) {
		t.Fatalf("NewRefID() returned a wrong ID: %s", val)
	}
}

func TestRef_IsSame(t *testing.T) {
	obj := helpers.SignedRawRTU(t)
	refV1 := rtu.NewRefV1(obj)
	refV2 := rtu.NewRefV2(obj)

	if refV1 == refV2 {
		t.Fatalf("RefV1 and RefV2 should not be the same")
	}

	if !refV1.IsSame(refV2) {
		t.Fatalf("RefV1 and RefV2 are from same RTU, but IsSame returned false")
	}
	if !refV2.IsSame(refV1) {
		t.Fatalf("RefV1 and RefV2 are from same RTU, but IsSame returned false")
	}
}

func TestRef_Bytes(t *testing.T) {
	obj := helpers.SignedRawRTU(t)
	refV1 := rtu.NewRefV1(obj)
	refV2 := rtu.NewRefV2(obj)

	v1Bytes := refV1.Bytes()
	v2Bytes := refV2.Bytes()

	if len(v1Bytes) != 10 {
		t.Fatalf("RefV1.Bytes() returned a wrong length: %d", len(v1Bytes))
	}
	if len(v2Bytes) != 20 {
		t.Fatalf("RefV2.Bytes() returned a wrong length: %d", len(v2Bytes))
	}

	id := rtu.NewID(obj)

	// check the v1Bytes have returned exactly the first 75 bits of the ID (9 bytes and 3 bits)
	if !bytes.Equal(v1Bytes[:9], id[:9]) || v1Bytes[9] != id[9]&0b11100000 {
		t.Fatalf("RefV1.Bytes() returned the wrong bytes")
	}
	if !bytes.Equal(v2Bytes, id[:20]) {
		t.Fatalf("RefV2.Bytes() returned the wrong bytes")
	}
}
