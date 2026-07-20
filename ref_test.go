package rtu_test

import (
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
	_, err := ref.Parse()
	if err != nil {
		t.Fatalf("Parse() returned an error: %s", err.Error())
	}
	if v := ref.Version(); v != 1 {
		t.Fatalf("Version() returned a wrong version: %d", v)
	}
}

func TestNewRefV2(t *testing.T) {
	obj := helpers.SignedRawRTU(t)
	ref := rtu.NewRefV2(obj)
	if ref == "" {
		t.Fatalf("NewRefV2() returned an empty string")
	}
	_, err := ref.Parse()
	if err != nil {
		t.Fatalf("Parse() returned an error: %s", err.Error())
	}
	if v := ref.Version(); v != 2 {
		t.Fatalf("Version() returned a wrong version: %d", v)
	}
}
