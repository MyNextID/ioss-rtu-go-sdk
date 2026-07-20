package rtu_test

import (
	"errors"
	"testing"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

var validRtuFormats []rtu.Format = []rtu.Format{
	rtu.ASN1, rtu.JWT,
}

const invalidRtuFormat rtu.Format = "abcdefghijklmnopqrst"

func TestFormat_Validate(t *testing.T) {
	t.Parallel()

	err := rtu.FormatNone.Validate()
	if err == nil {
		t.Fatalf("None format should return an error")
	} else if !errors.Is(err, rtu.ErrNoFormat) {
		t.Fatalf("None format should return ErrNoFormat")
	}

	for _, format := range validRtuFormats {
		err = format.Validate()
		if err != nil {
			t.Fatalf("%s format should not return an error: %s", format, err)
		}
	}

	err = invalidRtuFormat.Validate()
	if err == nil {
		t.Fatalf("Invalid format should return an error")
	} else if !errors.Is(err, rtu.ErrUnknownFormat) {
		t.Fatalf("Invalid format should return ErrUnknownFormat")
	}
}
