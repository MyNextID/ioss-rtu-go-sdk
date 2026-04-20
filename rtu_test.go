package rtu_test

import (
	"errors"
	"testing"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
	"github.com/MyNextID/ioss-rtu-go-sdk/internal/helpers"
)

// ===============================================
// PackedRTU test-suite
// ===============================================

func TestPackedRTU_UnpackValidRTU(t *testing.T) {
	t.Parallel()

	validRtu := helpers.SignedPackedRTUV1(t)

	_, err := validRtu.Unpack()

	if err != nil {
		t.Errorf("Unpack() returned an error, %v", err)
	}
}

func TestPackedRTU_UnpackInvalidRTU(t *testing.T) {
	t.Parallel()

	invalidRtu := rtu.PackedRTU("foobar")

	_, err := invalidRtu.Unpack()
	if err == nil {
		t.Errorf("Unpack() did not return an error")
	} else if !errors.Is(err, rtu.ErrDecoding) {
		t.Errorf("Unpack() returned an unexpected error, %v", err)
	}
}

func TestPackedRTU_UnpackInvalidRTUButValidEncoding(t *testing.T) {
	t.Parallel()

	raw := rtu.RawRTU("foobar")
	invalidRtu := raw.Pack()

	_, err := invalidRtu.Unpack()
	if err == nil {
		t.Errorf("Unpack() did not return an error")
	} else if !errors.Is(err, rtu.ErrDecoding) {
		t.Errorf("Unpack() returned an unexpected error, %v", err)
	}
}

func TestPackedRTU_UnpackRTUWithInvalidSize(t *testing.T) {
	t.Parallel()

	// create a valid structure, with invalid sizes (payload size too big for Version1)
	raw := rtu.RTU{
		Version:   rtu.Version1,
		Payload:   make([]byte, 1024),
		Signature: make([]byte, 128),
		Algorithm: rtu.AlgorithmNone,
	}

	invalidRtu, err := raw.Pack()
	if err != nil {
		t.Errorf("Pack() returned an error, %v", err)
	}

	_, err = invalidRtu.Unpack()
	if err == nil {
		t.Errorf("Unpack() did not return an error")
	} else {
		// we expect a validation error
		var e *rtu.ValidationError
		if !errors.As(err, &e) {
			t.Errorf("Unpack() returned an unexpected error, %v", err)
		}
	}
}

func BenchmarkRTU_Pack(b *testing.B) {
	signedRtu := helpers.SignedRTUV1(b)

	b.ResetTimer()

	for b.Loop() {
		_, _ = signedRtu.Pack()
	}
}

func BenchmarkPackedRTU_Unpack(b *testing.B) {
	packedRtu := helpers.SignedPackedRTUV1(b)

	b.ResetTimer()

	for b.Loop() {
		_, _ = packedRtu.Unpack()
	}
}

func BenchmarkPackedRTU_UnpackWithoutValidation(b *testing.B) {
	packedRtu := helpers.SignedPackedRTUV1(b)

	b.ResetTimer()

	for b.Loop() {
		raw, _ := packedRtu.Raw()
		_, _ = raw.Parse(false)
	}
}

// ======================================================
// RTU test-suite
// ======================================================
