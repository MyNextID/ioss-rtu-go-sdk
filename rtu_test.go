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

func TestPackedRTU_ParseValidRTU(t *testing.T) {
	t.Parallel()

	validRtu := helpers.SignedRTU(t)

	_, err := validRtu.Parse()

	if err != nil {
		t.Errorf("Parse() returned an error, %v", err)
	}
}

func TestPackedRTU_ParseInvalidRTU(t *testing.T) {
	t.Parallel()

	invalidRtu := rtu.PackedRTU("foobar")

	_, err := invalidRtu.Parse()
	if err == nil {
		t.Errorf("Parse() did not return an error")
	} else if !errors.Is(err, rtu.ErrDecoding) {
		t.Errorf("Unpack() returned an unexpected error, %v", err)
	}
}

func BenchmarkRTU_Pack(b *testing.B) {
	signedRtu := helpers.SignedRTU(b)

	obj, err := signedRtu.Parse()
	if err != nil {
		b.Fatalf("Parse() returned an error, %v", err)
	}

	b.ResetTimer()

	for b.Loop() {
		_, _ = obj.Pack()
	}
}

func BenchmarkPackedRTU_Parse(b *testing.B) {
	packedRtu := helpers.SignedRTU(b)

	b.ResetTimer()

	for b.Loop() {
		_, _ = packedRtu.Parse()
	}
}

func BenchmarkPackedRTU_Verify(b *testing.B) {
	packedRtu := helpers.SignedRTU(b)

	b.ResetTimer()

	for b.Loop() {
		_, _, _ = rtu.Verify(packedRtu)
	}
}

// ======================================================
// RTU test-suite
// ======================================================
