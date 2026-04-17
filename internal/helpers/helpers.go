package helpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

const (
	minimalRTUValidHours = 24
	fullRTUValidHours    = 48
	fullRTULimitConsign  = 10

	maxRTUValidHours     = 24
	maxSellerNameLen     = 100
	maxSellerAddressLen  = 100
	maxTransactionIDLen  = 50
	maxConsignmentIDLen  = 35
	maxLimitConsignments = 100
)

// GeneratePKCS8PEM returns a PEM-encoded PKCS#8 private key for testing.
func GeneratePKCS8PEM(tb testing.TB) ([]byte, *ecdsa.PrivateKey) {
	tb.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("failed to generate key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		tb.Fatalf("failed to marshal PKCS#8: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return pemBytes, priv
}

// GenerateSEC1PEM returns a PEM-encoded SEC1 (EC PRIVATE KEY) for testing.
func GenerateSEC1PEM(tb testing.TB) ([]byte, *ecdsa.PrivateKey) {
	tb.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("failed to generate key: %v", err)
	}

	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		tb.Fatalf("failed to marshal SEC1: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return pemBytes, priv
}

// GenerateKey returns a raw P-256 private key for testing without PEM encoding.
func GenerateKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("failed to generate P-256 key: %v", err)
	}

	return priv
}

func GenerateRTUPrivateKey(tb testing.TB) *rtu.PrivateKey {
	out, err := rtu.NewECPrivateKey(GenerateKey(tb))
	if err != nil {
		tb.Fatalf("failed to generate RTU private key: %v", err)
	}
	return out
}

func MinimalRTU() *rtu.Payload {
	return rtu.NewPayload("tx-minimal",
		time.Now().Add(minimalRTUValidHours*time.Hour)).
		SetDelegatedUse(false)
}

func FullRTU() *rtu.Payload {
	return rtu.NewPayload("tx-full-encode-test",
		time.Now().Add(fullRTUValidHours*time.Hour)).
		SetDelegatedUse(true).
		SetSellerName("Acme Corp").
		SetSellerAddress("1 Commerce Way").
		SetLimitDeliverArea("DE-BY").
		SetConsignments([]string{"CNS001", "CNS002", "CNS003"})
}

// MaxRTU returns the largest possible fully-valid IOSSRTU for size-boundary testing.
func MaxRTU() *rtu.Payload {
	return rtu.NewPayload(strings.Repeat("C", maxTransactionIDLen),
		time.Now().Add(maxRTUValidHours*time.Hour)).
		SetDelegatedUse(true).
		SetSellerName(strings.Repeat("A", maxSellerNameLen)).
		SetSellerAddress(strings.Repeat("B", maxSellerAddressLen)).
		SetLimitDeliverArea("US-ABCD").
		SetConsignments([]string{
			strings.Repeat("1", maxConsignmentIDLen), strings.Repeat("2", maxConsignmentIDLen),
			strings.Repeat("3", maxConsignmentIDLen), strings.Repeat("4", maxConsignmentIDLen),
			strings.Repeat("5", maxConsignmentIDLen), strings.Repeat("6", maxConsignmentIDLen),
			strings.Repeat("7", maxConsignmentIDLen), strings.Repeat("8", maxConsignmentIDLen),
			strings.Repeat("9", maxConsignmentIDLen), strings.Repeat("0", maxConsignmentIDLen),
		})
}

func SignedRTU(tb testing.TB) *rtu.RTU {
	tb.Helper()

	out, err := rtu.SignV1(MinimalRTU(), GenerateRTUPrivateKey(tb))
	if err != nil {
		tb.Fatalf("failed to sign RTU: %v", err)
	}
	return out
}

func SignedPackedRTU(tb testing.TB) rtu.PackedRTU {
	out, err := SignedRTU(tb).Pack()
	if err != nil {
		tb.Fatalf("failed to pack RTU: %v", err)
	}
	return out
}

// =============================================================================
// Assertion helper
// =============================================================================

func AssertPointerValuesRequiredFieldEqual[V comparable](tb testing.TB, name string, want, got *V) {
	tb.Helper()

	if want == nil {
		tb.Errorf("%s is nil", name)
		return
	}
	if got == nil {
		tb.Errorf("%s expected %v, got nil", name, *want)
		return
	}
	if *want != *got {
		tb.Errorf("%s: want %v, got %v", name, *want, *got)
	}
}

func AssertPointerValuesOptionalFieldEqual[V comparable](tb testing.TB, name string, want, got *V) {
	tb.Helper()

	if want != nil {
		if got == nil {
			tb.Errorf("%s expected %v, got nil", name, *want)
			return
		}
	} else if got != nil {
		tb.Errorf("%s expected nil, got %v", name, *got)
		return
	} else {
		return
	}

	if *want != *got {
		tb.Errorf("%s: want %v, got %v", name, *want, *got)
	}
}

func AssertPayloadEqual(t *testing.T, want, got *rtu.Payload) {
	t.Helper()

	// DelegatedUse is required
	AssertPointerValuesRequiredFieldEqual(t, "DelegatedUse",
		want.DelegatedUse(), got.DelegatedUse())

	// optional fields
	AssertPointerValuesOptionalFieldEqual(t, "SellerName",
		want.SellerName(), got.SellerName())

	AssertPointerValuesOptionalFieldEqual(t, "SellerAddress",
		want.SellerAddress(), got.SellerAddress())

	if got.TransactionID() != want.TransactionID() {
		t.Errorf("TransactionID: got %q, want %q", got.TransactionID(), want.TransactionID())
	}

	if !got.ValidUntil().Equal(want.ValidUntil()) {
		t.Errorf("ValidUntil: got %v, want %v", got.ValidUntil(), want.ValidUntil())
	}

	AssertPointerValuesOptionalFieldEqual(t, "LimitDeliverArea",
		want.LimitDeliverArea(), got.LimitDeliverArea())

	AssertPointerValuesOptionalFieldEqual(t, "LimitConsignments",
		want.LimitConsignments(), got.LimitConsignments())

	gotIds := got.Consignments()
	wantIds := want.Consignments()

	if len(gotIds) != len(wantIds) {
		t.Errorf("ConsignmentIDs length: got %d, want %d", len(gotIds), len(wantIds))
		return
	}
	for i := range wantIds {
		if gotIds[i] != wantIds[i] {
			t.Errorf("ConsignmentIDs[%d]: got %q, want %q", i, gotIds[i], wantIds[i])
		}
	}

}
