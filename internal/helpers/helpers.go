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

	maxRTUValidHours    = 24
	maxSellerNameLen    = 100
	maxSellerAddressLen = 100
	maxTransactionIDLen = 50
	maxConsignmentIDLen = 35
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

func GenerateRTUPrivateKey(tb testing.TB) rtu.PrivateKey {
	out, err := rtu.NewECPrivateKey(GenerateKey(tb))
	if err != nil {
		tb.Fatalf("failed to generate RTU private key: %v", err)
	}
	return out
}

func GenerateRTUPrivateKeyWithJWK(tb testing.TB) rtu.PrivateKey {
	key := GenerateRTUPrivateKey(tb)
	if key != nil {
		var err error
		key, err = rtu.AddJWKToPrivateKey(key)
		if err != nil {
			tb.Fatalf("failed to generate RTU private key with JWK: %v", err)
		}
	}
	return key
}

func EmptyRTU(tb testing.TB, format rtu.Format, version rtu.Version) rtu.UnsignedPayload {
	out, err := rtu.New(format, version)
	if err != nil {
		tb.Fatalf("failed to create RTU payload: %v", err)
	}
	return out
}

func MinimalRTU() rtu.UnsignedPayload {
	return rtu.NewVersion1ASN("tx-minimal",
		time.Now().Add(minimalRTUValidHours*time.Hour), false)
}

func MinimalJWTRTU() rtu.UnsignedPayload {
	return rtu.NewVersion1JWT("tx-minimal",
		time.Now().Add(minimalRTUValidHours*time.Hour), false)
}

func FullRTU() rtu.UnsignedPayload {
	return rtu.NewVersion1ASN("tx-full-encode-test",
		time.Now().Add(fullRTUValidHours*time.Hour), true).
		SetSellerName("Acme Corp").
		SetSellerAddress("1 Commerce Way").
		SetLimitDeliveryArea("DE-BY").
		SetConsignmentIDs([]string{"CNS001", "CNS002", "CNS003"})
}

func FullJWTRTU() rtu.UnsignedPayload {
	return rtu.NewVersion1JWT("tx-full-encode-test",
		time.Now().Add(fullRTUValidHours*time.Hour), true).
		SetSellerName("Acme Corp").
		SetSellerAddress("1 Commerce Way").
		SetLimitDeliveryArea("DE-BY").
		SetConsignmentIDs([]string{"CNS001", "CNS002", "CNS003"})
}

// MaxRTU returns the largest possible fully-valid IOSSRTU for size-boundary testing.
func MaxRTU() rtu.UnsignedPayload {
	return rtu.NewVersion1ASN(strings.Repeat("C", maxTransactionIDLen),
		time.Now().Add(maxRTUValidHours*time.Hour), true).
		SetSellerName(strings.Repeat("A", maxSellerNameLen)).
		SetSellerAddress(strings.Repeat("B", maxSellerAddressLen)).
		SetLimitDeliveryArea("US-ABCD").
		SetConsignmentIDs([]string{
			strings.Repeat("1", maxConsignmentIDLen), strings.Repeat("2", maxConsignmentIDLen),
			strings.Repeat("3", maxConsignmentIDLen), strings.Repeat("4", maxConsignmentIDLen),
			strings.Repeat("5", maxConsignmentIDLen), strings.Repeat("6", maxConsignmentIDLen),
			strings.Repeat("7", maxConsignmentIDLen), strings.Repeat("8", maxConsignmentIDLen),
			strings.Repeat("9", maxConsignmentIDLen), strings.Repeat("0", maxConsignmentIDLen),
		})
}

func MaxJWTRTU() rtu.UnsignedPayload {
	return rtu.NewVersion1JWT(strings.Repeat("C", maxTransactionIDLen),
		time.Now().Add(maxRTUValidHours*time.Hour), true).
		SetSellerName(strings.Repeat("A", maxSellerNameLen)).
		SetSellerAddress(strings.Repeat("B", maxSellerAddressLen)).
		SetLimitDeliveryArea("US-ABCD").
		SetConsignmentIDs([]string{
			strings.Repeat("1", maxConsignmentIDLen), strings.Repeat("2", maxConsignmentIDLen),
			strings.Repeat("3", maxConsignmentIDLen), strings.Repeat("4", maxConsignmentIDLen),
			strings.Repeat("5", maxConsignmentIDLen), strings.Repeat("6", maxConsignmentIDLen),
			strings.Repeat("7", maxConsignmentIDLen), strings.Repeat("8", maxConsignmentIDLen),
			strings.Repeat("9", maxConsignmentIDLen), strings.Repeat("0", maxConsignmentIDLen),
		})
}

func SignRTU(tb testing.TB, payload rtu.UnsignedPayload, key rtu.PrivateKey) rtu.PackedRTU {
	tb.Helper()

	out, err := rtu.Sign(payload, key)
	if err != nil {
		tb.Fatalf("failed to sign RTU: %v", err)
	}

	return out
}

func SignedRTU(tb testing.TB) rtu.PackedRTU {
	return SignRTU(tb, MinimalRTU(), GenerateRTUPrivateKey(tb))
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

	if want == nil {
		if got != nil {
			tb.Errorf("%s expected nil, got %v", name, *got)
		}
		return
	} else if got == nil {
		tb.Errorf("%s expected %v, got nil", name, *want)
		return
	}

	if *want != *got {
		tb.Errorf("%s: want %v, got %v", name, *want, *got)
	}
}

func AssertPayloadEqual(t *testing.T, want, got rtu.Payload) {
	t.Helper()

	// DelegatedUse is required
	AssertPointerValuesRequiredFieldEqual(t, "DelegatedUse",
		want.DelegatedUse(), got.DelegatedUse())

	AssertPointerValuesRequiredFieldEqual(t, "TransactionID",
		want.TransactionID(), got.TransactionID())

	if !got.ValidUntil().Equal(want.ValidUntil()) {
		t.Errorf("ValidUntil: got %v, want %v", got.ValidUntil(), want.ValidUntil())
	}

	// optional fields
	AssertPointerValuesOptionalFieldEqual(t, "SellerName",
		want.SellerName(), got.SellerName())

	AssertPointerValuesOptionalFieldEqual(t, "SellerAddress",
		want.SellerAddress(), got.SellerAddress())

	AssertPointerValuesOptionalFieldEqual(t, "LimitDeliveryArea",
		want.LimitDeliveryArea(), got.LimitDeliveryArea())

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
