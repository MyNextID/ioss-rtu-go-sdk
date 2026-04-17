package rtu_test

import (
	"errors"
	"strings"
	"testing"
	"time"

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

// ===========================================================
// Version1 test-suite
// ===========================================================

func TestVersion1_Make_ValidPayload(t *testing.T) {
	t.Parallel()

	key := helpers.GenerateRTUPrivateKey(t)
	validPayload := helpers.MinimalRTU().SetCPK(key.GetCPK())

	_, err := rtu.Version1.Make(validPayload)
	if err != nil {
		t.Errorf("Make() returned an unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithoutDelegatedUse(t *testing.T) {
	t.Parallel()

	key := helpers.GenerateRTUPrivateKey(t)
	payload := rtu.NewPayload("bad_rtu", time.Now().Add(time.Hour)).SetCPK(key.GetCPK())

	var expectedError *rtu.ValidationError

	_, err := rtu.Version1.Make(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if errors.As(err, &expectedError) {
		if expectedError.Field != rtu.ValidationFieldDelegatedUse {
			t.Errorf("Make() expected to return DelegatedUse validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithoutCPK(t *testing.T) {
	t.Parallel()

	payload := helpers.MinimalRTU()

	var expectedError *rtu.ValidationError

	_, err := rtu.Version1.Make(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if errors.As(err, &expectedError) {
		if expectedError.Field != rtu.ValidationFieldCPK {
			t.Errorf("Make() expected to return CPK validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithInvalidCPK(t *testing.T) {
	t.Parallel()

	payload := helpers.MinimalRTU().SetCPK([]byte("foobar"))

	var expectedError *rtu.ValidationError

	_, err := rtu.Version1.Make(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if errors.As(err, &expectedError) {
		if expectedError.Field != rtu.ValidationFieldCPK {
			t.Errorf("Make() expected to return CPK validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithInvalidTransactionID(t *testing.T) {
	t.Parallel()

	key := helpers.GenerateRTUPrivateKey(t)
	payload := rtu.NewPayload(strings.Repeat("A", 150), time.Now().Add(time.Hour)).SetCPK(key.GetCPK())
	var expectedError *rtu.ValidationError

	_, err := rtu.Version1.Make(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if errors.As(err, &expectedError) {
		if expectedError.Field != rtu.ValidationFieldTransactionID {
			t.Errorf("Make() expected to return TransactionID validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithInvalidValidUntil(t *testing.T) {
	t.Parallel()

	key := helpers.GenerateRTUPrivateKey(t)
	payload := rtu.NewPayload("invalid_tx", time.Now().Add(-time.Hour)).SetCPK(key.GetCPK())
	var expectedError *rtu.ValidationError

	_, err := rtu.Version1.Make(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if errors.As(err, &expectedError) {
		if expectedError.Field != rtu.ValidationFieldValidUntil {
			t.Errorf("Make() expected to return ValidUntil validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithInvalidSellerName(t *testing.T) {
	t.Parallel()

	key := helpers.GenerateRTUPrivateKey(t)
	payload := helpers.MinimalRTU().SetCPK(key.GetCPK()).SetSellerName(strings.Repeat("A", 150))

	var expectedError *rtu.ValidationError

	_, err := rtu.Version1.Make(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if errors.As(err, &expectedError) {
		if expectedError.Field != rtu.ValidationFieldSellerName {
			t.Errorf("Make() expected to return SellerName validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithValidSellerName(t *testing.T) {
	t.Parallel()

	key := helpers.GenerateRTUPrivateKey(t)
	payload := helpers.MinimalRTU().SetCPK(key.GetCPK()).SetSellerName("Acme Corporation")

	_, err := rtu.Version1.Make(payload)
	if err != nil {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithInvalidSellerAddress(t *testing.T) {
	t.Parallel()

	key := helpers.GenerateRTUPrivateKey(t)
	payload := helpers.MinimalRTU().SetCPK(key.GetCPK()).SetSellerAddress(strings.Repeat("A", 150))

	var expectedError *rtu.ValidationError

	_, err := rtu.Version1.Make(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if errors.As(err, &expectedError) {
		if expectedError.Field != rtu.ValidationFieldSellerAddress {
			t.Errorf("Make() expected to return SellerAddress validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithValidSellerAddress(t *testing.T) {
	t.Parallel()

	key := helpers.GenerateRTUPrivateKey(t)
	payload := helpers.MinimalRTU().SetCPK(key.GetCPK()).SetSellerAddress("Example street 1")

	_, err := rtu.Version1.Make(payload)
	if err != nil {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithInvalidLimitDeliveryArea(t *testing.T) {
	t.Parallel()

	key := helpers.GenerateRTUPrivateKey(t)
	payload := helpers.MinimalRTU().SetCPK(key.GetCPK()).SetLimitDeliverArea("INVALID_AREA")

	var expectedError *rtu.ValidationError

	_, err := rtu.Version1.Make(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if errors.As(err, &expectedError) {
		if expectedError.Field != rtu.ValidationFieldLimitDeliveryArea {
			t.Errorf("Make() expected to return LimitDeliveryArea validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithValidLimitDeliveryArea(t *testing.T) {
	t.Parallel()

	key := helpers.GenerateRTUPrivateKey(t)
	payload := helpers.MinimalRTU().SetCPK(key.GetCPK()).SetLimitDeliverArea("SI-00")

	_, err := rtu.Version1.Make(payload)
	if err != nil {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithTooManyConsignmentIDs(t *testing.T) {
	t.Parallel()

	key := helpers.GenerateRTUPrivateKey(t)
	payload := helpers.MinimalRTU().SetCPK(key.GetCPK()).SetConsignments([]string{
		"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11",
	})

	var expectedError *rtu.ValidationError

	_, err := rtu.Version1.Make(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if errors.As(err, &expectedError) {
		if expectedError.Field != rtu.ValidationFieldConsignmentIDs {
			t.Errorf("Make() expected to return ConsignmentIDs validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithOneTooBigConsignmentID(t *testing.T) {
	t.Parallel()

	key := helpers.GenerateRTUPrivateKey(t)
	payload := helpers.MinimalRTU().SetCPK(key.GetCPK()).SetConsignments([]string{
		strings.Repeat("A", 150),
	})

	var expectedError *rtu.ValidationError

	_, err := rtu.Version1.Make(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if errors.As(err, &expectedError) {
		if expectedError.Field != rtu.ValidationFieldConsignmentIDs {
			t.Errorf("Make() expected to return ConsignmentIDs validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithValidConsignmentIDs(t *testing.T) {
	t.Parallel()

	key := helpers.GenerateRTUPrivateKey(t)
	payload := helpers.MinimalRTU().SetCPK(key.GetCPK()).SetConsignments([]string{
		strings.Repeat("A", 20),
	})

	_, err := rtu.Version1.Make(payload)
	if err != nil {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithLimitConsignmentsAndConsignmentIDs(t *testing.T) {
	t.Parallel()

	key := helpers.GenerateRTUPrivateKey(t)
	payload := helpers.MinimalRTU().SetCPK(key.GetCPK()).SetConsignments([]string{
		"ok_consignment_id",
	}).SetLimitConsignments(2)

	var expectedError *rtu.ValidationError

	_, err := rtu.Version1.Make(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if errors.As(err, &expectedError) {
		if expectedError.Field != rtu.ValidationFieldLimitConsignments {
			t.Errorf("Make() expected to return LimitConsignments validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithValidLimitConsignment(t *testing.T) {
	t.Parallel()

	key := helpers.GenerateRTUPrivateKey(t)
	payload := helpers.MinimalRTU().SetCPK(key.GetCPK()).SetLimitConsignments(2)

	_, err := rtu.Version1.Make(payload)
	if err != nil {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithInvalidLimitConsignment(t *testing.T) {
	t.Parallel()

	key := helpers.GenerateRTUPrivateKey(t)
	payload := helpers.MinimalRTU().SetCPK(key.GetCPK()).
		SetLimitConsignments(101)

	var expectedError *rtu.ValidationError

	_, err := rtu.Version1.Make(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if errors.As(err, &expectedError) {
		if expectedError.Field != rtu.ValidationFieldLimitConsignments {
			t.Errorf("Make() expected to return LimitConsignments validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}
