package rtu_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
	"github.com/MyNextID/ioss-rtu-go-sdk/internal/helpers"
)

// ===========================================================
// Version1 test-suite
// ===========================================================

func TestVersion1_Make_ValidPayload(t *testing.T) {
	t.Parallel()

	err := rtu.ValidatePayload(helpers.MinimalRTU())

	if err != nil {
		t.Errorf("ValidatePayload() returned an unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithoutTransactionID(t *testing.T) {
	t.Parallel()

	payload := helpers.EmptyRTU(t, rtu.ASN1, rtu.Version1).SetValidUntil(time.Now().Add(1 * time.Hour)).SetDelegatedUse(false)

	err := rtu.ValidatePayload(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if expectedError, ok := errors.AsType[*rtu.ValidationError](err); ok {
		if expectedError.Field != rtu.ValidationFieldTransactionID {
			t.Errorf("Make() expected to return TransactionID validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithoutValidUntil(t *testing.T) {
	t.Parallel()

	payload := helpers.EmptyRTU(t, rtu.ASN1, rtu.Version1).SetTransactionID("tx-id").SetDelegatedUse(false)

	err := rtu.ValidatePayload(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if expectedError, ok := errors.AsType[*rtu.ValidationError](err); ok {
		if expectedError.Field != rtu.ValidationFieldValidUntil {
			t.Errorf("Make() expected to return ValidUntil validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithoutDelegatedUse(t *testing.T) {
	t.Parallel()

	payload := helpers.EmptyRTU(t, rtu.JWT, rtu.Version1).SetTransactionID("tx-id").SetValidUntil(time.Now().Add(1 * time.Hour))

	err := rtu.ValidatePayload(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error: %v", payload.DelegatedUse())
	} else if expectedError, ok := errors.AsType[*rtu.ValidationError](err); ok {
		if expectedError.Field != rtu.ValidationFieldDelegatedUse {
			t.Errorf("Make() expected to return DelegatedUse validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithInvalidTransactionID(t *testing.T) {
	t.Parallel()

	payload := helpers.EmptyRTU(t, rtu.ASN1, rtu.Version1).SetTransactionID(strings.Repeat("A", 150)).SetValidUntil(time.Now().Add(time.Hour)).SetDelegatedUse(false)

	err := rtu.ValidatePayload(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if expectedError, ok := errors.AsType[*rtu.ValidationError](err); ok {
		if expectedError.Field != rtu.ValidationFieldTransactionID {
			t.Errorf("Make() expected to return TransactionID validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithInvalidValidUntil(t *testing.T) {
	t.Parallel()

	payload := helpers.EmptyRTU(t, rtu.ASN1, rtu.Version1).SetTransactionID("invalid-tx").SetValidUntil(time.Now().Add(-time.Hour)).SetDelegatedUse(false)

	err := rtu.ValidatePayload(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if expectedError, ok := errors.AsType[*rtu.ValidationError](err); ok {
		if expectedError.Field != rtu.ValidationFieldValidUntil {
			t.Errorf("Make() expected to return ValidUntil validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithInvalidSellerName(t *testing.T) {
	t.Parallel()

	payload := helpers.MinimalRTU().SetSellerName(strings.Repeat("A", 150))

	err := rtu.ValidatePayload(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if expectedError, ok := errors.AsType[*rtu.ValidationError](err); ok {
		if expectedError.Field != rtu.ValidationFieldSellerName {
			t.Errorf("Make() expected to return SellerName validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithValidSellerName(t *testing.T) {
	t.Parallel()

	payload := helpers.MinimalRTU().SetSellerName("Acme Corporation")

	err := rtu.ValidatePayload(payload)
	if err != nil {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithInvalidSellerAddress(t *testing.T) {
	t.Parallel()

	payload := helpers.MinimalRTU().SetSellerAddress(strings.Repeat("A", 150))

	err := rtu.ValidatePayload(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if expectedError, ok := errors.AsType[*rtu.ValidationError](err); ok {
		if expectedError.Field != rtu.ValidationFieldSellerAddress {
			t.Errorf("Make() expected to return SellerAddress validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithValidSellerAddress(t *testing.T) {
	t.Parallel()

	payload := helpers.MinimalRTU().SetSellerAddress("Example street 1")

	err := rtu.ValidatePayload(payload)
	if err != nil {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithInvalidLimitDeliveryArea(t *testing.T) {
	t.Parallel()

	payload := helpers.MinimalRTU().SetLimitDeliveryArea("INVALID_AREA")

	err := rtu.ValidatePayload(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if expectedError, ok := errors.AsType[*rtu.ValidationError](err); ok {
		if expectedError.Field != rtu.ValidationFieldLimitDeliveryArea {
			t.Errorf("Make() expected to return LimitDeliveryArea validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithValidLimitDeliveryArea(t *testing.T) {
	t.Parallel()

	payload := helpers.MinimalRTU().SetLimitDeliveryArea("SI-00")

	err := rtu.ValidatePayload(payload)
	if err != nil {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithTooManyConsignmentIDs(t *testing.T) {
	t.Parallel()

	payload := helpers.MinimalRTU().SetConsignmentIDs([]string{
		"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11",
	})

	err := rtu.ValidatePayload(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if expectedError, ok := errors.AsType[*rtu.ValidationError](err); ok {
		if expectedError.Field != rtu.ValidationFieldConsignmentIDs {
			t.Errorf("Make() expected to return ConsignmentIDs validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithOneTooBigConsignmentID(t *testing.T) {
	t.Parallel()

	payload := helpers.MinimalRTU().SetConsignmentIDs([]string{
		strings.Repeat("A", 150),
	})

	err := rtu.ValidatePayload(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if expectedError, ok := errors.AsType[*rtu.ValidationError](err); ok {
		if expectedError.Field != rtu.ValidationFieldConsignmentIDs {
			t.Errorf("Make() expected to return ConsignmentIDs validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithValidConsignmentIDs(t *testing.T) {
	t.Parallel()

	payload := helpers.MinimalRTU().SetConsignmentIDs([]string{
		strings.Repeat("A", 20),
	})

	err := rtu.ValidatePayload(payload)
	if err != nil {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithLimitConsignmentsAndConsignmentIDs(t *testing.T) {
	t.Parallel()

	payload := helpers.MinimalRTU().SetConsignmentIDs([]string{
		"ok_consignment_id",
	}).SetLimitConsignments(2)

	err := rtu.ValidatePayload(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if expectedError, ok := errors.AsType[*rtu.ValidationError](err); ok {
		if expectedError.Field != rtu.ValidationFieldLimitConsignments {
			t.Errorf("Make() expected to return LimitConsignments validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithValidLimitConsignment(t *testing.T) {
	t.Parallel()

	payload := helpers.MinimalRTU().SetLimitConsignments(2)

	err := rtu.ValidatePayload(payload)
	if err != nil {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_Make_PayloadWithInvalidLimitConsignment(t *testing.T) {
	t.Parallel()

	payload := helpers.MinimalRTU().
		SetLimitConsignments(101)

	err := rtu.ValidatePayload(payload)
	if err == nil {
		t.Errorf("Make() expected to return an error")
	} else if expectedError, ok := errors.AsType[*rtu.ValidationError](err); ok {
		if expectedError.Field != rtu.ValidationFieldLimitConsignments {
			t.Errorf("Make() expected to return LimitConsignments validation error, got %s: %s", expectedError.Field, expectedError.Message)
		}
	} else {
		t.Errorf("Make() returned unexpected error: %v", err)
	}
}

func TestVersion1_DefaultSignatureAlgorithm(t *testing.T) {
	t.Parallel()

	if rtu.Version1.DefaultSignatureAlgorithm() != rtu.AlgorithmEcdsaP256 {
		t.Errorf("Incorrect default signature algorithm for version 1")
	}
}

func TestVersion1_Parse_ValidPayload(t *testing.T) {
	t.Parallel()

	payload := rtu.NewVersion1ASN("tx-test", time.Now().Add(time.Hour), false)

	err := rtu.ValidatePayload(payload)
	if err != nil {
		t.Errorf("Parse() returned unexpected error: %v", err)
	}
}
