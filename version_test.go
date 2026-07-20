package rtu_test

import (
	"testing"
	"time"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
	"github.com/MyNextID/ioss-rtu-go-sdk/internal/helpers"
)

func generateV1(tb testing.TB, id string) rtu.PackedRTU {
	return helpers.SignRTU(tb, rtu.NewVersion1ASN(id, time.Now().Add(time.Hour), false), helpers.GenerateRTUPrivateKey(tb))
}

var supportedVersions = map[rtu.Version]func(tb testing.TB, id string) rtu.PackedRTU{
	rtu.Version1: generateV1,
}

func TestVersions(t *testing.T) {
	tx := "tx-1234"
	for version, fn := range supportedVersions {
		out := fn(t, tx)
		// out is the value that should be sent to other services

		parsedPayload, _, err := rtu.Verify(out)

		if err != nil {
			t.Fatalf("%d: failed to verify payload: %s", version, err)
		}

		if *parsedPayload.TransactionID() != tx {
			t.Errorf("TransactionID mismatch for version %d", version)
		}
	}
}
