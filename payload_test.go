package rtu_test

import (
	"time"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

func generatePayload(txId string) *rtu.Payload {
	if txId == "" {
		txId = "test_tx_001"
	}
	return rtu.NewPayload(txId, time.Now().Add(time.Hour))
}
