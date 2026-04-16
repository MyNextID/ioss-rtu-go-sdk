package rtu_test

import (
	"testing"
	"time"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

func generatePayload(t *testing.T) *rtu.Payload {
	return rtu.NewPayload("test_tx_001", time.Now().Add(time.Hour))
}

func TestNewPayload(t *testing.T) {
	generatePayload(t)
}
