package rtu

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"
)

var (
	refEncoder = base32.StdEncoding.WithPadding(base32.NoPadding)
)

const (
	refV1Size    = 15
	refV1RawSize = 10

	refV2Size    = 34
	refV2RawSize = 20
	refV2Prefix  = "02"
)

// Ref is a reference string for an RTU. It is used as a reference or identity of an RTU by the
// IOSS RTU deposit service. When depositing the RTU, a Ref is returned by the deposit service. This
// code allows other implementations to calculate the Ref before depositing to the deposit service
type Ref string

// NewRefV1 creates a version 1 Ref = base32(first_75_bits_sha256(rtu_payload))
func NewRefV1(rtu RTU) Ref {
	// take first 10 bytes of sha256 hash
	raw := prepareUniqueHash(rtu)[:refV1RawSize]
	// unset the last 5 bits
	raw[len(raw)-1] &= 0b11100000
	// return the base32(NoPadding) encoded bytes (cut the last character 'A' as it is always the same)
	return Ref(refEncoder.EncodeToString(raw)[:refV1Size])
}

// NewRefV2 creates a version 2 Ref = "02" + base32(first_160_bits_sha256(rtu_payload))
func NewRefV2(rtu RTU) Ref {
	// take first 20 bytes of sha256 hash
	raw := prepareUniqueHash(rtu)[:refV2RawSize]
	// encode to base32, prepend the "02" header, which allows parsing this as v2 and return the created Ref
	return Ref(refV2Prefix + refEncoder.EncodeToString(raw))
}

// Parse parses the Ref and tries to get the raw bytes of the hash for the RTU payload. Used by the deposit
// and verifier services to query the correct RTU based on the given Ref.
func (r Ref) Parse() ([]byte, error) {
	switch len(r) {
	case refV1Size:
		// add "A" at the end, to make the string 16 chars long (base32 decode requires correct length)
		out, err := decodeRefString(string(r) + "A")
		if err != nil {
			return nil, err
		}
		// ensure the last byte only has the first 3 bits set
		out[len(out)-1] &= 0b11100000
		return out, nil
	case refV2Size:
		if strings.HasPrefix(string(r), refV2Prefix) {
			return decodeRefString(string(r)[len(refV2Prefix):])
		}
	}
	return nil, fmt.Errorf("invalid ref: %s", r)
}

// Version returns the version of this Ref. It does not validate the encoding, just tries to determine
// the version number. For validation, use Ref.Parse
func (r Ref) Version() int {
	switch len(r) {
	case refV1Size:
		return 1
	case refV2Size:
		if strings.HasPrefix(string(r), refV2Prefix) {
			return 2
		}
	}
	return 0
}

// prepareUniqueHash is a helper function, that creates a unique byte array from an RTU
func prepareUniqueHash(rtu RTU) []byte {
	h := sha256.New()
	h.Write(rtu.Payload())
	return h.Sum(nil)
}

// decodeRefString is a helper function, decoding the value with refEncoder and returning ErrDecoding
// if there is any errors
func decodeRefString(val string) ([]byte, error) {
	out, err := refEncoder.DecodeString(val)
	if err != nil {
		return nil, ErrDecoding
	}
	return out, nil
}
