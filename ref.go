package rtu

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"strings"
)

var (
	// refEncoder is the encoder for RefV1 and RefV2
	refEncoder = base32.StdEncoding.WithPadding(base32.NoPadding)
	// refIDEncoder is the encoder for RefID
	refIDEncoder = base64.RawURLEncoding
)

const (
	// refV1Size is the size of RefV1 in Ref form
	refV1Size = 15

	// refV2Size is the size of RefV2 in Ref form
	refV2Size = 34
	// refV2Prefix is the prefix for RefV2
	refV2Prefix = "02"

	// refID is sha256 hash base64url encoded. if prepareUniqueHash changes, these must be changed!
	refIDSize = 43

	// EmptyRef is a reference to an empty Ref
	EmptyRef = Ref("")
)

// Ref is a reference string for an RTU. It is used as a reference or identity of an RTU by the
// IOSS RTU deposit service. When depositing the RTU, a Ref is returned by the deposit service. This
// code allows other implementations to calculate the Ref before depositing to the deposit service
type Ref string

// NewRefID creates a version ID Ref = base64url(sha256(rtu_payload))
func NewRefID(rtu RTU) Ref {
	return newRefID(NewID(rtu))
}

func newRefID(id ID) Ref {
	if len(id) != idLength {
		return EmptyRef
	}
	return Ref(refIDEncoder.EncodeToString(id))
}

// NewRefV1 creates a version 1 Ref = base32(first_75_bits_sha256(rtu_payload))
func NewRefV1(rtu RTU) Ref {
	return newRefV1(NewID(rtu))
}

// newRefV1 creates the RefV1 from a raw ID.
func newRefV1(id ID) Ref {
	if len(id) < idRefV1Length {
		return EmptyRef
	}
	// take first 10 bytes of sha256 hash
	raw := make([]byte, idRefV1Length)
	copy(raw, id)
	// unset the last 5 bits
	raw[len(raw)-1] &= 0b11100000
	// return the base32(NoPadding) encoded bytes (cut the last character 'A' as it is always the same)
	return Ref(refEncoder.EncodeToString(raw)[:refV1Size])
}

// NewRefV2 creates a version 2 Ref = "02" + base32(first_160_bits_sha256(rtu_payload))
func NewRefV2(rtu RTU) Ref {
	return newRefV2(NewID(rtu))
}

func newRefV2(id ID) Ref {
	if len(id) < idRefV2Length {
		return EmptyRef
	}
	// take first 20 bytes of sha256 hash
	raw := id[:idRefV2Length]
	// encode to base32, prepend the "02" header, which allows parsing this as v2 and return the created Ref
	return Ref(refV2Prefix + refEncoder.EncodeToString(raw))
}

// ParseID parses the Ref and tries to get the raw bytes of the hash for the RTU payload (ID). Used by the deposit
// and verifier services to query the correct RTU based on the given Ref.
func (r Ref) ParseID() (ID, error) {
	switch len(r) {
	case refIDSize:
		val, err := refIDEncoder.DecodeString(string(r))
		if err != nil {
			return nil, ErrDecoding
		}
		return val, nil
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
	return nil, fmt.Errorf("%w: %s", ErrUnknownRefVersion, r)
}

// Bytes gets the raw byte array of the ID hash (as many bytes as the Ref holds)
func (r Ref) Bytes() []byte {
	out, _ := r.ParseID()
	if out == nil {
		return []byte{}
	}
	return out
}

// Version returns the version of this Ref. It does not validate the encoding, just tries to determine
// the version number. For validation, use Ref.Parse
func (r Ref) Version() RefVersion {
	switch len(r) {
	case refIDSize:
		return RefID
	case refV1Size:
		return RefV1
	case refV2Size:
		if strings.HasPrefix(string(r), refV2Prefix) {
			return RefV2
		}
	}
	return RefUnknown
}

// Equals is used to determine, if our Ref is for the same RTU as the given Ref. Refs used the first X bytes
// of a SHA256 hash.
//
// By normalizing both byte arrays, to be of same length, we can determine (but not prove)
// that the Refs were created from the same RTU
//
// (if RefV1 is used, there are some small chances that 2 RTUs have the same Ref)
func (r Ref) Equals(other Ref) bool {
	rB := r.Bytes()
	otherB := other.Bytes()
	if len(rB) == 0 || len(otherB) == 0 {
		return false
	}

	if len(rB) > len(otherB) {
		rB = rB[:len(otherB)]
	} else {
		otherB = otherB[:len(rB)]
	}
	if len(rB) == idRefV1Length {
		// one of the refs was RefV1 (make sure to check the last 3 bits of the last byte)
		return bytes.Equal(rB[:idRefV1Length-1], otherB[:idRefV1Length-1]) &&
			rB[idRefV1Length-1]&0b11100000 == otherB[idRefV1Length-1]&0b11100000
	}
	return bytes.Equal(rB, otherB)
}

// RefVersion is an enum used to determine Ref format and version.
type RefVersion int

const (
	// RefUnknown is only returned by Ref.Version in case the Ref is corrupt
	RefUnknown RefVersion = iota - 1
	RefID
	RefV1
	RefV2
)

// decodeRefString is a helper function, decoding the value with refEncoder and returning ErrDecoding
// if there is any errors
func decodeRefString(val string) ([]byte, error) {
	out, err := refEncoder.DecodeString(val)
	if err != nil {
		return nil, ErrDecoding
	}
	return out, nil
}
