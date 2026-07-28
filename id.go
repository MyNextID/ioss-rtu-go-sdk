package rtu

import (
	"crypto/sha256"
	"fmt"
)

type ID []byte

const (
	// idLength is the length of the full ID (32 bytes of SHA256)
	idLength = 32
	// idRefV1Length is the required byte length of ID for RefV1
	idRefV1Length = 10
	// idRefV2Length is the required byte length of ID for RefV2
	idRefV2Length = 20
)

// NewID generates the ID of an RTU (sha256 hash of its Payload)
func NewID(rtu RTU) ID {
	h := sha256.New()
	h.Write(rtu.Payload())
	return h.Sum(nil)
}

// AsRef transforms the ID into a Ref, based on the given RefVersion.
// it returns error if amount of bytes in the ID is not enough to fill the data for the Ref
// or if the RefVersion is unknown
func (i ID) AsRef(version RefVersion) (Ref, error) {
	switch version {
	case RefID:
		if len(i) < idLength {
			return "", ErrInvalidIDLength
		}
		return newRefID(i), nil
	case RefV1:
		if len(i) < idRefV1Length {
			return "", ErrInvalidIDLength
		}
		return newRefV1(i), nil
	case RefV2:
		if len(i) < idRefV2Length {
			return "", ErrInvalidIDLength
		}
		return newRefV2(i), nil
	default:
		return "", fmt.Errorf("%w: %d", ErrUnknownRefVersion, version)
	}
}
