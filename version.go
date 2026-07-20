package rtu

import (
	"fmt"
)

// Version is an integer (should be uint32, but int32 is used for asn1), that defines
// the schema for a given RTU. It is used by the RTU to parse its payload to return
// the common Payload structure.
type Version int32

const (
	VersionNone Version = iota
	Version1
)

func (v Version) Validate() error {
	switch v {
	case VersionNone:
		return ErrNoVersion
	case Version1:
		return nil
	default:
		return fmt.Errorf("%w: %d", ErrUnknownVersion, v)
	}
}

// DefaultSignatureAlgorithm returns the default signature algorithm for this version
// if AlgorithmNone is returned, it means either the version does not exist and/or
// there is no default for that version. Please use other methods, to validate if
// version exists
func (v Version) DefaultSignatureAlgorithm() SignatureAlgorithm {
	switch v {
	case Version1:
		return AlgorithmEcdsaP256
	default:
		return AlgorithmNone
	}
}
