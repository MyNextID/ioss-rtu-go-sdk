package rtu

import (
	"fmt"
)

type CPK []byte

// Parse tries to parse a public key, based on SignatureAlgorithm
func (c CPK) Parse(algorithm SignatureAlgorithm) (any, error) {
	parser, ok := cpkParserRegistry[algorithm]
	if !ok {
		return nil, fmt.Errorf("unknown signature algorithm: %s", algorithm)
	}
	return parser(c)
}

type CPKParser func(CPK) (any, error)

var cpkParserRegistry = map[SignatureAlgorithm]CPKParser{}

func registerCPKSignatureAlgorithm(signatureAlgorithm SignatureAlgorithm, parser CPKParser) {
	cpkParserRegistry[signatureAlgorithm] = parser
}
