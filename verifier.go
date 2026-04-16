package rtu

type Verifier func(pubKey any, payload []byte, signature []byte) (bool, error)

var verifierRegistry = map[SignatureAlgorithm]Verifier{}

func RegisterSignatureAlgorithm(alg SignatureAlgorithm, verifier Verifier, parser CPKParser) {
	verifierRegistry[alg] = verifier
	registerCPKSignatureAlgorithm(alg, parser)
}
