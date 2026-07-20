package rtu

func Verify(obj PackedRTU, opts ...VerifyOption) (Payload, PublicKey, error) {
	val, err := obj.Parse()
	if err != nil {
		return nil, nil, err
	}
	noValidation := hasVerifyOption[*ignoreValidation](opts)
	if !noValidation {
		if err = ValidateRTU(val); err != nil {
			return nil, nil, err
		}
	}
	payload, pub, err := val.Parse()
	if err != nil {
		return nil, nil, err
	}
	if !noValidation {
		if err = ValidatePayload(payload); err != nil {
			return nil, nil, err
		}
	}
	if !hasVerifyOption[*noSignatureVerification](opts) {
		if err = pub.Verify(val, val.Payload(), val.Signature()); err != nil {
			return nil, nil, err
		}
	}
	return payload, pub, nil
}

type VerifyOption interface {
	optArgs() any
}

type ignoreValidation struct{}

func (*ignoreValidation) optArgs() any { return nil }

func WithIgnoreValidation() VerifyOption {
	return &ignoreValidation{}
}

type noSignatureVerification struct{}

func (*noSignatureVerification) optArgs() any { return nil }

func WithNoSignatureVerification() VerifyOption {
	return &noSignatureVerification{}
}

func hasVerifyOption[T any](opts []VerifyOption) bool {
	return getVerifyOption[T](opts) != nil
}

func getVerifyOption[T any](opts []VerifyOption) VerifyOption {
	for _, opt := range opts {
		if _, ok := opt.(T); ok {
			return opt
		}
	}
	return nil
}
