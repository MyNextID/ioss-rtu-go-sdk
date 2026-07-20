package helpers

import (
	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

type rtuType struct {
	f rtu.Format
	v rtu.Version
}

func GetRTUType(f rtu.Format, v rtu.Version) rtu.Type {
	return rtuType{f: f, v: v}
}

func (r rtuType) Format() rtu.Format {
	return r.f
}

func (r rtuType) Version() rtu.Version {
	return r.v
}

func GetASN1Type() rtu.Type {
	return GetRTUType(rtu.ASN1, rtu.Version1)
}

func GetJWTType() rtu.Type {
	return GetRTUType(rtu.JWT, rtu.Version1)
}
