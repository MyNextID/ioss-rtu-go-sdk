package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"time"

	rtu "github.com/MyNextID/ioss-rtu-go-sdk"
)

func main() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	priv, err := rtu.NewECPrivateKey(key)
	if err != nil {
		panic(err)
	}

	out := signASN(priv)

	fmt.Println(out)
}

// change signASN with this function, to get a JWS Compact RTU with a 'jwk' header
func signJWTWithJWK(priv rtu.PrivateKey) rtu.PackedRTU {
	key, err := rtu.AddJWKToPrivateKey(priv)
	if err != nil {
		panic(err)
	}
	return signJWT(key)
}

// change signASN with this function, to get a JWS Compact RTU with a 'cpk' header
func signJWT(priv rtu.PrivateKey) rtu.PackedRTU {
	out, err := rtu.Sign(rtu.NewVersion1JWT("tx-id-001", time.Now().Add(time.Hour), false), priv)
	if err != nil {
		panic(err)
	}
	return out
}

// the QR code ready encoding for RTUs (ASN1 encoded RTU)
func signASN(priv rtu.PrivateKey) rtu.PackedRTU {
	out, err := rtu.Sign(rtu.NewVersion1ASN("tx-id-001", time.Now().Add(time.Hour), false), priv)
	if err != nil {
		panic(err)
	}
	return out
}
