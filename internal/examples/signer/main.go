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

	out := signJWTWithJWK(priv)

	fmt.Println(out)
}

func signJWTWithJWK(priv rtu.PrivateKey) rtu.PackedRTU {
	key, err := rtu.AddJWKToPrivateKey(priv)
	if err != nil {
		panic(err)
	}
	return signJWT(key)
}

func signJWT(priv rtu.PrivateKey) rtu.PackedRTU {
	out, err := rtu.Sign(rtu.NewVersion1JWT("tx-id-001", time.Now().Add(time.Hour), false), priv)
	if err != nil {
		panic(err)
	}
	return out
}

func signASN(priv rtu.PrivateKey) rtu.PackedRTU {
	out, err := rtu.Sign(rtu.NewVersion1ASN("tx-id-001", time.Now().Add(time.Hour), false), priv)
	if err != nil {
		panic(err)
	}
	return out
}
