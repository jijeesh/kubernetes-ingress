// +build aws

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"math/rand"

	"github.com/golang/glog"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/marketplacemetering"
	"github.com/aws/aws-sdk-go-v2/service/marketplacemetering/types"

	"github.com/dgrijalva/jwt-go/v4"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
	productCode   string
	pubKeyVersion int32 = 1
	pubKeyString  string
	nonce         string
)

func init() {
	rand.Seed(jwt.Now().UnixNano())
	nonce = RandStringBytesRmndr(20)

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		glog.Fatalf("Error loading AWS configuration: %v", err)
	}

	svc := marketplacemetering.New(marketplacemetering.Options{Region: cfg.Region, Credentials: cfg.Credentials})

	var notEnt *types.CustomerNotEntitledException
	var invalidRegion *types.InvalidRegionException

	out, err := svc.RegisterUsage(context.TODO(), &marketplacemetering.RegisterUsageInput{ProductCode: &productCode, PublicKeyVersion: &pubKeyVersion, Nonce: &nonce})
	if err != nil {
		if errors.As(err, &notEnt) {
			glog.Fatalf("Not entitled: %v", err)
		} else if errors.As(err, &invalidRegion) {
			glog.Fatalf("Invalid region: %v", err)
		}
		glog.Fatal(err)

	}

	pk, err := base64.StdEncoding.DecodeString(pubKeyString)
	if err != nil {
		glog.Fatal(err)
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pk)
	if err != nil {
		glog.Fatal(err)
	}

	token, err := jwt.ParseWithClaims(*out.Signature, &Claims{}, jwt.KnownKeyfunc(jwt.SigningMethodPS256, pubKey))
	if err != nil {
		glog.Fatal(err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		if claims.ProductCode == productCode && claims.PublicKeyVersion == pubKeyVersion && claims.Nonce == nonce {
			glog.Info("verification successful")
		}
	} else {
		glog.Fatal(err)
	}
}

type Claims struct {
	ProductCode      string    `json:"productCode,omitempty"`
	PublicKeyVersion int32     `json:"publicKeyVersion,omitempty"`
	IssuedAt         *jwt.Time `json:"iat,omitempty"`
	Nonce            string    `json:"nonce,omitempty"`
}

func (c Claims) Valid(h *jwt.ValidationHelper) error {
	if c.Nonce == "" {
		return &jwt.InvalidClaimsError{Message: "can't find nonce"}
	}
	if c.ProductCode == "" {
		return &jwt.InvalidClaimsError{Message: "can't find product code"}
	}
	if int32(c.IssuedAt.Hour()) == 0 {
		return &jwt.InvalidClaimsError{Message: "can't find key version"}
	}
	if h.Before(c.IssuedAt.Time) {
		return &jwt.InvalidClaimsError{Message: "time is wrong"}
	}

	return nil
}

func RandStringBytesRmndr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}
