// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/x509"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/xmidt-org/jwskeychain/keychaintest"
)

var errUnknown = fmt.Errorf("unknown error")

var chainA = mustGeneratecertChain(
	`leaf
		<-ica(1.2.900,1.2.901)
		<-ica(1.2.100)
		<-root`)

var chainB = mustGeneratecertChain(
	`leaf
		<-ica(1.2.900,1.2.901)
		<-ica(1.2.100)
		<-root`)

func mustGeneratecertChain(desc string) keychaintest.Chain {
	chain, err := keychaintest.New(keychaintest.Desc(desc))
	if err != nil {
		panic(err)
	}

	return chain
}

func mustGenerateResponse(alg jwa.KeyEncryptionAlgorithm, c *x509.Certificate) *Encryption {
	rv := Encryption{
		Alg: alg,
		Key: mustFromRaw(c.PublicKey),
	}

	return &rv
}

func mustFromRaw(a any) jwk.Key {
	k, err := jwk.FromRaw(a)
	if err != nil {
		panic(err)
	}
	return k
}
