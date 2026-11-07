// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/xmidt-org/jwskeychain/keychaintest"
)

var errUnknown = errors.New("unknown error")

// chainA and chainB are leaf <- ica(1.2.900, 1.2.901) <- ica(1.2.100) <- root.
//
// keychaintest sets x509.Certificate.PolicyIdentifiers, which Go 1.24+ ignores
// when creating certificates (GODEBUG x509usepolicies=1), so the chains are
// generated here using x509.Certificate.Policies instead.
var (
	chainA = mustGenerateCertChain([]string{"1.2.900", "1.2.901"}, []string{"1.2.100"})
	chainB = mustGenerateCertChain([]string{"1.2.900", "1.2.901"}, []string{"1.2.100"})
)

// mustGenerateCertChain creates a chain of a root, one intermediate CA for each
// policy list (listed from the leaf's issuer up to the root's child) and a leaf.
func mustGenerateCertChain(policies ...[]string) keychaintest.Chain {
	// Chain order is leaf first, root last.
	nodes := make([]keychaintest.Node, len(policies)+2)

	var parent keychaintest.Node

	for i := len(nodes) - 1; i >= 0; i-- {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}

		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 1)),
			Subject:               pkix.Name{Organization: []string{"Intermediate"}},
			NotBefore:             time.Now().Add(-time.Minute),
			NotAfter:              time.Now().AddDate(1, 0, 0),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			IsCA:                  true,
			BasicConstraintsValid: true,
		}

		switch i {
		case len(nodes) - 1:
			tmpl.Subject = pkix.Name{Organization: []string{"Root"}}
		case 0:
			tmpl.Subject = pkix.Name{Organization: []string{"Leaf"}}
			tmpl.KeyUsage = x509.KeyUsageDigitalSignature
			tmpl.IsCA = false
		default:
			for _, p := range policies[i-1] {
				oid, err := x509.ParseOID(p)
				if err != nil {
					panic(err)
				}

				tmpl.Policies = append(tmpl.Policies, oid)
			}
		}

		signer, signerKey := tmpl, priv
		if parent.Public != nil {
			signer, signerKey = parent.Public, parent.Private
		}

		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &priv.PublicKey, signerKey)
		if err != nil {
			panic(err)
		}

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			panic(err)
		}

		nodes[i] = keychaintest.Node{Public: cert, Private: priv}
		parent = nodes[i]
	}

	return nodes
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
