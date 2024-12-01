// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/xmidt-org/securly/hash"
	"github.com/xmidt-org/securly/internal/wire"
)

func validateSignature(JWS string, roots []*x509.Certificate, policies []string) error {
	untrusted, err := jws.Parse([]byte(JWS), jws.WithCompact())
	if err != nil {
		return fmt.Errorf("failed to parse JWS: %w", err)
	}

	sigs := untrusted.Signatures()
	if len(sigs) != 1 {
		return fmt.Errorf("expecting exactly one signer, got %d", len(sigs))
	}

	signer := sigs[0]
	headers := signer.ProtectedHeaders()

	// Get the algorithm
	alg, ok := headers.Get("alg")
	if !ok {
		return fmt.Errorf("alg header is missing")
	}

	// Get the x5c header
	chain, ok := headers.Get("x5c")
	if !ok || chain == nil {
		return fmt.Errorf("x5c header is missing or invalid")
	}

	// Validate the cert chain and get the leaf node.
	leaf, err := validateCertChain(roots, chain.(*cert.Chain), policies)
	if err != nil {
		return err
	}

	// Decode the first certificate in the x5c header
	certData, err := base64.URLEncoding.DecodeString(string(leaf))
	if err != nil {
		return fmt.Errorf("failed to decode x5c certificate: %w", err)
	}

	// Parse the certificate to get the public key
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return fmt.Errorf("failed to parse x5c certificate: %w", err)
	}

	_, err = jws.Verify([]byte(JWS),
		jws.WithKey(alg.(jwa.KeyAlgorithm), cert.PublicKey).(jws.VerifyOption))
	if err != nil {
		return fmt.Errorf("failed to verify JWS: %w", err)
	}

	return nil
}

func validateFiles(outer wire.Outer, inner wire.Inner) error {
	for fn, val := range outer.Files {
		expect, ok := inner.SHAs[fn]
		if !ok {
			return fmt.Errorf("missing SHA for %s", fn)
		}

		sha := hash.Canonical(expect.Alg)
		if sha == nil {
			return fmt.Errorf("unsupported SHA algorithm %s", expect.Alg)
		}

		if !sha.Validate(expect.Value, val) {
			return fmt.Errorf("invalid SHA for %s", fn)
		}
	}

	return nil
}
