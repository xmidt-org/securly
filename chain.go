// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/cert"
)

func validateCertChain(roots []*x509.Certificate, chain *cert.Chain, policies []string) (string, error) {
	// Decode the certificate chain
	var certChain []*x509.Certificate
	var leaf string

	for i := 0; i < chain.Len(); i++ {
		certStr, ok := chain.Get(i)
		if !ok {
			return "", fmt.Errorf("failed to get certificate from chain")
		}

		// The 0th index in the cert chain is the leaf.
		if i == 0 {
			leaf = string(certStr)
		}

		certData, err := base64.URLEncoding.DecodeString(string(certStr))
		if err != nil {
			return "", fmt.Errorf("failed to decode certificate: %w", err)
		}
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return "", fmt.Errorf("failed to parse certificate: %w", err)
		}
		certChain = append(certChain, cert)
	}

	// Verify the certificate chain against the trusted roots
	intermediates := x509.NewCertPool()
	for _, cert := range certChain[1:] {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: intermediates,
	}

	for _, root := range roots {
		opts.Roots.AddCert(root)
	}

	leafCert := certChain[0]
	if _, err := leafCert.Verify(opts); err != nil {
		return "", fmt.Errorf("certificate verification failed: %w", err)
	}

	// Check that at least one certificate in the chain contains all the required policies
	requiredPolicies := make(map[string]bool, len(policies))
	for _, policy := range policies {
		requiredPolicies[policy] = false
	}

	for _, cert := range certChain {
		for _, policy := range cert.PolicyIdentifiers {
			if _, ok := requiredPolicies[policy.String()]; ok {
				requiredPolicies[policy.String()] = true
			}
		}
	}

	for policy, found := range requiredPolicies {
		if !found {
			return "", fmt.Errorf("required policy %s not found in certificate chain", policy)
		}
	}

	return leaf, nil
}
