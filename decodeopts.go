// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/x509"
	"fmt"
)

// Option is a functional option for the Instructions constructor.
type DecoderOption interface {
	apply(*decoder) error
}

// TrustRootCAs specifies a list of root CAs to trust when verifying the signature.
func TrustRootCAs(certs ...*x509.Certificate) DecoderOption {
	return trustRootCAOption{
		certs: certs,
	}
}

type trustRootCAOption struct {
	certs []*x509.Certificate
}

func (t trustRootCAOption) apply(p *decoder) error {
	p.trustedRootCAs = append(p.trustedRootCAs, t.certs...)
	return nil
}

// RequirePolicies specifies a list of policies that must be present in the
// signing chain intermediates.
func RequirePolicies(policies ...string) DecoderOption {
	return requirePoliciesOption{
		policies: policies,
	}
}

type requirePoliciesOption struct {
	policies []string
}

func (r requirePoliciesOption) apply(p *decoder) error {
	p.policies = append(p.policies, r.policies...)
	return nil
}

// NoVerification does not verify the signature or credentials, but decodes
// the Message.  Generally this is only useful if testing.  DO NOT use this in
// production.  This will intentionally conflict with the TrustedRootCA() option.
func NoVerification() DecoderOption {
	return withoutVerificationOption{}
}

type withoutVerificationOption struct{}

func (withoutVerificationOption) apply(p *decoder) error {
	p.noVerification = true
	return nil
}

//------------------------------------------------------------------------------

func validateRoots() DecoderOption {
	return validateRootsOption{}
}

type validateRootsOption struct{}

func (v validateRootsOption) apply(p *decoder) error {
	if len(p.trustedRootCAs) == 0 && !p.noVerification {
		return fmt.Errorf("no trusted root CAs provided")
	}

	return nil
}
