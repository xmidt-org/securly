// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/x509"
	"fmt"
)

// Option is a functional option for the Instructions constructor.
type DecoderOption interface {
	apply(*Decoder) error
}

// TrustedRootCA specifies a root CA to trust when verifying the signature.
func TrustRootCA(certs *x509.Certificate) DecoderOption {
	return trustRootCAOption{
		certs: []*x509.Certificate{certs},
	}
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

func (t trustRootCAOption) apply(p *Decoder) error {
	p.trustedRootCAs = append(p.trustedRootCAs, t.certs...)
	return nil
}

// RequirePolicy specifies a policy that must be present in the signing chain
// intermediates.
func RequirePolicy(policy string) DecoderOption {
	return requirePoliciesOption{
		policies: []string{policy},
	}
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

func (r requirePoliciesOption) apply(p *Decoder) error {
	p.policies = append(p.policies, r.policies...)
	return nil
}

// WithoutVerification does not verify the signature or credentials, but decodes
// the Message.  Generally this is only useful if testing.  DO NOT use this in
// production.  This will intentionally conflict with the TrustedRootCA() option.
func WithoutVerification() DecoderOption {
	return withoutVerificationOption{}
}

type withoutVerificationOption struct{}

func (withoutVerificationOption) apply(p *Decoder) error {
	p.noVerification = true
	return nil
}

//------------------------------------------------------------------------------

func validateRoots() DecoderOption {
	return validateRootsOption{}
}

type validateRootsOption struct{}

func (v validateRootsOption) apply(p *Decoder) error {
	if len(p.trustedRootCAs) == 0 && !p.noVerification {
		return fmt.Errorf("no trusted root CAs provided")
	}

	return nil
}
