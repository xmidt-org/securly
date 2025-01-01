// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/x509"
	"fmt"

	"github.com/xmidt-org/keychainjwt"
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
	p.opts = append(p.opts, keychainjwt.TrustedRoots(t.certs...))
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
	p.opts = append(p.opts, keychainjwt.RequirePolicies(r.policies...))
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

// ------------------------------------------------------------------------------
func createTrust() DecoderOption {
	return createTrustOption{}
}

type createTrustOption struct{}

func (c createTrustOption) apply(p *decoder) error {
	trusted, err := keychainjwt.New(p.opts...)
	if err == nil {
		p.trusted = trusted
	}
	return err
}

func validateRoots() DecoderOption {
	return validateRootsOption{}
}

type validateRootsOption struct{}

func (v validateRootsOption) apply(p *decoder) error {
	if p.noVerification || len(p.trusted.Roots()) > 0 {
		return nil
	}

	return fmt.Errorf("no trusted root CAs provided")
}
