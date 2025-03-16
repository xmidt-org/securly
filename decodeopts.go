// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/xmidt-org/jwskeychain"
)

// Option is a functional option for the Instructions constructor.
type DecoderOption interface {
	apply(*decoder) error
}

type decoderOptionFunc func(*decoder) error

func (f decoderOptionFunc) apply(p *decoder) error {
	return f(p)
}

// TrustRootCAs specifies a list of root CAs to trust when verifying the signature.
func TrustRootCAs(certs ...*x509.Certificate) DecoderOption {
	return decoderOptionFunc(func(p *decoder) error {
		p.opts = append(p.opts, jwskeychain.TrustedRoots(certs...))
		return nil
	})
}

// RequirePolicies specifies a list of policies that must be present in the
// signing chain intermediates.
func RequirePolicies(policies ...string) DecoderOption {
	return decoderOptionFunc(func(p *decoder) error {
		p.opts = append(p.opts, jwskeychain.RequirePolicies(policies...))
		return nil
	})
}

// Verifier is an interface that defines a function to verify a certificate chain.
type Verifier interface {
	Verify(ctx context.Context, chain []*x509.Certificate, now time.Time) error
}

// VerifierFunc is a function type that implements the Verifier interface.
type VerifierFunc func(ctx context.Context, chain []*x509.Certificate, now time.Time) error

func (vf VerifierFunc) Verify(ctx context.Context, chain []*x509.Certificate, now time.Time) error {
	return vf(ctx, chain, now)
}

// _ is a compile-time assertion that VerifierFunc implements the Verifier interface.
var _ jwskeychain.Verifier = VerifierFunc(nil)

// Require provides a way to provide a custom verifier for the certificate chain.
func Require(v Verifier) DecoderOption {
	return decoderOptionFunc(func(p *decoder) error {
		p.opts = append(p.opts, jwskeychain.Require(v))
		return nil
	})
}

// NoVerification does not verify the signature or credentials, but decodes
// the Message.  Generally this is only useful if testing.  DO NOT use this in
// production.  This will intentionally conflict with the TrustedRootCA() option.
func NoVerification() DecoderOption {
	return decoderOptionFunc(func(p *decoder) error {
		p.noVerification = true
		return nil
	})
}

// ------------------------------------------------------------------------------

func createTrust() DecoderOption {
	return decoderOptionFunc(func(p *decoder) error {
		trusted, err := jwskeychain.New(p.opts...)
		if err != nil {
			return err
		}
		p.provider = trusted
		return nil
	})
}

func validateRoots() DecoderOption {
	return decoderOptionFunc(func(p *decoder) error {
		if p.noVerification && len(p.provider.Roots()) == 0 {
			return nil
		}
		if !p.noVerification && len(p.provider.Roots()) > 0 {
			return nil
		}

		return fmt.Errorf("no trusted root CAs provided")
	})
}
