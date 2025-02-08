// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// Option is a functional option for the Instructions constructor.
type DecoderOption interface {
	apply(*Decoder) error
}

type errDecoderOptionFunc func(*Decoder) error

func (f errDecoderOptionFunc) apply(p *Decoder) error {
	return f(p)
}

func decoderOptionFunc(f func(*Decoder)) DecoderOption {
	return errDecoderOptionFunc(func(p *Decoder) error {
		f(p)
		return nil
	})
}

func verifyOptionFunc(opt jws.VerifyOption) DecoderOption {
	return decoderOptionFunc(func(p *Decoder) {
		if opt != nil {
			p.verifyOpts = append(p.verifyOpts, opt)
		}
	})
}

// WithKeyProvider enables using a jws.KeyProvider.  See [jws.WithKeyProvider]
// for more details.
//
// It is likely you will want to use this option with [jwskeychain.Provider]
// package.
func WithKeyProvider(provider jws.KeyProvider) DecoderOption {
	return verifyOptionFunc(jws.WithKeyProvider(provider))
}

// WithKeySet enables using a jwk.Set. See [jws.WithKeySet] for more details.
func WithKeySet(set jwk.Set, options ...jws.WithKeySetSuboption) DecoderOption {
	return verifyOptionFunc(jws.WithKeySet(set, options...))
}

// WithKeyUsed enables using the [jws.WithKeyUsed] option.  See [jws.WithKeyUsed]
// for more details.
func WithKeyUsed(v any) DecoderOption {
	return verifyOptionFunc(jws.WithKeyUsed(v))
}

// WithVerifyAuto enables using the [jws.WithVerifyAuto] option.  See
// [jws.WithVeriftyAuto] for more details.
func WithVerifyAuto(f jwk.Fetcher, options ...jwk.FetchOption) DecoderOption {
	return verifyOptionFunc(jws.WithVerifyAuto(f, options...))
}

// NoVerification does not verify the signature or credentials, but decodes
// the Message.  Generally this is only useful if testing.  DO NOT use this in
// production.  This will intentionally conflict with the TrustedRootCA() option.
func NoVerification() DecoderOption {
	return decoderOptionFunc(func(p *Decoder) {
		p.noVerification = true
	})
}

// ------------------------------------------------------------------------------

func validateRoots() DecoderOption {
	return errDecoderOptionFunc(func(p *Decoder) error {
		if p.noVerification || len(p.verifyOpts) > 0 {
			return nil
		}

		return fmt.Errorf("no valid sources of trust")
	})
}
