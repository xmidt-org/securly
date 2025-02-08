// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/x509"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/xmidt-org/jwskeychain"
)

// SignOption is a functional option for the Instructions constructor.
type SignOption interface {
	apply(*Signer) error
}

type errSignOptionFunc func(*Signer) error

func (f errSignOptionFunc) apply(enc *Signer) error {
	return f(enc)
}

func signOptionFunc(f func(*Signer)) SignOption {
	return errSignOptionFunc(func(enc *Signer) error {
		f(enc)
		return nil
	})
}

// SignWithX509Chain sets the signing algorithm, public key, and private key
// used to sign the Message, as well as any intermediaries.  See
// [jwskeychain.Signer] for more details.
func SignWithX509Chain(alg jwa.SignatureAlgorithm, private any, certs []*x509.Certificate) SignOption {
	return errSignOptionFunc(func(enc *Signer) error {
		key, err := jwskeychain.Signer(alg, private, certs)
		if err != nil {
			return err
		}

		enc.key = key
		return nil
	})
}

// SignWithKey creates a signing key for the Message.  See [jws.WithKey] for more
// details about how to use this option.
func SignWithKey(alg jwa.SignatureAlgorithm, key any, opts ...jws.WithKeySuboption) SignOption {
	return signOptionFunc(func(enc *Signer) {
		enc.key = jws.WithKey(alg, key, opts...)
	})
}

// NoSignature indicates that the Message should not be signed.  It cannot be used
// with any SignWith options or an error will be returned.  This is to ensure that
// the caller is aware that the Message will not be signed.
func NoSignature() SignOption {
	return signOptionFunc(func(enc *Signer) {
		enc.doNotSign = true
	})
}

//------------------------------------------------------------------------------

func validateSigAlg() SignOption {
	return errSignOptionFunc(func(enc *Signer) error {
		if enc.doNotSign {
			if enc.key != nil {
				return fmt.Errorf("%w: NoSignature() must be used in isolation", ErrInvalidSignAlg)
			}
			return nil
		}

		if enc.key == nil {
			return fmt.Errorf("%w: key is required", ErrInvalidSignAlg)
		}

		return nil
	})
}
