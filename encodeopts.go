// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/x509"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// EncodeOption is a functional option for the Instructions constructor.
type EncodeOption interface {
	apply(*encoder) error
}

// SignWith sets the signing algorithm, public key, and private key used to sign
// the Message, as well as any intermediaries.
//
// The following combinations are valid (the public/private keys must match):
// - ES256, private: *ecdsa.PrivateKey
// - ES384, private: *ecdsa.PrivateKey
// - ES512, private: *ecdsa.PrivateKey
// - RS256, private: *rsa.PrivateKey
// - RS384, private: *rsa.PrivateKey
// - RS512, private: *rsa.PrivateKey
// - PS256, private: *rsa.PrivateKey
// - PS384, private: *rsa.PrivateKey
// - PS512, private: *rsa.PrivateKey
// - EdDSA, private: ed25519.PrivateKey
//
// Unfortunately, to make this work the private type needs to be an interface{}.
func SignWith(alg jwa.SignatureAlgorithm,
	public *x509.Certificate, private jwk.Key,
	intermediates ...*x509.Certificate,
) EncodeOption {
	return signAlgOption{
		alg:           alg,
		public:        public,
		key:           private,
		intermediates: intermediates,
	}
}

func SignWithRaw(alg jwa.SignatureAlgorithm,
	public *x509.Certificate, private any,
	intermediates ...*x509.Certificate,
) EncodeOption {
	key, err := jwk.FromRaw(private)
	if err != nil {
		return errorEncode(err)
	}

	return SignWith(alg, public, key, intermediates...)
}

type signAlgOption struct {
	alg           jwa.SignatureAlgorithm
	public        *x509.Certificate
	key           jwk.Key
	intermediates []*x509.Certificate
}

func (s signAlgOption) apply(enc *encoder) error {
	if s.alg.IsSymmetric() || s.alg == jwa.NoSignature {
		return ErrInvalidSignAlg
	}

	enc.signAlg = s.alg
	enc.leaf = s.public
	enc.key = s.key
	enc.intermediates = s.intermediates
	return nil
}

// NoSignature indicates that the Message should not be signed.  It cannot be used
// with any SignWith options or an error will be returned.  This is to ensure that
// the caller is aware that the Message will not be signed.
func NoSignature() EncodeOption {
	return noSignatureOption{}
}

type noSignatureOption struct{}

func (n noSignatureOption) apply(enc *encoder) error {
	enc.doNotSign = true
	return nil
}

//------------------------------------------------------------------------------

func errorEncode(err error) EncodeOption {
	return errorEncodeOption{
		err: err,
	}
}

type errorEncodeOption struct {
	err error
}

func (e errorEncodeOption) apply(*encoder) error {
	return e.err
}

func validateSigAlg() EncodeOption {
	return validateSigAlgOption{}
}

type validateSigAlgOption struct{}

func (v validateSigAlgOption) apply(enc *encoder) error {
	if enc.doNotSign {
		if enc.signAlg != "" ||
			enc.leaf != nil ||
			enc.key != nil ||
			len(enc.intermediates) > 0 {
			return fmt.Errorf("%w: NoSignature() must be used in isolation", ErrInvalidSignAlg)
		}
		return nil
	}

	if enc.signAlg == "" || enc.key == nil {
		return fmt.Errorf("%w: algorithm and key are required", ErrInvalidSignAlg)
	}

	return nil
}
