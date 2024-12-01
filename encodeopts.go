// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/x509"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/xmidt-org/securly/hash"
)

// EncoderOption is a functional option for the Instructions constructor.
type EncoderOption interface {
	apply(*Encoder) error
}

// WithFileSHA sets the SHA algorithm used for files in the Message.
func WithFileSHA(alg hash.SHA) EncoderOption {
	return shaOption{
		alg: alg,
	}
}

type shaOption struct {
	alg hash.SHA
}

func (s shaOption) apply(enc *Encoder) error {
	enc.shaAlg = &s.alg
	return nil
}

// SignWith sets the signing algorithm, public key, and private key used to sign
// the Message, as well as any intermediaries.
func SignWith(alg jwa.SignatureAlgorithm,
	public *x509.Certificate, private any,
	intermediates ...*x509.Certificate,
) EncoderOption {
	return signAlgOption{
		alg:           alg,
		public:        public,
		key:           private,
		intermediates: intermediates,
	}
}

type signAlgOption struct {
	alg           jwa.SignatureAlgorithm
	public        *x509.Certificate
	key           any
	intermediates []*x509.Certificate
}

func (s signAlgOption) apply(enc *Encoder) error {
	enc.signAlg = s.alg
	enc.leaf = s.public
	enc.key = s.key
	enc.intermediates = s.intermediates
	return nil
}

//------------------------------------------------------------------------------

var safeAlgs = map[jwa.SignatureAlgorithm]struct{}{
	jwa.ES256:  {},
	jwa.ES256K: {},
	jwa.ES384:  {},
	jwa.ES512:  {},
	jwa.EdDSA:  {},
	jwa.PS256:  {},
	jwa.PS384:  {},
	jwa.PS512:  {},
	jwa.RS256:  {},
	jwa.RS384:  {},
	jwa.RS512:  {},
}

func validateSigAlg() EncoderOption {
	return validateSigAlgOption{}
}

type validateSigAlgOption struct{}

func (v validateSigAlgOption) apply(enc *Encoder) error {
	if _, ok := safeAlgs[enc.signAlg]; !ok {
		return fmt.Errorf("%w: unsafe value: %s", ErrInvalidSignAlg, enc.signAlg)
	}

	return nil
}
