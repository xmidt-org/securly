// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/x509"
	"encoding/base64"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

type encoder struct {
	doNotSign         bool
	leaf              *x509.Certificate
	intermediates     []*x509.Certificate
	signAlg           jwa.SignatureAlgorithm
	key               jwk.Key
	skipResponseCheck bool
}

func newEncoder(opts ...EncodeOption) (*encoder, error) {
	enc := encoder{}

	opts = append(opts, validateSigAlg())

	for _, opt := range opts {
		if opt != nil {
			err := opt.apply(&enc)
			if err != nil {
				return nil, err
			}
		}
	}

	return &enc, nil
}

func (enc *encoder) encode(m Message) ([]byte, error) {
	if err := m.Response.safeInTheClear(); err != nil {
		return nil, err
	}

	if !enc.skipResponseCheck {
		if err := m.Response.verify(); err != nil {
			return nil, err
		}
	}

	data, err := m.MarshalMsg(nil)
	if err != nil {
		return nil, err
	}

	var signed []byte
	if enc.doNotSign {
		signed, err = jws.Sign(data, jws.WithInsecureNoSignature())
		if err != nil {
			return nil, err
		}
	} else {
		// Build certificate chain.
		var chain cert.Chain
		for _, cert := range append([]*x509.Certificate{enc.leaf}, enc.intermediates...) {
			err = chain.AddString(base64.URLEncoding.EncodeToString(cert.Raw))
			if err != nil {
				return nil, err
			}
		}

		// Create headers and set x5c with certificate chain.
		headers := jws.NewHeaders()
		err = headers.Set(jws.X509CertChainKey, &chain)
		if err != nil {
			return nil, err
		}

		key := jws.WithKey(enc.signAlg, enc.key, jws.WithProtectedHeaders(headers))

		// Sign the inner payload with the private key.
		signed, err = jws.Sign(data, key)
		if err != nil {
			return nil, err
		}
	}

	return compress(signed)
}
