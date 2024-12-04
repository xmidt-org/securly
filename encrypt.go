// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type encrypter struct {
	alg jwa.KeyEncryptionAlgorithm
	key jwk.Key
}

// newDecoder converts a slice of bytes plus options into a Message.
func newEncrypter(opts ...EncryptOption) (*encrypter, error) {
	var rv encrypter

	opts = append(opts, validateEncrypt())

	for _, opt := range opts {
		if opt != nil {
			err := opt.apply(&rv)
			if err != nil {
				return nil, err
			}
		}
	}

	return &rv, nil
}

func (enc *encrypter) encrypt(m Message) ([]byte, error) {
	switch {
	case m.Response == nil:
	case m.Response.Alg == "" && m.Response.Key == nil:
	case m.Response.Alg != "" && m.Response.Key != nil:
	default:
		return nil, ErrInvalidEncryptionAlg
	}

	// Default to what is set in the encryptor.
	alg := enc.alg
	key := enc.key

	if key == nil {
		if m.Response == nil || m.Response.Key == nil {
			return nil, ErrInvalidEncryptionAlg
		}

		alg = m.Response.Alg
		key = m.Response.Key
	}

	// If the EncryptWith option was not set, there is no additional response,
	// so we should not send the encryption instructions over the wire.
	if enc.alg == "" {
		m.Response = nil
	}
	payload, err := m.toWire()
	if err != nil {
		return nil, err
	}

	return sanitize(jwe.Encrypt(payload, jwe.WithKey(alg, key)))
}
