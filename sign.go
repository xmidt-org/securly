// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"github.com/lestrrat-go/jwx/v2/jws"
)

// Signer is a type that can encode & sign a Message.
type Signer struct {
	doNotSign         bool
	key               jws.SignVerifyOption
	skipResponseCheck bool
}

// NewSigner creates a new Signer with the given options.
func NewSigner(opts ...SignOption) (*Signer, error) {
	enc := Signer{}

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

// Encode encodes the given Message and signs it.
func (enc *Signer) Encode(m Message) ([]byte, error) {
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
		// Sign the inner payload with the private key.
		signed, err = jws.Sign(data, enc.key)
		if err != nil {
			return nil, err
		}
	}

	return compress(signed)
}
