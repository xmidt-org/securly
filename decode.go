// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/xmidt-org/keychainjwt"
)

// Decode converts a slice of bytes into a *Message if possible.  Depending on
// the options provided, the function may also verify the signature of the
// message.
//
// This function defaults secure, so it will verify the signature of the
// message.  If you want to skip this verification, you can pass the
// NoVerification() option.
func Decode(buf []byte, opts ...DecoderOption) (*Message, error) {
	p, err := newDecoder(opts...)
	if err != nil {
		return nil, err
	}

	return p.decode(buf)
}

// decoder contains the configuration for decoding a set of messages.
type decoder struct {
	noVerification bool
	opts           []keychainjwt.Option
	trusted        *keychainjwt.Trust
}

// newDecoder converts a slice of bytes plus options into a Message.
func newDecoder(opts ...DecoderOption) (*decoder, error) {
	var p decoder

	vadors := []DecoderOption{
		createTrust(),
		validateRoots(),
	}

	opts = append(opts, vadors...)

	for _, opt := range opts {
		err := opt.apply(&p)
		if err != nil {
			return nil, err
		}
	}

	return &p, nil
}

// decode converts a slice of bytes into a *Message if possible.
func (p *decoder) decode(buf []byte) (*Message, error) {
	JWS, err := decompress(buf)
	if err != nil {
		return nil, err
	}

	var payload []byte

	// Verify the JWS signature if possible.
	if p.noVerification {
		trusted, err := jws.Parse(JWS, jws.WithCompact())
		if err != nil {
			return nil, err
		}
		payload = trusted.Payload()
	} else {
		alg, key, err := p.trusted.GetKey(JWS)
		if err != nil {
			return nil, err
		}

		payload, err = jws.Verify(JWS, jws.WithKey(jwa.SignatureAlgorithm(alg), key))
		if err != nil {
			return nil, err
		}
	}

	// Unmarshal the inner payload
	var msg Message
	if _, err = msg.UnmarshalMsg(payload); err != nil {
		return nil, err
	}

	// The encryption algorithm must be safe to send in the clear, or this
	// message is invalid.
	if err := msg.Response.safeInTheClear(); err != nil {
		return nil, err
	}

	return &msg, nil
}
