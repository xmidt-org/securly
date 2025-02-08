// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"github.com/lestrrat-go/jwx/v2/jws"
)

// Decode converts a slice of bytes into a *Message if possible.  Depending on
// the options provided, the function may also verify the signature of the
// message.
//
// This function defaults secure, so it will verify the signature of the
// message.  If you want to skip this verification, you can pass the
// NoVerification() option.
func Decode(buf []byte, opts ...DecoderOption) (*Message, error) {
	p, err := NewDecoder(opts...)
	if err != nil {
		return nil, err
	}

	return p.Decode(buf)
}

// Decoder contains the configuration for decoding a set of messages.
type Decoder struct {
	noVerification bool
	verifyOpts     []jws.VerifyOption
}

// NewDecoder converts a slice of bytes plus options into a Message.
func NewDecoder(opts ...DecoderOption) (*Decoder, error) {
	var p Decoder

	vadors := []DecoderOption{
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

// Decode converts a slice of bytes into a *Message if possible.
func (p *Decoder) Decode(buf []byte) (*Message, error) {
	JWS, err := decompress(buf)
	if err != nil {
		return nil, err
	}

	var payload []byte

	// Verify the JWS signature if possible.
	if p.noVerification {
		var trusted *jws.Message
		if trusted, err = jws.Parse(JWS, jws.WithCompact()); err == nil {
			payload = trusted.Payload()
		}
	} else {
		payload, err = jws.Verify(JWS, p.verifyOpts...)
	}
	if err != nil {
		return nil, err
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
