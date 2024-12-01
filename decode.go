// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/x509"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/xmidt-org/securly/internal/wire"
)

// Decoder contains the configuration for decoding a set of messages.
type Decoder struct {
	noVerification bool
	trustedRootCAs []*x509.Certificate
	policies       []string
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
	// Unmarshal the outer payload
	var outer wire.Outer
	left, err := outer.UnmarshalMsg(buf)
	if err != nil {
		return nil, err
	}
	if len(left) != 0 {
		return nil, fmt.Errorf("%w leftover bytes", ErrInvalidPayload)
	}

	untrusted, err := jws.Parse([]byte(outer.JWS), jws.WithCompact())
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %w", err)
	}

	// Verify the JWS signature if possible.
	payload := untrusted.Payload()
	if !p.noVerification {
		err = validateSignature(outer.JWS, p.trustedRootCAs, p.policies)
		if err != nil {
			return nil, err
		}
	}

	// Unmarshal the inner payload
	var inner wire.Inner
	_, err = inner.UnmarshalMsg(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal inner payload: %w", err)
	}

	// Verify the file hashes.
	err = validateFiles(outer, inner)
	if err != nil {
		return nil, err
	}

	// Create the Message
	msg := Message{
		Payload: inner.Payload,
		Files:   outer.Files,
	}

	if inner.Encrypt != nil {
		alg, err := convertAlg(inner.Encrypt.Alg)
		if err != nil {
			return nil, err
		}

		msg.Response = &Encrypt{
			Alg: alg,
			Key: inner.Encrypt.Key,
		}
	}

	return &msg, nil
}

// DecodeEncrypted converts a byte slice into a *Message and decodes
// it it using the provided key.
func DecodeEncrypted(buf []byte, key string) (*Message, error) {
	// Parse the JWE to extract the header
	msg, err := jwe.Parse(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWE: %w", err)
	}

	// Extract the algorithm from the JWE header
	alg, ok := msg.ProtectedHeaders().Get(jwe.AlgorithmKey)
	if !ok {
		return nil, fmt.Errorf("algorithm not found in JWE header")
	}

	// Parse the JWK key
	jwkKey, err := jwk.ParseKey([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK key: %w", err)
	}

	// Decrypt the JWE
	decrypted, err := jwe.Decrypt(buf, jwe.WithKey(alg.(jwa.KeyEncryptionAlgorithm), jwkKey))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt JWE: %w", err)
	}

	// Unmarshal the decrypted payload into wire.Encrypted
	var encrypted wire.Encrypted
	left, err := encrypted.UnmarshalMsg(decrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypted payload: %w", err)
	}
	if len(left) != 0 {
		return nil, fmt.Errorf("%w leftover bytes", ErrInvalidPayload)
	}

	// Unmarshal the inner payload
	var inner wire.Inner
	_, err = inner.UnmarshalMsg(encrypted.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal inner payload: %w", err)
	}

	// Create the Message
	rv := Message{
		Payload: encrypted.Payload,
		Files:   encrypted.Files,
	}

	if encrypted.Encrypt != nil {
		alg, err := convertAlg(encrypted.Encrypt.Alg)
		if err != nil {
			return nil, err
		}

		rv.Response = &Encrypt{
			Alg: alg,
			Key: inner.Encrypt.Key,
		}
	}

	return &rv, nil
}

func convertAlg(alg string) (jwa.KeyEncryptionAlgorithm, error) {
	list := jwa.KeyEncryptionAlgorithms()

	for _, v := range list {
		// Skip symmetric algorithms.
		if v.IsSymmetric() {
			continue
		}

		if v.String() == alg {
			return v, nil
		}
	}

	return "", ErrInvalidEncryptionAlg
}
