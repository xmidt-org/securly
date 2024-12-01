// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/xmidt-org/securly/hash"
	"github.com/xmidt-org/securly/internal/wire"
)

type Encoder struct {
	shaAlg        *hash.SHA
	leaf          *x509.Certificate
	intermediates []*x509.Certificate
	signAlg       jwa.SignatureAlgorithm
	key           any
}

func NewEncoder(opts ...EncoderOption) (*Encoder, error) {
	enc := Encoder{}

	defaults := []EncoderOption{
		WithFileSHA(hash.SHA256),
	}

	vadors := []EncoderOption{
		validateSigAlg(),
	}

	opts = append(defaults, opts...)
	opts = append(opts, vadors...)

	for _, opt := range opts {
		err := opt.apply(&enc)
		if err != nil {
			return nil, err
		}
	}

	return &enc, nil
}

func (enc *Encoder) Encode(m *Message) ([]byte, error) {
	// Assemble the inner payload first.
	inner := wire.Inner{
		Payload: m.Payload,
		SHAs:    make(map[string]wire.SHA, len(m.Files)),
	}

	if m.Response != nil {
		if m.Response.Alg == "" || m.Response.Alg.IsSymmetric() {
			return nil, ErrInvalidEncryptionAlg
		}

		// Verify that the key is valid for the algorithm.
		err := verifyEncryptionKey(m.Response.Alg, m.Response.Key)
		if err != nil {
			return nil, fmt.Errorf("invalid encryption key: %w", err)
		}

		inner.Encrypt = &wire.Response{
			Alg: m.Response.Alg.String(),
			Key: m.Response.Key,
		}
	}

	for filename, filedata := range m.Files {
		inner.SHAs[filename] = wire.SHA{
			Alg:   enc.shaAlg.String(),
			Value: enc.shaAlg.Sum(filedata),
		}
	}

	innerBytes, err := inner.MarshalMsg(nil)
	if err != nil {
		return nil, err
	}

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

	// Sign the inner payload with the private key.
	signed, err := jws.Sign(innerBytes, jws.WithKey(enc.signAlg, enc.key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return nil, err
	}

	// Assemble the outer payload.
	outer := wire.Outer{
		JWS:   string(signed),
		Files: m.Files,
	}

	rv, err := outer.MarshalMsg(nil)
	if err != nil {
		return nil, err
	}

	return rv, nil
}

// verifyEncryptionKey verifies that the key is valid for the specified encryption algorithm.
func verifyEncryptionKey(alg jwa.KeyEncryptionAlgorithm, key string) error {
	// Parse the JWK key
	jwkKey, err := jwk.ParseKey([]byte(key))
	if err != nil {
		return fmt.Errorf("failed to parse JWK key: %w", err)
	}

	// Create a test payload
	testPayload := []byte("test payload")

	// Encrypt the test payload & if possible, we're good.
	_, err = jwe.Encrypt(testPayload, jwe.WithKey(alg, jwkKey))
	if err != nil {
		return fmt.Errorf("failed to encrypt test payload: %w", err)
	}

	return nil
}

func EncodeEncrypted(buf []byte, key string) (*Message, error) {
	return nil, nil
}
