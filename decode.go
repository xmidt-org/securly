// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/xmidt-org/securly/hash"
	"github.com/xmidt-org/securly/internal/wire"
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
	trustedRootCAs []*x509.Certificate
	policies       []string
}

// newDecoder converts a slice of bytes plus options into a Message.
func newDecoder(opts ...DecoderOption) (*decoder, error) {
	var p decoder

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

// decode converts a slice of bytes into a *Message if possible.
func (p *decoder) decode(buf []byte) (*Message, error) {
	// Unmarshal the outer payload
	var outer wire.Outer
	left, err := outer.UnmarshalMsg(buf)
	if err != nil {
		return nil, err
	}
	if len(left) != 0 {
		return nil, fmt.Errorf("%w leftover bytes", ErrInvalidPayload)
	}

	// Verify the JWS signature if possible.
	if !p.noVerification {
		if err = validateSignature(outer.JWS, p.trustedRootCAs, p.policies); err != nil {
			return nil, err
		}
	}

	trusted, err := jws.Parse([]byte(outer.JWS), jws.WithCompact())
	if err != nil {
		return nil, err
	}

	payload := trusted.Payload()

	// Unmarshal the inner payload
	var inner wire.Inner
	if _, err = inner.UnmarshalMsg(payload); err != nil {
		return nil, err
	}

	// Verify the data hash.
	sha := hash.Canonical(inner.Alg)
	if sha == nil {
		return nil, errors.Join(ErrInvalidSHA, fmt.Errorf("unsupported SHA algorithm %s", inner.Alg))
	}

	if !sha.Validate(inner.SHA, outer.Data) {
		return nil, errors.Join(ErrInvalidSHA, ErrInvalidSignature)
	}

	msg, err := msgFromWire(outer.Data)
	if err != nil {
		return nil, err
	}

	// The encryption algorithm must be safe to send in the clear, or this
	// message is invalid.
	if err := msg.Response.safeInTheClear(); err != nil {
		return nil, err
	}

	return msg, nil
}

func validateSignature(JWS string, roots []*x509.Certificate, policies []string) error {
	untrusted, err := jws.Parse([]byte(JWS), jws.WithCompact())
	if err != nil {
		return err
	}

	sigs := untrusted.Signatures()
	if len(sigs) != 1 {
		return fmt.Errorf("expecting exactly one signer, got %d", len(sigs))
	}

	signer := sigs[0]
	headers := signer.ProtectedHeaders()

	// Get the algorithm
	alg, ok := headers.Get("alg")
	if !ok {
		return fmt.Errorf("alg header is missing")
	}

	// Get the x5c header
	chain, ok := headers.Get("x5c")
	if !ok || chain == nil {
		return fmt.Errorf("x5c header is missing or invalid")
	}

	// Validate the cert chain and get the leaf node.
	leaf, err := validateCertChain(roots, chain.(*cert.Chain), policies)
	if err != nil {
		return err
	}

	// Decode the first certificate in the x5c header
	certData, err := base64.URLEncoding.DecodeString(leaf)
	if err != nil {
		return fmt.Errorf("failed to decode x5c certificate: %w", err)
	}

	// Parse the certificate to get the public key
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return fmt.Errorf("failed to parse x5c certificate: %w", err)
	}

	key := jws.WithKey(alg.(jwa.KeyAlgorithm), cert.PublicKey).(jws.VerifyOption)

	_, err = jws.Verify([]byte(JWS), key)
	if err != nil {
		return fmt.Errorf("failed to verify JWS: %w", err)
	}

	return nil
}
