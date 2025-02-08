// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignWithX509(t *testing.T) {
	chain := mustGeneratecertChain("leaf<-ica<-root")

	tests := []struct {
		name    string
		alg     jwa.SignatureAlgorithm
		private any
		certs   []*x509.Certificate
		err     bool
	}{
		{
			name:    "valid RS256 key and chain",
			alg:     jwa.RS256,
			private: chain.Leaf().Private,
			certs:   chain.Included(),
		}, {
			name:    "invalid symmetric key",
			alg:     jwa.HS256,
			private: chain.Leaf().Private,
			certs:   chain.Included(),
			err:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := SignWithX509Chain(tt.alg, tt.private, tt.certs)

			assert.NotNil(t, opt)

			var enc Signer
			err := opt.apply(&enc)

			if tt.err {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestSignWithKey(t *testing.T) {
	// Generate test keys
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name       string
		alg        jwa.SignatureAlgorithm
		privateKey any
	}{
		{
			name:       "valid RS256 key",
			alg:        jwa.RS256,
			privateKey: rsaPrivateKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := SignWithKey(tt.alg, tt.privateKey)

			assert.NotNil(t, opt)

			var enc Signer
			err := opt.apply(&enc)

			assert.NoError(t, err)
		})
	}
}

/*
func TestValidateSigAlg(t *testing.T) {
	// Generate a test certificate
	cert := &x509.Certificate{}

	key, err := jwk.FromRaw([]byte("key"))
	require.NoError(t, err)
	require.NotNil(t, key)

	tests := []struct {
		name          string
		signAlg       jwa.SignatureAlgorithm
		doNotSign     bool
		leaf          *x509.Certificate
		key           jwk.Key
		intermediates []*x509.Certificate
		expectErr     error
	}{
		{
			name:          "valid RS256 key",
			signAlg:       jwa.RS256,
			leaf:          cert,
			key:           key,
			intermediates: []*x509.Certificate{cert},
		}, {
			name:      "no signature works",
			doNotSign: true,
		}, {
			name:          "no signature with other options",
			doNotSign:     true,
			signAlg:       jwa.RS256,
			leaf:          cert,
			key:           key,
			intermediates: []*x509.Certificate{cert},
			expectErr:     ErrInvalidSignAlg,
		}, {
			name:          "missing algorithm",
			leaf:          cert,
			key:           key,
			intermediates: []*x509.Certificate{cert},
			expectErr:     ErrInvalidSignAlg,
		}, {
			name:          "missing key",
			signAlg:       jwa.RS256,
			intermediates: []*x509.Certificate{cert},
			expectErr:     ErrInvalidSignAlg,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := &Encoder{
				signAlg:       tt.signAlg,
				doNotSign:     tt.doNotSign,
				leaf:          tt.leaf,
				key:           tt.key,
				intermediates: tt.intermediates,
			}

			opt := validateSigAlg()
			err := opt.apply(enc)
			if tt.expectErr != nil {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
		})
	}
}
*/
