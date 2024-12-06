// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignWithRaw(t *testing.T) {
	// Generate test keys
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Generate a test certificate
	cert := &x509.Certificate{}

	tests := []struct {
		name        string
		alg         jwa.SignatureAlgorithm
		privateKey  any
		expectErr   bool
		expectedAlg jwa.SignatureAlgorithm
		expectedKey any
	}{
		{
			name:        "valid RS256 key",
			alg:         jwa.RS256,
			privateKey:  rsaPrivateKey,
			expectErr:   false,
			expectedAlg: jwa.RS256,
		},
		{
			name:        "valid ES256 key",
			alg:         jwa.ES256,
			privateKey:  ecdsaPrivateKey,
			expectErr:   false,
			expectedAlg: jwa.ES256,
		},
		{
			name:        "valid EdDSA key",
			alg:         jwa.EdDSA,
			privateKey:  ed25519PrivateKey,
			expectErr:   false,
			expectedAlg: jwa.EdDSA,
		},
		{
			name:       "invalid key type",
			alg:        jwa.RS256,
			privateKey: "invalid-key",
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			opt := SignWithRaw(tt.alg, cert, tt.privateKey)
			enc := &encoder{}

			err := opt.apply(enc)
			if tt.expectErr {
				assert.Error(err)
			} else {
				require.NoError(err)
				assert.Equal(tt.expectedAlg, enc.signAlg)
				assert.NotNil(enc.key)
			}
		})
	}
}

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
			enc := &encoder{
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
