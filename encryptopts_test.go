// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptWithRaw(t *testing.T) {
	// Generate test keys
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name      string
		alg       jwa.KeyEncryptionAlgorithm
		rawKey    any
		expectErr bool
	}{
		{
			name:      "valid RSA key",
			alg:       jwa.RSA_OAEP,
			rawKey:    rsaPrivateKey,
			expectErr: false,
		},
		{
			name:      "valid ECDSA key",
			alg:       jwa.ECDH_ES,
			rawKey:    ecdsaPrivateKey,
			expectErr: false,
		},
		{
			name:      "valid Ed25519 key",
			alg:       jwa.ECDH_ES,
			rawKey:    ed25519PrivateKey,
			expectErr: false,
		},
		{
			name:      "invalid key type",
			alg:       jwa.RSA_OAEP,
			rawKey:    "invalid-key",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := EncryptWithRaw(tt.alg, tt.rawKey)
			enc := &encrypter{}

			err := opt.apply(enc)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.alg, enc.alg)
				assert.NotNil(t, enc.key)
			}
		})
	}
}

func TestValidateEncryptOption(t *testing.T) {
	tests := []struct {
		name      string
		alg       jwa.KeyEncryptionAlgorithm
		key       jwk.Key
		expectErr bool
	}{
		{
			name:      "valid algorithm and key",
			alg:       jwa.DIRECT,
			key:       mustFromRaw([]byte("a clear text key")),
			expectErr: false,
		},
		{
			name:      "missing algorithm and key",
			expectErr: false,
		},
		{
			name:      "missing key",
			alg:       jwa.RSA_OAEP,
			expectErr: true,
		},
		{
			name:      "missing algorithm",
			key:       mustFromRaw([]byte("a clear text key")),
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := &encrypter{
				alg: tt.alg,
				key: tt.key,
			}

			opt := validateEncrypt()
			err := opt.apply(enc)
			if tt.expectErr {
				require.Error(t, err)
				assert.Equal(t, ErrInvalidEncryptionAlg, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
