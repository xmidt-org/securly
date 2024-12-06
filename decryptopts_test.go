// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateDecrypt(t *testing.T) {
	tests := []struct {
		name      string
		key       jwk.Key
		expectErr bool
	}{
		{
			name:      "valid key",
			key:       mustFromRaw([]byte("test")),
			expectErr: false,
		},
		{
			name:      "missing key",
			key:       nil,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := &decrypter{
				key: tt.key,
			}

			opt := validateDecrypt()
			err := opt.apply(dec)
			if tt.expectErr {
				require.Error(t, err)
				assert.Equal(t, fmt.Errorf("key is required"), err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDecryptWithRaw(t *testing.T) {
	// Generate test keys
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name      string
		rawKey    any
		expectErr bool
	}{
		{
			name:      "valid RSA key",
			rawKey:    rsaPrivateKey,
			expectErr: false,
		},
		{
			name:      "valid ECDSA key",
			rawKey:    ecdsaPrivateKey,
			expectErr: false,
		},
		{
			name:      "valid Ed25519 key",
			rawKey:    ed25519PrivateKey,
			expectErr: false,
		},
		{
			name:      "invalid key type",
			rawKey:    "invalid-key",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := DecryptWithRaw(tt.rawKey)
			dec := &decrypter{}

			err := opt.apply(dec)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, dec.key)
			}
		})
	}
}
