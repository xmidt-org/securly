// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSafeInTheClear(t *testing.T) {
	tests := []struct {
		name        string
		encryption  *Encryption
		errExpected error
	}{
		{
			name: "nil encryption",
		}, {
			name:       "empty encryption",
			encryption: &Encryption{},
		}, {
			name: "symmetric key",
			encryption: &Encryption{
				Alg: jwa.PBES2_HS256_A128KW,
				Key: mustFromRaw([]byte("a clear text key")),
			},
			errExpected: ErrUnsafeAlgorithm,
		}, {
			name: "asymmetric key",
			encryption: &Encryption{
				Alg: jwa.RSA_OAEP,
				Key: mustFromRaw(chainA.leaf.PublicKey),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.encryption.safeInTheClear()
			if tt.errExpected != nil {
				require.Error(t, result)
				assert.ErrorIs(t, result, tt.errExpected)
				return
			}
			assert.NoError(t, result)
		})
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name        string
		encryption  *Encryption
		expectedErr error
	}{
		{
			name: "nil encryption",
		}, {
			name:       "empty encryption",
			encryption: &Encryption{},
		}, {
			name: "valid JWK key",
			encryption: &Encryption{
				Alg: jwa.PBES2_HS256_A128KW,
				Key: mustFromRaw([]byte("a clear text key")),
			},
		}, {
			name: "invalid JWK key/alg",
			encryption: &Encryption{
				Alg: jwa.RSA_OAEP,
				Key: mustFromRaw([]byte("a clear text key")),
			},
			expectedErr: ErrInvalidEncryptionAlg,
		}, {
			name: "invalid JWK key",
			encryption: &Encryption{
				Alg: jwa.RSA_OAEP, // They key is an EC key, generating an error.
				Key: mustFromRaw(chainA.leaf.PublicKey),
			},
			expectedErr: ErrInvalidEncryptionAlg,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.encryption.verify()
			if tt.expectedErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMarshalErrors(t *testing.T) {
	good := Message{
		Payload: []byte("Hello, world."),
		Files: map[string]File{
			"file1": {
				Data:    []byte("file1 data"),
				Size:    1000,
				Mode:    0644,
				ModTime: time.Now(),
				Owner:   "owner",
				UID:     1000,
				Group:   "group",
				GID:     1000,
			},
		},
		Response: &Encryption{
			Alg: jwa.DIRECT,
			Key: mustFromRaw(chainA.leaf.PublicKey),
		},
	}

	bytes, err := good.MarshalMsg(nil)
	require.NoError(t, err)
	require.NotEmpty(t, bytes)

	for i := 0; i < len(bytes); i++ {
		tmp := bytes
		tmp[i] = tmp[i] ^ 0xff

		var got Message
		n, err := got.UnmarshalMsg(tmp)

		require.Zero(t, n)
		if err == nil {
			require.Equal(t, good, got)
			continue
		}
		require.Error(t, err)
	}
}

func TestEncode(t *testing.T) {
	// Generate test keys
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Convert keys to JWK
	rsaJWK, err := jwk.FromRaw(rsaPrivateKey)
	require.NoError(t, err)

	ecdsaJWK, err := jwk.FromRaw(ecdsaPrivateKey)
	require.NoError(t, err)

	tests := []struct {
		name          string
		message       Message
		expectErr     bool
		expectEncrypt bool
	}{
		{
			name: "unsigned message",
			message: Message{
				Payload: []byte("Hello, world."),
				Files: map[string]File{
					"file1": {
						Data:    []byte("file1 data"),
						Size:    1000,
						Mode:    0644,
						ModTime: time.Now(),
						Owner:   "owner",
						UID:     1000,
						Group:   "group",
						GID:     1000,
					},
				},
			},
			expectErr:     false,
			expectEncrypt: false,
		},
		{
			name: "encrypted message with RSA key",
			message: Message{
				Payload: []byte("Hello, world."),
				Files: map[string]File{
					"file1": {
						Data:    []byte("file1 data"),
						Size:    1000,
						Mode:    0644,
						ModTime: time.Now(),
						Owner:   "owner",
						UID:     1000,
						Group:   "group",
						GID:     1000,
					},
				},
				Response: &Encryption{
					Alg: jwa.RSA_OAEP,
					Key: rsaJWK,
				},
			},
			expectErr:     false,
			expectEncrypt: true,
		},
		{
			name: "encrypted message with ECDSA key",
			message: Message{
				Payload: []byte("Hello, world."),
				Files: map[string]File{
					"file1": {
						Data:    []byte("file1 data"),
						Size:    1000,
						Mode:    0644,
						ModTime: time.Now(),
						Owner:   "owner",
						UID:     1000,
						Group:   "group",
						GID:     1000,
					},
				},
				Response: &Encryption{
					Alg: jwa.ECDH_ES,
					Key: ecdsaJWK,
				},
			},
			expectErr:     false,
			expectEncrypt: true,
		},
		{
			name: "invalid encryption algorithm",
			message: Message{
				Payload: []byte("Hello, world."),
				Files: map[string]File{
					"file1": {
						Data:    []byte("file1 data"),
						Size:    1000,
						Mode:    0644,
						ModTime: time.Now(),
						Owner:   "owner",
						UID:     1000,
						Group:   "group",
						GID:     1000,
					},
				},
				Response: &Encryption{
					Alg: jwa.ECDH_ES,
				},
			},
			expectErr:     true,
			expectEncrypt: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, isEncrypted, err := tt.message.Encode()
			assert.Equal(t, tt.expectEncrypt, isEncrypted)
			if tt.expectErr {
				require.Error(t, err)
				assert.Empty(t, data)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, data)
			}
		})
	}
}

/*
func FuzzMarshalUnmarshal(f *testing.F) {
	// Seed the fuzzer with a valid Message
	good := Message{
		Payload: []byte("Hello, world."),
		Files: map[string]File{
			"file1": {
				Data:  []byte("file1 data"),
				Size:  1000,
				Mode:  0644,
				Owner: "owner",
				UID:   1000,
				Group: "group",
				GID:   1000,
			},
		},
		Response: &Encryption{
			Alg: jwa.DIRECT,
			Key: mustFromRaw(chainA.leaf.PublicKey),
		},
	}

	bytes, err := good.MarshalMsg(nil)
	require.NoError(f, err)
	require.NotEmpty(f, bytes)

	// Add the seed corpus
	f.Add(bytes)

	f.Fuzz(func(t *testing.T, data []byte) {
		var got Message
		n, err := got.UnmarshalMsg(data)

		if err == nil {
			require.Equal(t, good, got)
		} else {
			require.Zero(t, n)
			require.Error(t, err)
		}
	})
}
*/
