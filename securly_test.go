// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
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
