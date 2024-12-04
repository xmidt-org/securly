// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateCertChain tests the validateCertChain function.
func TestValidateCertChain(t *testing.T) {
	require := require.New(t)

	errUnknown := errors.New("unknown")

	unrelated, _, err := generateCertChain("leaf<-root")
	require.NoError(err)
	require.NotNil(unrelated)

	unrelated2, _, err := generateCertChain("leaf<-root")
	require.NoError(err)
	require.NotNil(unrelated2)

	certs, _, err := generateCertChain("leaf<-ica(1.2.900,1.2.901)<-ica(1.2.100)<-root")
	require.NoError(err)
	require.NotNil(certs)

	// Slice off the root.
	root := certs[len(certs)-1]
	certs = certs[:len(certs)-1]

	tests := []struct {
		name     string
		chain    []*x509.Certificate
		root     *x509.Certificate
		roots    []*x509.Certificate
		policies []string
		encoder  func([]byte) string
		err      error
	}{
		{
			name:     "valid chain with policies",
			chain:    certs,
			root:     root,
			policies: []string{"1.2.900", "1.2.901"},
		}, {
			name:  "valid chain with policies, multiple roots",
			chain: certs,
			roots: []*x509.Certificate{
				unrelated[1],
				root,
				unrelated2[1],
			},
			policies: []string{"1.2.900", "1.2.901"},
		}, {
			name:     "invalid chain missing root",
			chain:    certs,
			policies: []string{"1.2.900", "1.2.901"},
			err:      errUnknown,
		}, {
			name:     "valid chain no policy check",
			chain:    certs,
			root:     root,
			policies: []string{},
		}, {
			name:     "invalid chain due to missing policies",
			chain:    certs,
			root:     root,
			policies: []string{"1.2.999"},
			err:      errUnknown,
		}, {
			name:  "unrelated root and chain",
			chain: certs,
			root:  unrelated[1],
			err:   errUnknown,
		}, {
			name:  "unrelated roots and chain",
			chain: certs,
			roots: []*x509.Certificate{
				unrelated[1],
				unrelated2[1],
			},
			err: errUnknown,
		}, {
			name:  "valid chain but encoded value is invalid",
			chain: certs,
			root:  root,
			encoder: func(_ []byte) string {
				return base64.URLEncoding.EncodeToString([]byte("invalid"))
			},
			err: errUnknown,
		}, {
			name:    "valid chain but encoding is invalid",
			chain:   certs,
			root:    root,
			encoder: base64.StdEncoding.EncodeToString,
			err:     errUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			// Encode certificates to base64
			var certChain cert.Chain
			for _, cert := range certs {
				fn := base64.URLEncoding.EncodeToString
				if tt.encoder != nil {
					fn = tt.encoder
				}
				certBase64 := fn(cert.Raw)
				err := certChain.AddString(certBase64)
				require.NoError(err)
			}

			// Determine roots
			roots := tt.roots
			if tt.root != nil {
				roots = append(roots, tt.root)
			}

			leaf, err := validateCertChain(roots, &certChain, tt.policies)

			if tt.err != nil {
				assert.Empty(leaf)
				require.Error(err)
				if !errors.Is(errUnknown, tt.err) {
					require.ErrorIs(err, tt.err)
				}
				return
			}

			assert.NotEmpty(leaf)
			assert.NoError(err)

		})
	}
}
