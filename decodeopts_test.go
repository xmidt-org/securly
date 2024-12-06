// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRoots(t *testing.T) {
	// Generate a test certificate
	cert := &x509.Certificate{}

	tests := []struct {
		name           string
		trustedRootCAs []*x509.Certificate
		noVerification bool
		expectErr      bool
	}{
		{
			name:           "valid with trusted root CAs",
			trustedRootCAs: []*x509.Certificate{cert},
			expectErr:      false,
		},
		{
			name:           "valid with no verification",
			noVerification: true,
			expectErr:      false,
		},
		{
			name:      "invalid with no trusted root CAs and verification enabled",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := &decoder{
				trustedRootCAs: tt.trustedRootCAs,
				noVerification: tt.noVerification,
			}

			opt := validateRoots()
			err := opt.apply(dec)
			if tt.expectErr {
				require.Error(t, err)
				assert.Equal(t, fmt.Errorf("no trusted root CAs provided"), err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
