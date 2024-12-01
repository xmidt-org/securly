// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSum(t *testing.T) {
	tests := []struct {
		name string
		sha  SHA
		data []byte
		new  func() hash.Hash
	}{
		{
			name: "SHA-256",
			sha:  SHA256,
			data: []byte("hello world"),
			new:  sha256.New,
		},
		{
			name: "SHA-512",
			sha:  SHA512,
			data: []byte("hello world"),
			new:  sha512.New,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.sha.Sum(tt.data)

			h := tt.new()
			h.Write(tt.data)
			expected := h.Sum(nil)
			assert.Equal(t, expected, result, "Sum() = %x, want %x", result, expected)
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name     string
		sha      SHA
		data     []byte
		expected []byte
		want     bool
	}{
		{
			name:     "SHA-256 valid",
			sha:      SHA256,
			data:     []byte("hello world"),
			expected: SHA256.Sum([]byte("hello world")),
			want:     true,
		},
		{
			name:     "SHA-256 invalid",
			sha:      SHA256,
			data:     []byte("hello world"),
			expected: SHA256.Sum([]byte("hello")),
			want:     false,
		},
		{
			name:     "SHA-512 valid",
			sha:      SHA512,
			data:     []byte("hello world"),
			expected: SHA512.Sum([]byte("hello world")),
			want:     true,
		},
		{
			name:     "SHA-512 invalid",
			sha:      SHA512,
			data:     []byte("hello world"),
			expected: SHA512.Sum([]byte("hello")),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.sha.Validate(tt.expected, tt.data)
			assert.Equal(t, tt.want, got, "Validate() = %v, want %v", got, tt.want)
		})
	}
}

func TestCanonical(t *testing.T) {
	tests := []struct {
		in   string
		want *SHA
	}{
		{"SHA-224", &SHA224},
		{"SHA-256", &SHA256},
		{"SHA-384", &SHA384},
		{"SHA-512", &SHA512},
		{"SHA-512/224", &SHA512_224},
		{"SHA-512/256", &SHA512_256},

		// Unsupported
		{"SHA-1", nil},
		{"", nil},

		// Differnt case
		{"sha-256", &SHA256},
		{"sHa-512", &SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := Canonical(tt.in)

			if tt.want == nil {
				assert.Nil(t, got, "Canonical(%s) = %v, want nil", tt.in, got)
				return
			}

			assert.Equal(t, tt.want.String(), got.String(), "Canonical(%s) = %s, want %s", tt.in, got, tt.want)
		})
	}
}

func TestList(t *testing.T) {
	expected := []string{
		"SHA-224",
		"SHA-256",
		"SHA-384",
		"SHA-512",
		"SHA-512/224",
		"SHA-512/256",
	}

	got := List()

	assert.Equal(t, expected, got, "List() = %v, want %v", got, expected)
}
