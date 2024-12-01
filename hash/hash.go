// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package hash

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"sort"
	"strings"
)

// SHA is a hash algorithm.
type SHA struct {
	name string
	new  func() hash.Hash
}

func (s SHA) String() string {
	return s.name
}

// Sum returns the SHA hash of the data.
func (s SHA) Sum(data []byte) []byte {
	h := s.new()
	h.Write(data)
	return h.Sum(nil)
}

// Validate returns true if the expected hash matches the calculated hash of the data.
func (s SHA) Validate(expected, data []byte) bool {
	calculated := s.Sum(data)

	return bytes.Equal(expected, calculated)
}

var (
	SHA224     = SHA{"SHA-224", sha256.New224}
	SHA256     = SHA{"SHA-256", sha256.New}
	SHA384     = SHA{"SHA-384", sha512.New384}
	SHA512     = SHA{"SHA-512", sha512.New}
	SHA512_224 = SHA{"SHA-512/224", sha512.New512_224}
	SHA512_256 = SHA{"SHA-512/256", sha512.New512_256}
)

var (
	shas = []SHA{
		SHA224,
		SHA256,
		SHA384,
		SHA512,
		SHA512_224,
		SHA512_256,
	}
)

// List returns a sorted list of supported algorithms.
//
// The supported algorithms are SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224,
// and SHA-512/256.
func List() []string {
	l := make([]string, 0, len(shas))
	for _, k := range shas {
		l = append(l, k.name)
	}

	sort.Strings(l)

	return l
}

// Canonical returns the canonical name of the algorithm.  The check is
// case-insensitive and cleans up any leading/trailing whitespace.
func Canonical(alg string) *SHA {
	alg = strings.ToUpper(alg)
	alg = strings.TrimSpace(alg)

	for _, sha := range shas {
		if sha.name == alg {
			return &sha
		}
	}
	return nil
}
