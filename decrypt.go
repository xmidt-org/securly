// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type decrypter struct {
	key jwk.Key
}

// Decrypt converts a byte slice into a *Message and decodes
// it it using the provided key.
func Decrypt(buf []byte, opts ...DecryptOption) (*Message, error) {
	d := decrypter{}

	opts = append(opts, validateDecrypt())

	for _, opt := range opts {
		if opt != nil {
			err := opt.apply(&d)
			if err != nil {
				return nil, err
			}
		}
	}

	// Parse the JWE to extract the header
	JWE, err := jwe.Parse(buf)
	if err != nil {
		return nil, err
	}

	// Extract the algorithm from the JWE header
	alg, ok := JWE.ProtectedHeaders().Get(jwe.AlgorithmKey)
	if !ok {
		return nil, err
	}

	// Decrypt the JWE
	decrypted, err := jwe.Decrypt(buf, jwe.WithKey(alg.(jwa.KeyEncryptionAlgorithm), d.key))
	if err != nil {
		return nil, err
	}

	bytes, err := decompress(decrypted)
	if err != nil {
		return nil, err
	}

	var msg Message
	_, err = msg.UnmarshalMsg(bytes)
	if err != nil {
		return nil, err
	}

	return &msg, nil
}
