// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errUnknown = fmt.Errorf("unknown error")

var chainA = mustGeneratecertChain(
	`leaf
		<-ica(1.2.900,1.2.901)
		<-ica(1.2.100)
		<-root`)

var chainB = mustGeneratecertChain(
	`leaf
		<-ica(1.2.900,1.2.901)
		<-ica(1.2.100)
		<-root`)

type encDecTest struct {
	desc      string
	encOpts   []EncoderOption
	newEncErr error
	input     Message
	encErr    error
	decOpts   []DecoderOption
	newDecErr error
	decErr    error
	output    *Message // set if different than the input
}

var tests = []encDecTest{
	{
		desc: "simple, working",
		encOpts: []EncoderOption{
			SignWith(jwa.ES256, chainA.leaf, chainA.leafKey, chainA.chain...),
		},
		input: Message{
			Payload: []byte("Hello, world."),
			Files:   make(map[string][]byte),
		},
		decOpts: []DecoderOption{
			TrustRootCA(chainA.root),
			RequirePolicy("1.2.100"),
		},
	}, {
		desc: "complex, working",
		encOpts: []EncoderOption{
			SignWith(jwa.ES256, chainA.leaf, chainA.leafKey, chainA.chain...),
		},
		input: Message{
			Payload: []byte("Hello, world."),
			Files: map[string][]byte{
				"file1": []byte("file1 contents"),
				"file2": []byte("file2 contents"),
			},
			Response: mustGenerateResponse(jwa.ECDH_ES, chainA.leaf),
		},
		decOpts: []DecoderOption{
			TrustRootCA(chainA.root),
			RequirePolicy("1.2.100"),
		},
	}, {
		desc: "disallowed signing algorithm",
		encOpts: []EncoderOption{
			SignWith(jwa.HS256, chainA.leaf, chainA.leafKey, chainA.chain...),
		},
		newEncErr: errUnknown,
	}, {
		desc: "invalid response encryption algorithm",
		encOpts: []EncoderOption{
			SignWith(jwa.ES256, chainA.leaf, chainA.leafKey, chainA.chain...),
		},
		input: Message{
			Payload: []byte("Hello, world."),
			Response: &Encrypt{
				Alg: jwa.DIRECT,
				Key: "a clear text key, which is not allowed",
			},
		},
		encErr: ErrInvalidEncryptionAlg,
	}, {
		desc: "invalid response encryption key/alg combination",
		encOpts: []EncoderOption{
			SignWith(jwa.ES256, chainA.leaf, chainA.leafKey, chainA.chain...),
		},
		input: Message{
			Payload: []byte("Hello, world."),
			Response: &Encrypt{
				Alg: jwa.RSA_OAEP,
				Key: "a clear text key, which is not allowed",
			},
		},
		encErr: errUnknown,
	}, {
		desc: "untrusted chain",
		encOpts: []EncoderOption{
			SignWith(jwa.ES256, chainB.leaf, chainB.leafKey, chainB.chain...),
		},
		input: Message{
			Payload: []byte("Hello, world."),
			Files:   make(map[string][]byte),
		},
		decOpts: []DecoderOption{
			TrustRootCA(chainA.root),
		},
		decErr: errUnknown,
	},
}

func TestEncDec(t *testing.T) {
	for _, tt := range tests {
		runEncDecTest(t, tt)
	}
}

func runEncDecTest(t *testing.T, tt encDecTest) {
	t.Run(tt.desc, func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		enc, err := NewEncoder(tt.encOpts...)
		if tt.newEncErr != nil {
			assert.Nil(enc)
			assert.Error(err)
			if tt.newEncErr != errUnknown {
				assert.ErrorIs(err, tt.newEncErr)
			}
			return
		}
		require.NoError(err)
		require.NotNil(enc)

		buf, err := enc.Encode(&tt.input)
		if tt.encErr != nil {
			assert.Nil(buf)
			assert.Error(err)
			if tt.encErr != errUnknown {
				assert.ErrorIs(err, tt.encErr)
			}
			return
		}
		require.NoError(err)
		require.NotNil(buf)

		dec, err := NewDecoder(tt.decOpts...)
		if tt.newDecErr != nil {
			assert.Nil(dec)
			assert.Error(err)
			if tt.newDecErr != errUnknown {
				assert.ErrorIs(err, tt.newDecErr)
			}
			return
		}
		require.NoError(err)
		require.NotNil(dec)

		msg, err := dec.Decode(buf)
		if tt.decErr != nil {
			assert.Nil(msg)
			assert.Error(err)
			if tt.decErr != errUnknown {
				assert.ErrorIs(err, tt.decErr)
			}
			return
		}

		require.NoError(err)
		require.NotNil(msg)

		want := &tt.input
		if tt.output != nil {
			want = tt.output
		}
		assert.Equal(want, msg)
	})
}

func mustGenerateResponse(alg jwa.KeyEncryptionAlgorithm, c *x509.Certificate) *Encrypt {
	key, err := jwk.FromRaw(c.PublicKey)
	if err != nil {
		panic(err)
	}

	b, err := json.Marshal(key)
	if err != nil {
		panic(err)
	}

	rv := Encrypt{
		Alg: alg,
		Key: string(b),
	}

	return &rv
}
