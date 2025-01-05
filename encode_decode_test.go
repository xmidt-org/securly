// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type encodeDecodeTest struct {
	desc    string
	encOpts []SignOption
	input   Message
	encErr  error
	decOpts []DecoderOption
	decErr  error
	output  *Message // set if different than the input
}

var simpleWorking = encodeDecodeTest{
	desc: "simple, working",
	encOpts: []SignOption{
		SignWithRaw(jwa.ES256, chainA.Leaf().Public, chainA.Leaf().Private, chainA.Included()...),
	},
	input: Message{
		Payload: []byte("Hello, world."),
	},
	decOpts: []DecoderOption{
		TrustRootCAs(chainA.Root().Public),
		RequirePolicies("1.2.100"),
	},
}

var complexWorking = encodeDecodeTest{
	desc: "complex, working",
	encOpts: []SignOption{
		SignWithRaw(jwa.ES256, chainA.Leaf().Public, chainA.Leaf().Private, chainA.Included()...),
	},
	input: Message{
		Payload: []byte("Hello, world."),
		Files: map[string]File{
			"file1": {
				Data: []byte("file1 contents"),
			},
			"file2": {
				Data: []byte("file2 contents"),
			},
		},
		Response: &Encryption{
			Alg: jwa.ECDH_ES,
			Key: mustFromRaw(chainA.Leaf().Public.PublicKey),
		},
	},
	decOpts: []DecoderOption{
		TrustRootCAs(chainA.Root().Public),
		RequirePolicies("1.2.100"),
		Require(
			// Show this verifier is called and works.
			VerifierFunc(
				func(_ context.Context, _ []*x509.Certificate, _ time.Time) error {
					return nil
				})),
	},
}

var encodeDecodeTests = []encodeDecodeTest{
	simpleWorking,
	complexWorking,
	{
		desc: "No trusted roots",
		encOpts: []SignOption{
			SignWithRaw(jwa.ES256, chainA.Leaf().Public, chainA.Leaf().Private, chainA.Included()...),
		},
		input: Message{
			Payload: []byte("Hello, world."),
		},
		decErr: errUnknown,
	}, {
		desc: "Require() not met",
		encOpts: []SignOption{
			SignWithRaw(jwa.ES256, chainA.Leaf().Public, chainA.Leaf().Private, chainA.Included()...),
		},
		input: Message{
			Payload: []byte("Hello, world."),
		},
		decOpts: []DecoderOption{
			TrustRootCAs(chainA.Root().Public),
			RequirePolicies("1.2.100"),
			Require(
				VerifierFunc(
					func(_ context.Context, _ []*x509.Certificate, _ time.Time) error {
						return errors.New("custom verifier failed")
					})),
		},
		decErr: errUnknown,
	}, {
		desc: "NoSignature()/NoVerification(), working",
		encOpts: []SignOption{
			NoSignature(),
		},
		input: Message{
			Payload: []byte("Hello, world."),
		},
		decOpts: []DecoderOption{
			NoVerification(),
		},
	}, {
		desc: "Signature with NoVerification(), working",
		encOpts: []SignOption{
			SignWithRaw(jwa.ES256, chainA.Leaf().Public, chainA.Leaf().Private, chainA.Included()...),
		},
		input: Message{
			Payload: []byte("Hello, world."),
		},
		decOpts: []DecoderOption{
			NoVerification(),
		},
	}, {
		desc: "NoSignature() with verification, should fail",
		encOpts: []SignOption{
			NoSignature(),
		},
		input: Message{
			Payload: []byte("Hello, world."),
		},
		decOpts: []DecoderOption{
			TrustRootCAs(chainA.Root().Public),
		},
		decErr: errUnknown,
	}, {
		desc: "Try using signing algorith none, should fail",
		encOpts: []SignOption{
			SignWith("none", nil, nil),
		},
		input: Message{
			Payload: []byte("Hello, world."),
		},
		encErr: ErrInvalidSignAlg,
	}, {
		desc: "Try setting multiple signing algorithms, should fail",
		encOpts: []SignOption{
			NoSignature(),
			SignWithRaw(jwa.ES256, chainA.Leaf().Public, chainA.Leaf().Private, chainA.Included()...),
		},
		input: Message{
			Payload: []byte("Hello, world."),
		},
		encErr: ErrInvalidSignAlg,
	}, {
		desc: "invalid response encryption algorithm",
		encOpts: []SignOption{
			SignWithRaw(jwa.ES256, chainA.Leaf().Public, chainA.Leaf().Private, chainA.Included()...),
		},
		input: Message{
			Payload: []byte("Hello, world."),
			Response: &Encryption{
				Alg: "invalid",
				Key: mustFromRaw([]byte("a clear text key, which is not allowed")),
			},
		},
		encErr: ErrInvalidEncryptionAlg,
	}, {
		desc: "unsafe response encryption algorithm	in the clear is not allowed",
		encOpts: []SignOption{
			SignWithRaw(jwa.ES256, chainA.Leaf().Public, chainA.Leaf().Private, chainA.Included()...),
		},
		input: Message{
			Payload: []byte("Hello, world."),
			Response: &Encryption{
				Alg: jwa.PBES2_HS256_A128KW,
				Key: mustFromRaw([]byte("a clear text key, which is not allowed")),
			},
		},
		encErr: ErrUnsafeAlgorithm,
	}, {
		desc: "invalid response encryption key/alg combination",
		encOpts: []SignOption{
			SignWithRaw(jwa.ES256, chainA.Leaf().Public, chainA.Leaf().Private, chainA.Included()...),
		},
		input: Message{
			Payload: []byte("Hello, world."),
			Response: &Encryption{
				Alg: jwa.RSA_OAEP,
				Key: mustFromRaw([]byte("invalid key form")),
			},
		},
		encErr: errUnknown,
	}, {
		desc: "untrusted chain",
		encOpts: []SignOption{
			SignWithRaw(jwa.ES256, chainB.Leaf().Public, chainB.Leaf().Private, chainB.Included()...),
		},
		input: Message{
			Payload: []byte("Hello, world."),
		},
		decOpts: []DecoderOption{
			TrustRootCAs(chainA.Root().Public),
		},
		decErr: errUnknown,
	},
}

func TestSigningTampering(t *testing.T) {
	// Require everything to prevent 100s of duplicate errors.
	require := require.New(t)

	buf, err := complexWorking.input.Sign(complexWorking.encOpts...)
	require.NoError(err)
	require.NotNil(buf)

	for i := 0; i < len(buf); i++ {
		tmp := make([]byte, len(buf))
		copy(tmp, buf)
		tmp[i] = tmp[i] ^ 0xff

		msg, err := Decode(tmp, complexWorking.decOpts...)

		// Sometimes changing gzip data can result in the original message.
		if err == nil && msg != nil {
			require.Equal(&complexWorking.input, msg)
			continue
		}

		require.Nil(msg, "idx=%d 0x%02x '%c'", i, tmp[i]^0xff, tmp[i]^0xff)
		require.Error(err)
	}
}

func TestEncDec(t *testing.T) {
	for _, tt := range encodeDecodeTests {
		runEncDecTest(t, tt)
	}
}

func runEncDecTest(t *testing.T, tt encodeDecodeTest) {
	t.Run(tt.desc, func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		buf, err := tt.input.Sign(tt.encOpts...)
		if tt.encErr != nil {
			assert.Nil(buf)
			require.Error(err)
			if !errors.Is(errUnknown, tt.encErr) {
				require.ErrorIs(err, tt.encErr)
			}
			return
		}
		require.NoError(err)
		require.NotNil(buf)

		msg, err := Decode(buf, tt.decOpts...)
		if tt.decErr != nil {
			assert.Nil(msg)
			require.Error(err)
			if !errors.Is(errUnknown, tt.decErr) {
				require.ErrorIs(err, tt.decErr)
			}
			return
		}

		require.NoError(err)
		require.NotNil(msg)

		want := &tt.input
		if tt.output != nil {
			want = tt.output
		}

		require.Equal(want, msg)
	})
}
