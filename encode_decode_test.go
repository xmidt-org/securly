// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type encodeDecodeTest struct {
	desc    string
	encOpts []EncodeOption
	input   Message
	encErr  error
	decOpts []DecoderOption
	decErr  error
	output  *Message // set if different than the input
}

var simpleWorking = encodeDecodeTest{
	desc: "simple, working",
	encOpts: []EncodeOption{
		SignWithRaw(jwa.ES256, chainA.leaf, chainA.leafKey, chainA.chain...),
	},
	input: Message{
		Payload: []byte("Hello, world."),
	},
	decOpts: []DecoderOption{
		TrustRootCAs(chainA.root),
		RequirePolicies("1.2.100"),
	},
}

var complexWorking = encodeDecodeTest{
	desc: "complex, working",
	encOpts: []EncodeOption{
		SignWithRaw(jwa.ES256, chainA.leaf, chainA.leafKey, chainA.chain...),
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
			Key: mustFromRaw(chainA.leaf.PublicKey),
		},
	},
	decOpts: []DecoderOption{
		TrustRootCAs(chainA.root),
		RequirePolicies("1.2.100"),
	},
}

var encodeDecodeTests = []encodeDecodeTest{
	simpleWorking,
	complexWorking,
	{
		desc: "NoSignature()/NoVerification(), working",
		encOpts: []EncodeOption{
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
		encOpts: []EncodeOption{
			SignWithRaw(jwa.ES256, chainA.leaf, chainA.leafKey, chainA.chain...),
		},
		input: Message{
			Payload: []byte("Hello, world."),
		},
		decOpts: []DecoderOption{
			NoVerification(),
		},
	}, {
		desc: "NoSignature() with verification, should fail",
		encOpts: []EncodeOption{
			NoSignature(),
		},
		input: Message{
			Payload: []byte("Hello, world."),
		},
		decOpts: []DecoderOption{
			TrustRootCAs(chainA.root),
		},
		decErr: errUnknown,
	}, {
		desc: "Try using signing algorith none, should fail",
		encOpts: []EncodeOption{
			SignWith("none", nil, nil),
		},
		input: Message{
			Payload: []byte("Hello, world."),
		},
		encErr: ErrInvalidSignAlg,
	}, {
		desc: "Try setting multiple signing algorithms, should fail",
		encOpts: []EncodeOption{
			NoSignature(),
			SignWithRaw(jwa.ES256, chainA.leaf, chainA.leafKey, chainA.chain...),
		},
		input: Message{
			Payload: []byte("Hello, world."),
		},
		encErr: ErrInvalidSignAlg,
	}, {
		desc: "invalid response encryption algorithm",
		encOpts: []EncodeOption{
			SignWithRaw(jwa.ES256, chainA.leaf, chainA.leafKey, chainA.chain...),
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
		encOpts: []EncodeOption{
			SignWithRaw(jwa.ES256, chainA.leaf, chainA.leafKey, chainA.chain...),
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
		encOpts: []EncodeOption{
			SignWithRaw(jwa.ES256, chainA.leaf, chainA.leafKey, chainA.chain...),
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
		encOpts: []EncodeOption{
			SignWithRaw(jwa.ES256, chainB.leaf, chainB.leafKey, chainB.chain...),
		},
		input: Message{
			Payload: []byte("Hello, world."),
		},
		decOpts: []DecoderOption{
			TrustRootCAs(chainA.root),
		},
		decErr: errUnknown,
	},
}

func TestSigningTampering(t *testing.T) {
	// Require everything to prevent 100s of duplicate errors.
	require := require.New(t)

	buf, err := complexWorking.input.Encode(complexWorking.encOpts...)
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

		buf, err := tt.input.Encode(tt.encOpts...)
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
