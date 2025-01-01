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

type encryptDecryptTest struct {
	desc    string
	encOpts []EncryptOption
	input   Message
	encErr  error
	decOpts []DecryptOption
	decErr  error
	output  *Message // set if different than the input
}

var encryptExternalKey = encryptDecryptTest{
	desc: "simple, working with external key",
	encOpts: []EncryptOption{
		EncryptWithRaw(jwa.ECDH_ES, chainA.Leaf().Public.PublicKey),
	},
	input: Message{
		Payload: []byte("Hello, world."),
	},
	decOpts: []DecryptOption{
		DecryptWithRaw(chainA.Leaf().Private),
	},
}

var encryptResponseKey = encryptDecryptTest{
	desc: "simple, working with response key",
	input: Message{
		Payload:  []byte("Hello, world."),
		Response: mustGenerateResponse(jwa.ECDH_ES, chainA.Leaf().Public),
	},
	decOpts: []DecryptOption{
		DecryptWithRaw(chainA.Leaf().Private),
	},
	output: &Message{
		Payload: []byte("Hello, world."),
	},
}

var encryptDecryptTests = []encryptDecryptTest{
	encryptExternalKey,
	encryptResponseKey,
	{
		desc: "simple, working with a present but empty response key",
		encOpts: []EncryptOption{
			EncryptWithRaw(jwa.ECDH_ES, chainA.Leaf().Public.PublicKey),
		},
		input: Message{
			Payload:  []byte("Hello, world."),
			Response: &Encryption{},
		},
		decOpts: []DecryptOption{
			DecryptWithRaw(chainA.Leaf().Private),
		},
		output: &Message{
			Payload: []byte("Hello, world."),
		},
	}, {
		desc:   "no encryption algorithm",
		encErr: ErrInvalidEncryptionAlg,
		input: Message{
			Payload: []byte("Hello, world."),
		},
	}, {
		desc: "invalid encryption algorithm",
		encOpts: []EncryptOption{
			EncryptWith(jwa.ECDH_ES, nil),
		},
		encErr: ErrInvalidEncryptionAlg,
	}, {
		desc: "invalid decryption key",
		input: Message{
			Payload:  []byte("Hello, world."),
			Response: mustGenerateResponse(jwa.ECDH_ES, chainA.Leaf().Public),
		},
		decOpts: []DecryptOption{
			DecryptWith(nil),
		},
		decErr: errUnknown,
	}, {
		desc: "invalid response key/alg pair",
		input: Message{
			Payload: []byte("Hello, world."),
			Response: &Encryption{
				Alg: jwa.DIRECT,
				Key: mustFromRaw(chainA.Leaf().Public.PublicKey),
			},
		},
		encErr: errUnknown,
	}, {
		desc: "invalid response key, missing the alg",
		input: Message{
			Payload: []byte("Hello, world."),
			Response: &Encryption{
				Key: mustFromRaw(chainA.Leaf().Public.PublicKey),
			},
		},
		decOpts: []DecryptOption{
			DecryptWithRaw(chainA.Leaf().Private),
		},
		output: &Message{
			Payload: []byte("Hello, world."),
		},
		encErr: ErrInvalidEncryptionAlg,
	},
}

func TestEncryptDecrypt(t *testing.T) {
	for _, tt := range encryptDecryptTests {
		runEncryptDecryptTest(t, tt)
	}
}

func runEncryptDecryptTest(t *testing.T, tt encryptDecryptTest) {
	t.Run(tt.desc, func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		buf, err := tt.input.Encrypt(tt.encOpts...)
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

		msg, err := Decrypt(buf, tt.decOpts...)
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

		assert.Equal(want, msg)
	})
}
func TestEncryptingTampering(t *testing.T) {
	// Require everything to prevent 100s of duplicate errors.
	require := require.New(t)

	buf, err := encryptResponseKey.input.Encrypt(encryptResponseKey.encOpts...)
	require.NoError(err)
	require.NotNil(buf)

	for i := 0; i < len(buf); i++ {
		tmp := make([]byte, len(buf))
		copy(tmp, buf)
		tmp[i] = tmp[i] ^ 0xff

		msg, err := Decrypt(tmp, encryptExternalKey.decOpts...)
		require.Nil(msg, "idx=%d 0x%02x '%c'", i, tmp[i]^0xff, tmp[i]^0xff)
		require.Error(err)
	}
}
