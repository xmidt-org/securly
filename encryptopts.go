// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// EncryptOption is a functional option for the Instructions constructor.
type EncryptOption interface {
	apply(*encrypter) error
}

// EncryptWith sets the key encryption algorithm and key to use for encryption.
// If set, this will override the key and algorithm set in the Message.  The
// value set in the message will be sent over the wire if this option is set.
func EncryptWith(alg jwa.KeyEncryptionAlgorithm, key jwk.Key) EncryptOption {
	return encryptWith{alg, key}
}

func EncryptWithRaw(alg jwa.KeyEncryptionAlgorithm, raw any) EncryptOption {
	key, err := jwk.FromRaw(raw)
	if err != nil {
		return errorEncrypt(err)
	}

	return EncryptWith(alg, key)
}

type encryptWith struct {
	alg jwa.KeyEncryptionAlgorithm
	key jwk.Key
}

func (e encryptWith) apply(enc *encrypter) error {
	enc.alg = e.alg
	enc.key = e.key
	return nil
}

//------------------------------------------------------------------------------

func errorEncrypt(err error) EncryptOption {
	return errorEncryptOption{
		err: err,
	}
}

type errorEncryptOption struct {
	err error
}

func (e errorEncryptOption) apply(d *encrypter) error {
	return e.err
}

func validateEncrypt() EncryptOption {
	return validateEncryptOption{}
}

type validateEncryptOption struct{}

func (v validateEncryptOption) apply(e *encrypter) error {
	switch {
	case e.alg == "" && e.key == nil:
		return nil
	case e.alg != "" && e.key != nil:
		return nil
	}

	return ErrInvalidEncryptionAlg
}
