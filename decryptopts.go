// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// EncodeOption is a functional option for the Instructions constructor.
type DecryptOption interface {
	apply(*decrypter) error
}

func errorDecrypt(err error) DecryptOption {
	return errorDecryptOption{
		err: err,
	}
}

type errorDecryptOption struct {
	err error
}

func (e errorDecryptOption) apply(d *decrypter) error {
	return e.err
}

func DecryptWith(key jwk.Key) DecryptOption {
	return decryptWithOption{
		key: key,
	}
}

func DecryptWithRaw(raw any) DecryptOption {
	key, err := jwk.FromRaw(raw)
	if err != nil {
		return errorDecrypt(err)
	}

	return DecryptWith(key)
}

type decryptWithOption struct {
	key jwk.Key
}

func (k decryptWithOption) apply(dec *decrypter) error {
	dec.key = k.key
	return nil
}

//------------------------------------------------------------------------------

func validateDecrypt() DecryptOption {
	return validateDecryptOption{}
}

type validateDecryptOption struct{}

func (v validateDecryptOption) apply(d *decrypter) error {
	if d.key == nil {
		return fmt.Errorf("key is required")
	}
	return nil
}
