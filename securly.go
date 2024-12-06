// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

//go:generate msgp -io=false
//msgp:newtime
//msgp:replace fs.FileMode with:uint32
//msgp:shim jwk.Key as:string using:keyToString/stringToKey
//msgp:shim jwa.KeyEncryptionAlgorithm as:string using:jwaToString/stringToJWA

// Package securly provides functionality for securely encoding, decoding,
// encrypting and decrypting messages sent over the wire.
//
// The main types in this package are:
// - Message: Represents a secure message with a payload and optional files.
// - Encryption: Contains instructions for how to encrypt the response.
//
// The package relies on the https://github.com/lestrrat-go/jwx/v2 library for
// JSON Web Encryption (JWE) and JSON Web Key (JWK) handling.
//
// # Usage:
//
// To encode a message:
//
//	msg := securly.Message{
//	    Payload: []byte("your payload"),
//	    Files: map[string][]byte{
//	        "file1.txt": []byte("file content"),
//	    },
//	}
//	encoded, err := msg.Encode()
//	if err != nil {
//	    log.Fatalf("failed to encode message: %v", err)
//	}
//
// To encrypt a message:
//
//	encrypted, err := msg.Encrypt()
//	if err != nil {
//	    log.Fatalf("failed to encrypt message: %v", err)
//	}
package securly

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// Message is a secure message.
type Message struct {
	// Payload is the main payload of the message.
	Payload []byte `msg:"payload"`

	// Files is a map of filenames to file data.  When sent over the wire, the
	// file signatures are sent and validated to ensure the files are not
	// tampered with.
	Files map[string]File `msg:"files,omitempty"`

	// Response is the instructions for how to encrypt the response, if that is
	// required.
	Response *Encryption `msg:"response,omitzero"`
}

// A File describes a single file.
type File struct {
	// Data is the file content.
	Data []byte `msg:"data"`

	// Size is the file size.  Note that the data slice may not be the full file
	// content.
	Size int64 `msg:"size,omitempty"`

	// Mode is the file mode.
	Mode fs.FileMode `msg:"mode,omitempty"`

	// ModTime is the file modification time.
	ModTime time.Time `msg:"modtime,omitempty"`

	// Owner is the file owner.
	Owner string `msg:"owner,omitempty"`

	// UID is the file owner's User ID.
	UID uint32 `msg:"uid,omitempty"`

	// Group is the file group.
	Group string `msg:"group,omitempty"`

	// GID is the file group's Group ID.
	GID uint32 `msg:"gid,omitempty"`
}

// Encryption is the instructions for how to encrypt the response.
type Encryption struct {
	// Alg is the algorithm used to encrypt the payload.
	Alg jwa.KeyEncryptionAlgorithm `msg:"alg"`

	// Key is the key used to encrypt the payload.
	Key jwk.Key `msg:"key"`
}

// Encode converts a Message into a slice of bytes based on the data present in
// the Reponse field.  If the Response field is nil, the message is encoded as
// an unsigned message.  If the Response field is present, the message is
// encrypted using the provided instructions.
func (m Message) Encode() (data []byte, isEncrypted bool, err error) {
	if m.Response.IsZero() {
		data, err = m.Sign(NoSignature())
		return
	}

	data, err = m.Encrypt()
	isEncrypted = true
	return
}

// Sign converts a Message into a slice of bytes and signs it using the
// provided options.
func (m Message) Sign(opts ...SignOption) ([]byte, error) {
	enc, err := newEncoder(opts...)
	if err != nil {
		return nil, err
	}

	return enc.encode(m)
}

// Encrypt encrypts the message using the provided options.
func (m Message) Encrypt(opts ...EncryptOption) ([]byte, error) {
	enc, err := newEncrypter(opts...)
	if err != nil {
		return nil, err
	}

	return enc.encrypt(m)
}

//------------------------------------------------------------------------------

func (e *Encryption) IsZero() bool {
	return e == nil || (e.Alg == "" && e.Key == nil)
}

func (e *Encryption) safeInTheClear() error {
	if e == nil {
		return nil
	}

	if e.Alg == "" && e.Key == nil {
		return nil
	}

	// Symmetric keys are NOT safe to send in the clear.
	if e.Alg.IsSymmetric() {
		return ErrUnsafeAlgorithm
	}

	return nil
}

func (e *Encryption) withKey() (jwe.EncryptDecryptOption, error) {
	if e == nil || (e.Alg == "" && e.Key == nil) {
		return nil, nil
	}

	if e.Alg == "" || e.Key == nil {
		return nil, ErrInvalidEncryptionAlg
	}

	return jwe.WithKey(e.Alg, e.Key), nil
}

func (e *Encryption) verify() error {
	key, err := e.withKey()
	if err != nil {
		return err
	}

	if key == nil {
		return nil
	}

	// Create a test payload
	testPayload := []byte("test payload")

	// Encrypt the test payload & if possible, we're good.
	if _, err := jwe.Encrypt(testPayload, key); err != nil {
		return errors.Join(err, ErrInvalidEncryptionAlg)
	}

	return nil
}

//------------------------------------------------------------------------------

func keyToString(key jwk.Key) string {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(key); err != nil {
		return ""
	}

	return buf.String()
}

func stringToKey(s string) jwk.Key {
	key, err := jwk.ParseKey([]byte(s))
	if err != nil {
		return nil
	}

	return key
}

func jwaToString(alg jwa.KeyEncryptionAlgorithm) string {
	return alg.String()
}

func stringToJWA(s string) jwa.KeyEncryptionAlgorithm {
	list := jwa.KeyEncryptionAlgorithms()
	for _, v := range list {
		if v.String() == s {
			return v
		}
	}

	return ""
}

func sanitize(b []byte, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}

	return b, nil
}
