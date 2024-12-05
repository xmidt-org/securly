// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

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
	"github.com/xmidt-org/securly/internal/wire"
)

// Message is a secure message.
type Message struct {
	// Payload is the main payload of the message.
	Payload []byte

	// Files is a map of filenames to file data.  When sent over the wire, the
	// file signatures are sent and validated to ensure the files are not
	// tampered with.
	Files map[string]File

	// Response is the instructions for how to encrypt the response, if that is
	// required.
	Response *Encryption
}

// A File describes a single file.
type File struct {
	// Data is the file content.
	Data []byte

	// Size is the file size.  Note that the data slice may not be the full file
	// content.
	Size int64

	// Mode is the file mode.
	Mode fs.FileMode

	// ModTime is the file modification time.
	ModTime time.Time

	// Owner is the file owner.
	Owner string

	// UID is the file owner's User ID.
	UID uint32

	// Group is the file group.
	Group string

	// GID is the file group's Group ID.
	GID uint32
}

// Encryption is the instructions for how to encrypt the response.
type Encryption struct {
	// Alg is the algorithm used to encrypt the payload.
	Alg jwa.KeyEncryptionAlgorithm

	// Key is the key used to encrypt the payload.
	Key jwk.Key
}

// Encode converts a Message into a slice of bytes and signs it using the
// provided options.
func (m Message) Encode(opts ...EncodeOption) ([]byte, error) {
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

// toWire converts a Message into a wire.Message.
func (m Message) toWire() ([]byte, error) {
	enc, err := m.Response.toWire()
	if err != nil {
		return nil, err
	}

	msg := wire.Message{
		Payload:  m.Payload,
		Response: enc,
		Files:    make(map[string]wire.File, len(m.Files)),
	}

	for filename, filedata := range m.Files {
		msg.Files[filename] = filedata.toWire()
	}

	return sanitize(msg.MarshalMsg(nil))
}

//------------------------------------------------------------------------------

func (f File) toWire() wire.File {
	return wire.File{
		Data:    f.Data,
		Size:    f.Size,
		Mode:    uint32(f.Mode),
		ModTime: f.ModTime,
		Owner:   f.Owner,
		UID:     f.UID,
		Group:   f.Group,
		GID:     f.GID,
	}
}

// toWire converts an Encryption into a wire.Response.
func (e *Encryption) toWire() (*wire.Encryption, error) {
	if e == nil {
		return nil, nil
	}

	if e.Alg == "" && e.Key == nil {
		return nil, nil
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(e.Key); err != nil {
		return nil, err
	}

	return &wire.Encryption{
		Alg: e.Alg.String(),
		Key: buf.String(),
	}, nil
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
