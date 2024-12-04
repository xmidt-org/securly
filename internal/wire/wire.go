// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

//go:generate msgp
//msgp:newtime

// Package wire provides the data structures that are sent over the wire.
// The data structures are encoded and decoded using MessagePack.
//
// The wire structures are isolated from the rest of the code to ensure that
// the wire format is stable and can be used by other services.  It also
// prevents unintended values from being used from a new version of the
// protocol or malicious values from being used to exploit the system.
package wire

import "time"

// Outer is what is put in the WRP payload.
type Outer struct {
	// JWS is the JWS that is used to sign the inner payload.
	JWS string `msg:"jws"`

	// Data is the useful data that is sent over the wire.  It is SHA'd and
	// the SHA is put in the JWS.  This keeps the JWS small and efficient
	// since the JWS is base64 encoded and this data is not.  The data is
	// SHA'd to ensure that the data is not tampered with.
	//
	// The data is a slice of bytes and not the Message struct to ensure that
	// the SHA data is consistent everywhere.
	Data []byte `msg:"data"`
}

// Message is the useful data that is sent over the wire.  It is SHA'd and
// the SHA is put in the JWS.
type Message struct {
	// Payload is the externally defined payload.
	Payload []byte `msg:"payload"`

	// Files is a map of file names to file data to send over the wire.
	Files map[string]File `msg:"files,omitempty"`

	// Response is the optional response to encrypt.
	Response *Encryption `msg:"response,omitempty"`
}

// File is a file that is sent over the wire.
type File struct {
	// Data is the file data.
	Data []byte `msg:"data"`

	// Mode is the file mode.
	Mode uint32 `msg:"mode,omitempty"`

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

// Inner is the payload of the JWS in the Outer.
type Inner struct {
	// Alg is the algorithm used to generate the SHA.
	Alg string `msg:"alg"`

	// SHA is the SHA of the message data.
	SHA []byte `msg:"sha"`
}

// Encryption defines the encryption response.
type Encryption struct {
	// Alg is the algorithm used to encrypt the payload.
	Alg string `msg:"alg"`

	// Key is the key used to encrypt the payload.
	Key string `msg:"key"`
}
