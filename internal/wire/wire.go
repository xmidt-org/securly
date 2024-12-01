// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

//go:generate msgp
package wire

// Outer is what is put in the WRP payload.
type Outer struct {
	// JWS is the JWS that is used to sign the inner payload.
	JWS string `msg:"jws"`

	// Files is a map of file names and their bytes.  By keeping the files
	// separate and only encoding the SHA of the files in the JWS, we can
	// avoid encoding the files in the JWS (base64 encoded) and save quite a bit
	// of space potentially.
	Files map[string][]byte `msg:"files"`
}

// Inner is the payload of the JWS in the Outer.
type Inner struct {
	// Payload is the externally defined payload.
	Payload []byte `msg:"payload"`

	// SHAs is a map of file name to SHA.  This is used to
	// verify the files in the payload.
	SHAs map[string]SHA `msg:"shas"`

	// Encrypt is the optional block if the response should be encrypted.
	Encrypt *Response `msg:"encrypt"`
}

// SHA is the SHA of a file.
type SHA struct {
	// Alg is the algorithm used to generate the SHA.
	Alg string `msg:"alg"`

	// Value is the SHA value.
	Value []byte `msg:"value"`
}

// Response defines the encryption response.
type Response struct {
	// Alg is the algorithm used to encrypt the payload.
	Alg string `msg:"alg"`

	// Key is the key used to encrypt the payload.
	Key string `msg:"key"`
}

// Encrypted is the encrypted form/response of a message.
type Encrypted struct {
	// Payload is the externally defined payload.
	Payload []byte `msg:"payload"`

	// Files is a map of file names to file data to send over the wire.
	Files map[string][]byte `msg:"files"`

	// Encrypt is the optional block if the response should be encrypted.
	Encrypt *Response `msg:"encrypt"`
}
