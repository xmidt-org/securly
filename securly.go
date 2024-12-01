// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import "github.com/lestrrat-go/jwx/v2/jwa"

// Message is a secure message.
type Message struct {
	// Files is a map of filenames to file data.  When sent over the wire, the
	// file signatures are sent and validated to ensure the files are not
	// tampered with.
	Files map[string][]byte

	// Payload is the main payload of the message.
	Payload []byte

	// Response is the instructions for how to encrypt the response, if that is
	// required.
	Response *Encrypt
}

// Encrypt is the instructions for how to encrypt the response.
type Encrypt struct {
	// Alg is the algorithm used to encrypt the payload.
	Alg jwa.KeyEncryptionAlgorithm

	// Key is the key used to encrypt the payload.
	Key string
}
