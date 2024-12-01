// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import "errors"

var (
	ErrInvalidPayload       = errors.New("invalid payload")
	ErrInvalidSHA           = errors.New("invalid SHA")
	ErrInvalidSignAlg       = errors.New("invalid signature algorithm")
	ErrInvalidEncryptionAlg = errors.New("invalid encryption algorithm")
)
