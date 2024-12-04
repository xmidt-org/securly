// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package securly

import (
	"io/fs"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/xmidt-org/securly/internal/wire"
)

func mapEncAlg(alg string) (jwa.KeyEncryptionAlgorithm, error) {
	list := jwa.KeyEncryptionAlgorithms()
	for _, v := range list {
		if v.String() == alg {
			return v, nil
		}
	}

	return "", ErrInvalidEncryptionAlg
}

func msgFromWire(buf []byte) (*Message, error) {
	var wm wire.Message

	_, err := wm.UnmarshalMsg(buf)
	if err != nil {
		return nil, err
	}

	resp, err := encryptionFromWire(wm.Response)
	if err != nil {
		return nil, err
	}

	msg := Message{
		Payload:  wm.Payload,
		Files:    make(map[string]File, len(wm.Files)),
		Response: resp,
	}

	for k, wf := range wm.Files {
		msg.Files[k] = File{
			Data:    wf.Data,
			Mode:    fs.FileMode(wf.Mode),
			ModTime: wf.ModTime,
			Owner:   wf.Owner,
			UID:     wf.UID,
			Group:   wf.Group,
			GID:     wf.GID,
		}
	}

	return &msg, nil
}

func encryptionFromWire(w *wire.Encryption) (*Encryption, error) {
	if w == nil {
		return nil, nil
	}

	alg, err := mapEncAlg(w.Alg)
	if err != nil {
		return nil, err
	}

	key, err := jwk.ParseKey([]byte(w.Key))
	if err != nil {
		return nil, err
	}

	return &Encryption{
		Alg: alg,
		Key: key,
	}, nil
}

func sanitize(b []byte, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}

	return b, nil
}
