/*
 * paperback: resilient paper backups for the very paranoid
 * Copyright (C) 2018 Aleksa Sarai <cyphar@cyphar.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package shamir

import (
	"encoding/base64"
	"encoding/json"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
)

// schemaVersion is the version of the internal secret schema we are using.
// This is detached from the other versions in paperback because this library
// can be used separately.
const schemaVersion = 0x00

// secretFormat is the internal representation of the secret we share. This
// includes the users secret (obviously) but also includes the private key used
// for signing of the shards.
type secretFormat struct {
	Version byte
	Key     ed25519.PrivateKey
	Data    []byte
}

// wireSecret is the on-wire representation of our secret.
type wireSecretFormat struct {
	Version byte   `json:"v"`
	Key     string `json:"k"`
	Data    string `json:"s"`
}

// toWireSecret converts a secret to its wire representation.
func (s secretFormat) wireSecretFormat() wireSecretFormat {
	return wireSecretFormat{
		Version: s.Version,
		Key:     base64.StdEncoding.EncodeToString(s.Key),
		Data:    base64.StdEncoding.EncodeToString(s.Data),
	}
}

// toSecret converts a wireSecret to it's normal representation.
func (ws wireSecretFormat) secretFormat() (secretFormat, error) {
	key, err := base64.StdEncoding.DecodeString(ws.Key)
	if err != nil {
		return secretFormat{}, errors.Wrap(err, "decode key string")
	}
	data, err := base64.StdEncoding.DecodeString(ws.Data)
	if err != nil {
		return secretFormat{}, errors.Wrap(err, "decode data")
	}
	return secretFormat{
		Version: ws.Version,
		Key:     key,
		Data:    data,
	}, nil
}

// MarshalJSON returns the JSON encoding of the secret.
func (s secretFormat) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.wireSecretFormat())
}

// UnmarshalJSON fills the secret with the given data.
func (s *secretFormat) UnmarshalJSON(data []byte) error {
	var ws wireSecretFormat
	if err := json.Unmarshal(data, &ws); err != nil {
		return errors.Wrap(err, "unmarshal wire format")
	}
	newS, err := ws.secretFormat()
	if err != nil {
		return errors.Wrap(err, "convert to internal")
	}
	*s = newS
	return nil
}
