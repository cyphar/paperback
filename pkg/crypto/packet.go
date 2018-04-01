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

package crypto

import (
	"encoding/base64"
	"encoding/json"

	"github.com/pkg/errors"
)

// ExtraData is the schema for our additional data that we use with
// ChaCha20-Poly1305. It is the unencrypted portion of the data, and contains
// the version of the schema, and any custom headers.
type ExtraData struct {
	Headers map[string]string `json:"hdr"`
}

// Packet is the wire format we use for ciphertext. It's encoded as JSON, and
// contains the {nonce, ciphertext, additional data} tuple
// that makes up an AEAD message.
type Packet struct {
	Nonce      []byte
	Ciphertext []byte
	Extra      ExtraData
}

// wirePacket is an internal struct that represents the *real* wire format for
// the JSON object for Packet. It has identical contents but the types are
// changed from their semantic value ([]byte for instance) to the more
// efficient representation (base64-encoded strings).
type wirePacket struct {
	Nonce      string    `json:"n"`
	Ciphertext string    `json:"d"`
	Extra      ExtraData `json:"ad"`
}

// toWirePacket converts a Packet to the wirePacket version of it. This is done
// losslessly.
func (p Packet) wirePacket() wirePacket {
	return wirePacket{
		Nonce:      base64.StdEncoding.EncodeToString(p.Nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(p.Ciphertext),
		Extra:      p.Extra,
	}
}

// toPacket converts a wirePacket back to the exportable Packet version. This
// is done losslessly.
func (wp wirePacket) packet() (Packet, error) {
	nonce, err := base64.StdEncoding.DecodeString(wp.Nonce)
	if err != nil {
		return Packet{}, errors.Wrap(err, "decode nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(wp.Ciphertext)
	if err != nil {
		return Packet{}, errors.Wrap(err, "decode ciphertext")
	}
	return Packet{
		Nonce:      nonce,
		Ciphertext: ciphertext,
		Extra:      wp.Extra,
	}, nil
}

// MarshalJSON implements the JSON Marshaler interface for our wire format.
func (p Packet) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.wirePacket())
}

// UnmarshalJSON implements the JSON Unmarshaler interface for our wire format.
func (p *Packet) UnmarshalJSON(data []byte) error {
	var wp wirePacket
	if err := json.Unmarshal(data, &wp); err != nil {
		return errors.Wrap(err, "unmarshal wire packet")
	}
	newP, err := wp.packet()
	if err != nil {
		return errors.Wrap(err, "convert from wire packet")
	}
	*p = newP
	return nil
}
