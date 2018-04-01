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

package schema

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/cyphar/paperback/internal/version"
	"github.com/cyphar/paperback/pkg/crypto"
	"github.com/cyphar/paperback/pkg/shamir"
)

// Shard is a wrapped version of shamir.Share, containing the version data for
// the current schema. We don't bother making a "deep" clone of the structure
// here, because we control the shamir package and so won't accidentally break
// the schema. The encrypted variant can be created using Encrypt().
type Shard struct {
	Version string       `json:"version"`
	Inner   shamir.Share `json:"share"`
}

// NewShard constructs a new schema.Shard from a shamir.Share, using the
// default values for all other fields. This is the recommended way of creating
// a new Shard.
func NewShard(share shamir.Share) Shard {
	return Shard{
		Version: version.Version,
		Inner:   share,
	}
}

// EncryptedShard is the type of the armored and OpenPGP encrypted blob that is
// published as the shard key payload. It can be decrypted using Decrypt. This
// is just an alias for []byte but is used for type-safety.
type EncryptedShard []byte

// Encrypt returns the encrypted version of the given shard (using the provided
// key) of type EncryptedShard. This is the recommended way of handling
// encryption of shards as this way it will remain consistent.
func (s Shard) Encrypt(key []byte) (EncryptedShard, error) {
	// Construct the buffer with the plaintext shard.
	shardBytes, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	shardBuffer := bytes.NewBuffer(shardBytes)

	// Encrypt the shard.
	encryptedShard, err := crypto.Encrypt(shardBuffer, key)
	if err != nil {
		return nil, err
	}
	return encryptedShard, nil
}

// Decrypt returns the decrypted version (or an error) of the given shard using
// the given key. This is the recommended way of handling decryption of shards
// as this way all users will remain consistent.
func (es EncryptedShard) Decrypt(key []byte) (Shard, error) {
	// Decrypt the shard.
	encryptedShardBuffer := bytes.NewBuffer(es)
	shardBytes, err := crypto.Decrypt(encryptedShardBuffer, key)
	if err != nil {
		return Shard{}, err
	}

	// Unmarshal the JSON.
	var shard Shard
	if err := json.Unmarshal(shardBytes, &shard); err != nil {
		return Shard{}, err
	}
	// TODO: Probably should do some sort of crypto verification here, to
	//       ensure that the shard is actually useful.
	return shard, nil
}
