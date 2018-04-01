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
	"crypto/rand"
	"encoding/json"
	"io"
	"io/ioutil"

	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// generateBytes reads a (cryptographically) random source of bytes of the
// given length. Err will only be nil if enough bytes were read from the random
// source.
func generateBytes(size int64) ([]byte, error) {
	data, err := ioutil.ReadAll(&io.LimitedReader{
		R: rand.Reader,
		N: size,
	})
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != size {
		return nil, errors.New("not enough bytes read from random sources")
	}
	return data, nil
}

// GenerateKey generates a new chacha20poly1305 key, sourced from the OS's
// random number generator (and passed through Argon2 to reduce the probability
// of getting a "bad key").
func GenerateKey() ([]byte, error) {
	const seedSize = 128

	seed, err := generateBytes(seedSize)
	if err != nil {
		return nil, errors.Wrap(err, "generate key seed")
	}
	salt, err := generateBytes(seedSize)
	if err != nil {
		return nil, errors.Wrap(err, "generate key salt")
	}

	// These paramters are pretty beefed-up from the recommended parameters in
	// 2018, but this shouldn't be a concern since this is only done during key
	// generation.
	const (
		time    = 8
		memory  = 128 * 1024
		threads = 4
	)
	key := argon2.IDKey(seed, salt, time, memory, threads, chacha20poly1305.KeySize)
	return key, nil
}

// Encrypt constructs a new Packet by taking the plaintext and encrypting it
// with the given key. The additional data in the ChaCha20-Poly1305 AEAD
// construction used is a combination of internal data, and the provided
// headers. If you do not wish to include headers, set them to nil.
func Encrypt(plaintext, key []byte, headers map[string]string) (cipher Packet, err error) {
	cipher.Extra.Headers = headers

	// Generate nonce.
	cipher.Nonce, err = generateBytes(chacha20poly1305.NonceSize)
	if err != nil {
		return cipher, errors.Wrap(err, "generate chacha20poly1305 nonce")
	}

	// Get the AD (as in AEAD) bytes.
	extraBytes, err := json.Marshal(cipher.Extra)
	if err != nil {
		return cipher, errors.Wrap(err, "marshal additional data")
	}

	// Encrypt.
	if len(key) != chacha20poly1305.KeySize {
		return cipher, errors.Errorf("provided chacha20poly1305 key is incorrect size")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return cipher, errors.Wrap(err, "construct chacha20poly1305 aead")
	}
	cipher.Ciphertext = aead.Seal(nil, cipher.Nonce, plaintext, extraBytes)
	return cipher, nil
}

// Decrypt takes a given Packet and then returns the plaintext and associated
// headers. As we use an AEAD scheme, Decrypt will return an error if there is
// an authentication error detected during decryption.
func Decrypt(cipher Packet, key []byte) (plaintext []byte, headers map[string]string, err error) {
	// Get the AD (as in AEAD) bytes.
	extraBytes, err := json.Marshal(cipher.Extra)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshal additional data")
	}

	// Decrypt and check the authentication.
	if len(key) != chacha20poly1305.KeySize {
		return nil, nil, errors.Errorf("provided chacha20poly1305 key is incorrect size")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "construct chacha20poly1305 aead")
	}
	plaintext, err = aead.Open(nil, cipher.Nonce, cipher.Ciphertext, extraBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "decrypt chacha20poly1305")
	}
	return plaintext, cipher.Extra.Headers, nil
}
