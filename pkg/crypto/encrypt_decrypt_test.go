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
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// TestEncryptDecrypt just does a bunch of randomised round-trip testing,
// making sure that encryption is done correctly.
func TestEncryptDecrypt(t *testing.T) {
	testEncryptDecryptHelper(t, func(t *testing.T, plain []byte, headers map[string]string) {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("generate key failed: %v", err)
		}

		// Encrypt.
		cipher, err := Encrypt(plain, key, headers)
		if err != nil {
			t.Fatalf("encrypting document failed: %v", err)
		}

		// Make sure that the ciphertext is different from the plaintext.
		if bytes.Equal(cipher.Ciphertext, plain) {
			t.Errorf("encrypted ciphertext is equal to the plaintext!")
		}
		if bytes.Contains(cipher.Ciphertext, plain) {
			t.Errorf("encrypted ciphertext contains the plaintext!")
		}

		// Simulate a round-trip through JSON.
		cipherBytes, err := json.Marshal(cipher)
		if err != nil {
			t.Fatalf("marshal encrypted document failed: %v", err)
		}
		var cipherCopy Packet
		if err := json.Unmarshal(cipherBytes, &cipherCopy); err != nil {
			t.Fatalf("unmarshal encrypted document failed: %v", err)
		}
		if !reflect.DeepEqual(cipher, cipherCopy) {
			t.Errorf("packet round-trip through json wasn't lossless")
		}

		// Decrypt.
		plainCopy, headersCopy, err := Decrypt(cipherCopy, key)
		if err != nil {
			t.Fatalf("decrypting document failed: %v", err)
		}

		// Make sure everything is as expected.
		if !bytes.Equal(plainCopy, plain) {
			t.Errorf("decrypted document not equal to original: %v != %v", plainCopy, plain)
		}
		if !reflect.DeepEqual(headersCopy, headers) {
			t.Errorf("authenticated headers not equal to original: %v != %v", headersCopy, headers)
		}
		if !reflect.DeepEqual(headersCopy, cipherCopy.Extra.Headers) {
			t.Errorf("authenticated headers not equal to packet: %v != %v", headersCopy, cipherCopy.Extra.Headers)
		}
	})
}

// TestModificationProtection ensures that the decryption will fail if the
// ciphertext or additional data are modified. This is quite important to test,
// as it makes sure that we can have confidence in our crypto.
func TestModificationProtection(t *testing.T) {
	testEncryptDecryptHelper(t, func(t *testing.T, plain []byte, headers map[string]string) {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("generate key failed: %v", err)
		}

		// Encrypt.
		cipher, err := Encrypt(plain, key, headers)
		if err != nil {
			t.Fatalf("encrypting document failed: %v", err)
		}

		// We now apply a bunch of modifications
		modifiers := []func(t *testing.T, cipher *Packet) error{
			// 1. If the ciphertext is modified in any way, we must fail.

			// Flip a bit somewhere in the ciphertext.
			func(t *testing.T, cipher *Packet) error {
				pos := len(cipher.Ciphertext) / 2
				cipher.Ciphertext[pos] ^= 0x80
				return nil
			},

			// Truncate the ciphertext.
			func(t *testing.T, cipher *Packet) error {
				end := len(cipher.Ciphertext) - 4
				cipher.Ciphertext = cipher.Ciphertext[:end]
				return nil
			},

			// Append to the ciphertext.
			func(t *testing.T, cipher *Packet) error {
				cipher.Ciphertext = append(cipher.Ciphertext, mustRandomBytes(8)...)
				return nil
			},

			// Prepend to the ciphertext.
			func(t *testing.T, cipher *Packet) error {
				cipher.Ciphertext = append(mustRandomBytes(8), cipher.Ciphertext...)
				return nil
			},

			// 2. If the headers or other "extradata" is modified, we must also
			//    fail.

			// Add a header.
			func(t *testing.T, cipher *Packet) error {
				if cipher.Extra.Headers == nil {
					cipher.Extra.Headers = make(map[string]string)
				}
				cipher.Extra.Headers["X-Modified"] = "I-Was-Zero-Cool"
				return nil
			},

			// Remove a header.
			func(t *testing.T, cipher *Packet) error {
				var firstHdr string
				for hdr := range cipher.Extra.Headers {
					firstHdr = hdr
					break
				}
				if len(cipher.Extra.Headers) == 0 {
					// Fallback -- we can't remove headers from an empty map.
					cipher.Extra.Headers = map[string]string{"was": "empty"}
					return nil
				}
				delete(cipher.Extra.Headers, firstHdr)
				return nil
			},

			// Replace a header.
			func(t *testing.T, cipher *Packet) error {
				var firstHdr string
				for hdr := range cipher.Extra.Headers {
					firstHdr = hdr
					break
				}
				if len(cipher.Extra.Headers) == 0 {
					// Fallback -- we can't replace headers from an empty map.
					cipher.Extra.Headers = map[string]string{"was": "empty"}
					return nil
				}
				cipher.Extra.Headers[firstHdr] = "THIS IS A REPLACEMENT"
				return nil
			},

			// 3. Modifying the nonce must also fail.
			func(t *testing.T, cipher *Packet) error {
				newNonce := cipher.Nonce
				for bytes.Equal(newNonce, cipher.Nonce) {
					newNonce = mustRandomBytes(chacha20poly1305.NonceSize)
				}
				cipher.Nonce = newNonce
				return nil
			},
		}

		for modIdx, modifier := range modifiers {
			// Modify a scratchspace version of the packet.
			scratchCipher := copyPacket(cipher)
			if err := modifier(t, &scratchCipher); err != nil {
				t.Errorf("failed to run modifier %d: %v", modIdx, err)
				continue
			}

			// Simulate a round-trip through JSON.
			scratchCipherBytes, err := json.Marshal(scratchCipher)
			if err != nil {
				t.Fatalf("marshal encrypted document failed: %v", err)
			}
			var scratchCipherCopy Packet
			if err := json.Unmarshal(scratchCipherBytes, &scratchCipherCopy); err != nil {
				t.Fatalf("unmarshal encrypted document failed: %v", err)
			}
			if !reflect.DeepEqual(scratchCipher, scratchCipherCopy) {
				t.Errorf("packet round-trip through json wasn't lossless")
			}

			// Attempt to decrypt. It must always fail.
			_, _, err = Decrypt(scratchCipherCopy, key)
			if err == nil {
				t.Errorf("decryption of modifier %d packet succeeded, expected an error", modIdx)
			}
		}
	})
}
