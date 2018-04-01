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
	"fmt"
	"io"
	"testing"
)

// mustRandomBytes returns a slice of random bytes of the given size.
func mustRandomBytes(size uint) []byte {
	bytes := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		panic(err)
	}
	return bytes
}

func testEncryptDecryptHelper(t *testing.T, testFn func(t *testing.T, plain []byte, headers map[string]string)) {
	plainVectors := [][]byte{
		[]byte("Test string vector -- hello world."),
		[]byte("The quick brown fox jumps over the lazy dog."),
		[]byte{'H', 0x00, 'a', 'c', 'k', 0x00, 0xFF, 'T', 'P'},
		mustRandomBytes(64),
		mustRandomBytes(192),
		mustRandomBytes(377),
		mustRandomBytes(855),
	}
	headerVectors := []map[string]string{
		nil,
		{},
		{"test": "hello world!"},
		{"abc": "def", "hij": "k lmnopqrs", "tuv": "wxyz1234"},
		{"war": "peace", "freedom": "slavery", "ignorance": "strength"},
	}

	for pIdx, plain := range plainVectors {
		for hIdx, headers := range headerVectors {
			tn := fmt.Sprintf("Plain:%d_Header:%d", pIdx, hIdx)
			t.Run(tn, func(t *testing.T) {
				testFn(t, plain, headers)
			})
		}
	}
}

func copyPacket(packet Packet) Packet {
	packetBytes, err := json.Marshal(packet)
	if err != nil {
		panic(err)
	}
	var newPacket Packet
	if err := json.Unmarshal(packetBytes, &newPacket); err != nil {
		panic(err)
	}
	return newPacket
}
