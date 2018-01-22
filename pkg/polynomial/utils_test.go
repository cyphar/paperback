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

package polynomial

import (
	"io"
	"math/rand"
	"time"
)

// rng is the global random number generator used for all non-important RNG
// operations in our tests.
var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

// mustRandomBytes returns a slice of random bytes of the given size.
func mustRandomBytes(size uint) []byte {
	bytes := make([]byte, size)
	if _, err := io.ReadFull(rng, bytes); err != nil {
		panic(err)
	}
	return bytes
}

// extendBytes takes a series of byte slices and combines them into a single
// slice, by appending one after the other (using minimal allocations).
func extendBytes(slices ...[]byte) []byte {
	var totalLen int
	for _, slice := range slices {
		totalLen += len(slice)
	}
	result := make([]byte, totalLen)
	var start int
	for _, slice := range slices {
		start += copy(result[start:], slice)
	}
	return result
}
