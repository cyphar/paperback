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

package bip39

import (
	"math/bits"
)

// You can re-generate the Go wordlist source from the BIP39 wordlist files
// using 'go generate'. You can also verify that the wordlist is the actual
// BIP39 wordlist by re-downloading it from the BIP repo.
//go:generate ./wordlist_generate.sh data/wordlist_english.txt wordlist_english.go

// bitsPerWord is the number of bits represented by each word. This is directly
// dependent on the size of the wordlist, and is core to a lot of the functions
// of wordlist generation. This allows us to (potentially) swap to a longer
// wordlist in the future, though this is unlikely to happen. It also makes the
// calculations clearer.
var bitsPerWord = bits.Len(wordlistSize - 1)

// reverseWordlist is a reverse-lookup table for the indices of words inside
// the generated wordlist. This is less efficient than a binary search (since
// the wordlist is also ordered), but it's simpler in Go.
var reverseWordlist map[string]uint

func init() {
	reverseWordlist = make(map[string]uint)
	for idx, word := range wordlist {
		reverseWordlist[word] = idx
	}
	if len(reverseWordlist) != wordlistSize {
		panic("bip39 wordlist lookup table is wrong size!")
	}
}
