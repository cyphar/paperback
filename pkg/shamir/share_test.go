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
	"encoding/json"
	"reflect"
	"testing"
)

// TestShareWireFormatting makes sure that random shares can round-trip through
// JSON.
func TestShareWireFormatting(t *testing.T) {
	testSchemeHelper(t, func(t *testing.T, k, n uint, secret []byte) {
		shares, err := Split(k, n, secret)
		if err != nil {
			t.Fatalf("cannot split secret into (k=%d,n=%d): %v", k, n, err)
		}
		var encodedShares [][]byte

		// We marshal then unmarshal each share.
		for _, share := range shares {
			encoded, err := json.Marshal(share)
			if err != nil {
				t.Fatalf("failed to marshal share %v: %v", share, err)
			}
			encodedShares = append(encodedShares, encoded)
		}
		newShares := make([]Share, len(shares))
		for idx, encoded := range encodedShares {
			err := json.Unmarshal(encoded, &newShares[idx])
			if err != nil {
				t.Fatalf("failed to unmarshal encoded share %v: %v", encoded, err)
			}
		}
		// Make sure each share is identical to the original.
		if !reflect.DeepEqual(shares, newShares) {
			t.Errorf("round-trip doesn't produce idential shares: expected %v got %v", shares, newShares)
		}
	})
}
