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
	"fmt"
	"reflect"
	"testing"
)

// TestSplitCombineAll does the most simple thing -- it just checks that with
// all of the shares the secret can be reconstructed (even though this usually
// is more shares than needed).
func TestSplitCombineAll(t *testing.T) {
	testSplitCombineHelper(t, func(t *testing.T, secret []byte, shares []Share) {
		recovered, err := Combine(shares...)
		if err != nil {
			t.Errorf("combining shares failed unexpectedly: %v", err)
		} else if !reflect.DeepEqual(recovered, secret) {
			t.Errorf("combined share doesn't match: expected %v got %v", secret, recovered)
		}
	})
}

// TestSplitCombinePartial checks tha the secret can/cannot be reconstructured
// given different random subsets of the shares returned by Split. It doesn't
// check what happens if we have "enough" but some are duplicates.
func TestSplitCombinePartial(t *testing.T) {
	secretIdx := 0
	testSplitCombineHelper(t, func(t *testing.T, secret []byte, shares []Share) {
		for k := 0; k < len(shares); k++ {
			tn := fmt.Sprintf("subshares_n=%d_secret=%d", k, secretIdx)
			t.Run(tn, func(t *testing.T) {
				shuffleShares(shares)
				subShares := shares[:k]
				// Make sure that in both partial cases we actually get what we want.
				recovered, err := Combine(subShares...)
				if uint(k) < shares[0].Meta.K {
					if err != ErrCombineTooFewShares {
						t.Errorf("expected to get ErrCombineTooFewShares on recombination: got %v", err)
					}
				} else {
					if err != nil {
						t.Errorf("combining shares failed unexpectedly: %v", err)
					} else if !reflect.DeepEqual(recovered, secret) {
						t.Errorf("combined share doesn't match: expected %v got %v", secret, recovered)
					}
				}
			})
			secretIdx++
		}
	})
}

// TestSplitExtendCombine checks to make sure that the shares which are
// generated separately from Split using Extend are compatible with the
// original shares (and can reconstruct the secret on their own).
//
// Extend is quite CPU-intensive so we test much fewer cases.
func TestSplitExtendCombine(t *testing.T) {
	// Test only a few (k,n) combinations.
	schemes := []struct{ k, n uint }{
		{2, 2},
		{2, 3},
		{2, 4},
		{4, 4},
		{4, 7},
		{7, 7},
		{7, 8},
		{7, 12},
		{8, 9},
		// TODO: Re-enable this, but it makes the tests run too long.
		//{14, 15},
	}
	for _, scheme := range schemes {
		k, n := scheme.k, scheme.n
		tn := fmt.Sprintf("split_extend_combine_k=%d_n=%d", k, n)
		t.Run(tn, func(t *testing.T) {
			for _, secret := range secretVectors {
				shares, err := Split(uint(k), uint(n), secret)
				if err != nil {
					t.Fatalf("failed to split secret(k=%d, n=%d): %v", k, n, err)
				}
				shuffleShares(shares)
				subShares := shares[:k]

				// Construct some new shares.
				newShares, err := Extend(2*shares[0].Meta.K, subShares...)
				if uint(k) < shares[0].Meta.K {
					if err == nil {
						t.Fatalf("expected to get an error when extending shares: %v", err)
					}
					continue
				} else {
					if err != nil {
						t.Fatalf("extending shares failed unexpectedly: %v", err)
					}
				}

				// Make sure that they're compatible with the old shares and
				// can be used by themselves.
				for _, kk := range []uint{1, shares[0].Meta.K / 2, shares[0].Meta.K} {
					var tmpShares []Share
					shuffleShares(subShares)
					tmpShares = append(tmpShares, subShares[:shares[0].Meta.K-kk]...)
					shuffleShares(newShares)
					tmpShares = append(tmpShares, newShares[:kk]...)
					recovered, err := Combine(tmpShares...)
					if err != nil {
						t.Errorf("combining shares failed unexpectedly: %v", err)
					} else if !reflect.DeepEqual(recovered, secret) {
						t.Errorf("combined share doesn't match: expected %v got %v", secret, recovered)
					}
				}
			}
		})
	}
}
