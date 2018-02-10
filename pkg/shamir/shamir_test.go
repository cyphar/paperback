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
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
)

// TestCombine does the most simple thing -- it just checks that with all of
// the shares the secret can be reconstructed (even though this usually is more
// shares than needed).
func TestCombine(t *testing.T) {
	testSchemeHelper(t, func(t *testing.T, k, n uint, secret []byte) {
		shares, err := Split(k, n, secret)
		if err != nil {
			t.Fatalf("cannot split secret into (k=%d,n=%d): %v", k, n, err)
		}
		recovered, err := Combine(shares...)
		if err != nil {
			t.Errorf("combining shares failed unexpectedly: %v", err)
		} else if !reflect.DeepEqual(recovered, secret) {
			t.Errorf("combined share doesn't match: expected %v got %v", secret, recovered)
		}
	})
}

// TestCombinePartial checks tha the secret can/cannot be reconstructured given
// different random subsets of the shares returned by Split. It doesn't check
// what happens if we have "enough" but some are duplicates.
func TestCombinePartial(t *testing.T) {
	testSchemeHelper(t, func(t *testing.T, k, n uint, secret []byte) {
		shares, err := Split(k, n, secret)
		if err != nil {
			t.Fatalf("cannot split secret into (k=%d,n=%d): %v", k, n, err)
		}
		for k := 0; k < len(shares); k++ {
			shuffleShares(shares)
			subShares := shares[:k]
			// Make sure that in both partial cases we actually get what we want.
			recovered, err := Combine(subShares...)
			if uint(k) < shares[0].Safe.Meta.K {
				if errors.Cause(err) != ErrCombineTooFewShares {
					t.Errorf("expected to get ErrCombineTooFewShares on recombination: got %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("combining shares failed unexpectedly: %v", err)
				} else if !reflect.DeepEqual(recovered, secret) {
					t.Errorf("combined share doesn't match: expected %v got %v", secret, recovered)
				}
			}
		}
	})
}

// TestForgeryProtection ensures that if we intentionally break the signature
// in any way (make it invalid by changing it, modify the struct, change the
// public key, etc) then the combination will fail.
func TestForgeryProtection(t *testing.T) {
	testSchemeHelper(t, func(t *testing.T, k, n uint, secret []byte) {
		// Always generate one extra share since we're going to intentionally
		// break one.
		n++

		// Generate the set of shares.
		shares, err := Split(k, n, secret)
		if err != nil {
			t.Fatalf("failed to split secret(k=%d, n=%d): %v", k, n, err)
		}
		shuffleShares(shares)

		// We now a share share and mutate it. It's very important that we
		// include extra *valid* shares, so that we are sure that the errors we
		// get are *because* of signature failure.
		modifiers := []struct {
			verifyExpected bool // Expected return from Verify.
			modFn          func(t *testing.T, shares []Share) (bad Share, err error)
		}{
			// 1. Data in the share being modified without updating the
			//    signature must fail.

			// Try changing the X value.
			{false, func(t *testing.T, shares []Share) (Share, error) {
				shuffleShares(shares)
				s := &shares[0]

				x, err := rand.Int(rand.Reader, s.Safe.Meta.P)
				if err != nil {
					return Share{}, err
				}
				s.Safe.X = x
				return *s, nil
			}},

			// Try changing the Y values. This is most important because this
			// is fundamentally how cheating is performed.
			{false, func(t *testing.T, shares []Share) (Share, error) {
				shuffleShares(shares)
				s := &shares[0]

				y, err := rand.Int(rand.Reader, s.Safe.Meta.P)
				if err != nil {
					return Share{}, err
				}
				s.Safe.Ys[0] = y
				return *s, nil
			}},

			// Try truncating the Y values.
			{false, func(t *testing.T, shares []Share) (Share, error) {
				shuffleShares(shares)
				s := &shares[0]

				s.Safe.Ys = s.Safe.Ys[:len(s.Safe.Ys)-2]
				return *s, nil
			}},

			// Try appending to the Y values.
			{false, func(t *testing.T, shares []Share) (Share, error) {
				shuffleShares(shares)
				s := &shares[0]

				y, err := rand.Int(rand.Reader, s.Safe.Meta.P)
				if err != nil {
					return Share{}, err
				}
				s.Safe.Ys = append(s.Safe.Ys, y)
				return *s, nil
			}},

			// Try modifying the metadata.
			{false, func(t *testing.T, shares []Share) (Share, error) {
				shuffleShares(shares)
				s := &shares[0]

				prime, err := rand.Prime(rand.Reader, int(8*DefaultBlockSize+1))
				if err != nil {
					return Share{}, err
				}
				s.Safe.Meta.P = prime
				return *s, nil
			}},

			// 2. Signature changed without having the relevant private key
			//    must fail.
			{false, func(t *testing.T, shares []Share) (Share, error) {
				shuffleShares(shares)
				s := &shares[0]

				// Create a new private key and then sign the share.
				publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					return Share{}, err
				}
				if bytes.Equal(publicKey, s.Safe.Meta.PublicKey) {
					return Share{}, fmt.Errorf("new key is identical to old one")
				}
				msg, err := json.Marshal(s.Safe)
				if err != nil {
					return Share{}, err
				}

				// Change the signature.
				newSig := ed25519.Sign(privateKey, msg)
				if bytes.Equal(newSig, s.Signature) {
					return Share{}, fmt.Errorf("new signature is identical to old one")
				}
				s.Signature = newSig
				return *s, nil
			}},

			// 3. Public key changed (and the signature along with it) must
			//    fail, as the keys don't match the other shares. Note that
			//    Verify will *not* fail because the error comes from trying to
			//    combine multiple shares (the share itself is
			//    self-consistent).
			{true, func(t *testing.T, shares []Share) (Share, error) {
				shuffleShares(shares)
				s := &shares[0]

				// Create a new keypair and swap them out.
				publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					return Share{}, err
				}
				s.Safe.Meta.PublicKey = publicKey
				newSig, err := s.Safe.Sign(privateKey)
				if err != nil {
					return Share{}, err
				}
				if bytes.Equal(newSig, s.Signature) {
					return Share{}, fmt.Errorf("new signature is identical to old one")
				}
				s.Signature = newSig
				return *s, nil
			}},

			// 4. Signature changed to a valid signature from another share
			//    must not work (as the entire shard payload is signed).
			{false, func(t *testing.T, shares []Share) (Share, error) {
				shuffleShares(shares)
				s := &shares[0]

				var newSig []byte
				for _, otherShare := range shares[1:] {
					if !bytes.Equal(otherShare.Signature, s.Signature) {
						newSig = otherShare.Signature
						break
					}
				}
				if newSig == nil {
					// What?
					for shareIdx, share := range shares {
						str, _ := json.Marshal(share)
						t.Logf("share %d: %s", shareIdx, str)
					}
					return Share{}, fmt.Errorf("could not find different signature in set")
				}

				s.Signature = newSig
				return *s, nil
			}},
		}

		// Run our modification functions on the shares:
		for modIdx, modifier := range modifiers {
			// Create a scratchspace for modFn which simulates a malicious
			// share set.
			scratchShares := copyShares(shares)
			badShare, err := modifier.modFn(t, scratchShares)
			if err != nil {
				t.Errorf("error while modifying share in modifier %d: %v", modIdx, err)
				continue
			}

			// Combine *must* fail.
			if _, err := Combine(scratchShares...); err == nil {
				t.Errorf("expected combine with modifier %d share to fail", modIdx)
			}
			// Make sure that the error is from verify.
			if good, err := badShare.Safe.Verify(badShare.Signature); err != nil {
				t.Errorf("unexpected error while verifying modifier %d share: %v", modIdx, err)
			} else if good != modifier.verifyExpected {
				t.Errorf("expected verify with modifier %d share to produce %v", modIdx, modifier.verifyExpected)
			}
		}
	})
}

// TestExtendCompatibility checks to make sure that the shares which are
// generated separately from Split using Extend are compatible with the
// original shares (and can reconstruct the secret on their own).
//
// Extend is quite CPU-intensive so we test much fewer cases.
func TestExtendCompatibility(t *testing.T) {
	testSchemeHelper(t, func(t *testing.T, k, n uint, secret []byte) {
		shares, err := Split(k, n, secret)
		if err != nil {
			t.Fatalf("cannot split secret into (k=%d,n=%d): %v", k, n, err)
		}
		shuffleShares(shares)
		subShares := shares[:k]

		// Construct some new shares.
		newShares, err := Extend(2*shares[0].Safe.Meta.K, subShares...)
		if uint(k) < shares[0].Safe.Meta.K {
			if err == nil {
				t.Fatalf("expected to get an error when extending shares: %v", err)
			}
			return
		} else {
			if err != nil {
				t.Fatalf("extending shares failed unexpectedly: %v", err)
			}
		}

		// Make sure that they're compatible with the old shares and
		// can be used by themselves.
		for _, kk := range []uint{1, shares[0].Safe.Meta.K / 2, shares[0].Safe.Meta.K} {
			var tmpShares []Share
			shuffleShares(subShares)
			tmpShares = append(tmpShares, subShares[:shares[0].Safe.Meta.K-kk]...)
			shuffleShares(newShares)
			tmpShares = append(tmpShares, newShares[:kk]...)
			recovered, err := Combine(tmpShares...)
			if err != nil {
				t.Errorf("combining shares failed unexpectedly: %v", err)
			} else if !reflect.DeepEqual(recovered, secret) {
				t.Errorf("combined share doesn't match: expected %v got %v", secret, recovered)
			}
		}
	})
}
