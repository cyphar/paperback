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

// Package shamir implements Shamir Secret Sharing[1] for arbitrary blobs of
// data. It uses modular arithmetic with a randomly generated prime, which is
// then published alongside the data itself. The "Share" structure produced by
// shamir can be serialised to JSON, and includes all of the important metadata
// about how to reconstruct the secret. Each chunk of the secret uses a
// separate polynomial which protects against other attacks. Note that the
// secret *length* is not kept secret in this scheme (in fact, it's published
// in the Share metadata). If you wish to obscure the secret length, add extra
// padding to the secret provided to shamir.Split.
//
// [1]: Shamir, Adi (1979), "How to share a secret",
//      Communications of the ACM, 22 (11): 612–613,
//      doi:10.1145/359168.359176.
package shamir

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/cyphar/paperback/pkg/polynomial"
)

// DefaultBlockSize is the block size (in bytes) used by default.
const DefaultBlockSize = 16

// Set of errors returned by this package.
var (
	// ErrNotPrime is returned if the prime configured is not actually a prime,
	// and thus attempting to construct a share using it is not safe (and may
	// not even be mathematically recoverable).
	ErrNotPrime = errors.New("'prime' used for secret sharing is not a prime")

	// ErrPrimeTooSmall is returned when the configured prime is too small for
	// the block size. In order for the secret to be recoverable, every
	// possible block value must be smaller than the prime used for the finite
	// field.
	ErrPrimeTooSmall = errors.New("prime is too small for given block size")

	// ErrSplitTooFewShares is returned when the number of shares being
	// generated is not enough for the (k, n) threshold to be recoverable.
	ErrSplitTooFewShares = errors.New("too few shares generated for provided k-threshold")

	// ErrSplitNoShares is returned when the k-threshold is zero.
	ErrSplitNoShares = errors.New("k-threshold cannot be zero")

	// ErrCombineTooFewShares is returned when there are not enough shares
	// present in order to reconstruct the original secret.
	ErrCombineTooFewShares = errors.New("too few shares present to reconstruct secret")

	// ErrCombineMismatchShares is returned when shamir detects that the shares
	// provided are not from the same secret.
	ErrCombineMismatchShares = errors.New("provided shares do not come from the same secret")

	// ErrCombineWrongSize is returned when the reconstruction succeeded for
	// the share, but the size of the share is not the expected size.
	// TODO: We should add a checksum for the share, so we can also check that.
	ErrCombineWrongSize = errors.New("reconstructed share is the wrong size")
)

// maxBlockValue is the max value that can be stored in a block of the
// given size. This is equivalent to (2**(8*size)-1) or (256**size-1).
func maxBlockValue(size uint) *big.Int {
	v := big.NewInt(1)
	v.Lsh(v, 8*size)
	v.Sub(v, big.NewInt(1))
	return v
}

// blockBytes takes a given slice of bytes and splits it into blocks of the
// given size. The trailing block is *not* zero-padded and is instead
// zero-padded.
func blockBytes(data []byte, size uint) [][]byte {
	var blocks [][]byte
	dataLen := uint(len(data))
	for i := uint(0); i < dataLen; i += size {
		end := i + size
		if end > dataLen {
			end = dataLen
		}
		blocks = append(blocks, data[i:end])
	}
	return blocks
}

// constructShare creates a new share (with a random x-coordinate) from a given
// polynomial slice that corresponds to a secret's chunks. The prime is taken
// from the provided ShareMeta (which is embedded in the returned Share).
func constructShare(meta ShareMeta, polys []polynomial.Polynomial) (Share, error) {
	// Compute the polynomial values for the share.
	x, err := rand.Int(rand.Reader, meta.P)
	if err != nil {
		return Share{}, err
	}
	ys := make([]*big.Int, len(polys))
	for j, poly := range polys {
		y, err := poly.EvaluateMod(x, meta.P)
		if err != nil {
			return Share{}, err
		}
		ys[j] = y
	}

	// We now have the share.
	return Share{
		Meta: meta,
		X:    x,
		Ys:   ys,
	}, nil
}

// Split constructs a (k, n) threshold scheme with the given secret, and thus
// produces n Shares where only k shares are required to reconstruct the
// original secret.
func Split(k, n uint, secret []byte) ([]Share, error) {
	// Argument checks.
	if k > n {
		return nil, ErrSplitTooFewShares
	}
	if k < 1 {
		return nil, ErrSplitNoShares
	}

	// Generate our prime.
	blockSize := uint(DefaultBlockSize)
	prime, err := rand.Prime(rand.Reader, int(8*blockSize+1))
	if err != nil {
		return nil, err
	}

	// Sanity checks for the generated prime.
	if !prime.ProbablyPrime(80) {
		return nil, ErrNotPrime
	}
	if prime.Cmp(maxBlockValue(blockSize)) <= 0 {
		return nil, ErrPrimeTooSmall
	}

	// First we split the secret into blockSize-sized blocks. Each block is
	// handled as a separate Shamir secret, but they have the same X
	// coordinate. We also generate a new Polynomial for each block (this is
	// required for security).
	var secretPolys []polynomial.Polynomial
	for _, block := range blockBytes(secret, blockSize) {
		poly, err := polynomial.RandomPolynomial(k-1, prime)
		if err != nil {
			return nil, err
		}
		poly.SetConst(big.NewInt(0).SetBytes(block))
		secretPolys = append(secretPolys, poly)
	}

	// Each share shares the same metadata.
	meta := ShareMeta{
		S:  uint(len(secret)),
		BS: blockSize,
		P:  prime,
		K:  k,
	}

	// Now we construct each share.
	var shares []Share
	for i := uint(0); i < n; i++ {
		share, err := constructShare(meta, secretPolys)
		if err != nil {
			return nil, err
		}
		shares = append(shares, share)
	}
	return shares, nil
}

// combineSharePoints collects all of the given shares, does some sanity
// checking on them, and then produces a k-set of points for each chunk stored
// in the secret. The points are then usable by Combine or Extend for
// interpolation purposes. An error is returned if the shares are malformed or
// otherwise incorrect.
func combineSharePoints(shares []Share) ([][]polynomial.Point, ShareMeta, error) {
	if len(shares) < 1 {
		return nil, ShareMeta{}, ErrCombineTooFewShares
	}

	// Apply checks to ensure that the shares are not mismatched, as well as
	// figure out how many unique "usable" shares are available.
	shareMap := map[string]int{}
	numBlocks := len(shares[0].Ys)
	for idx, share := range shares {
		// Must have identical metadata.
		if !share.Meta.Equal(shares[0].Meta) {
			return nil, ShareMeta{}, ErrCombineMismatchShares
		}
		// Must have equal numbers of parts.
		if len(share.Ys) != numBlocks {
			return nil, ShareMeta{}, ErrCombineMismatchShares
		}
		// Keep track of unique "usable" shares and whether duplicates Xs are
		// identical in other respects.
		shareKey := share.X.String()
		if oldIdx, ok := shareMap[shareKey]; !ok {
			shareMap[shareKey] = idx
		} else if !share.Equal(shares[oldIdx]) {
			return nil, ShareMeta{}, ErrCombineMismatchShares
		}
	}

	// Get the "usable" shares.
	var usableShares []Share
	for _, idx := range shareMap {
		usableShares = append(usableShares, shares[idx])
	}
	shares = usableShares

	// Do we have enough usable shares?
	meta := shares[0].Meta
	if len(shares) < int(meta.K) {
		return nil, ShareMeta{}, ErrCombineTooFewShares
	}
	shares = shares[:meta.K]

	// Get the set of points for each chunk.
	chunkedPoints := make([][]polynomial.Point, numBlocks)
	for i := range chunkedPoints {
		var points []polynomial.Point
		for _, share := range shares {
			points = append(points, polynomial.Point{
				X: share.X,
				Y: share.Ys[i],
			})
		}
		chunkedPoints[i] = points
	}
	return chunkedPoints, meta, nil
}

// Combine takes k Shares in an (k, n) threshold scheme and derives the secret
// associated with the shares. If the shares are malformed or do not correspond
// to the same secret, an error is returned.
func Combine(shares ...Share) ([]byte, error) {
	// Get the set of points of each chunk.
	chunkedPoints, meta, err := combineSharePoints(shares)
	if err != nil {
		return nil, err
	}

	// Interpolate the constant in each of the chunks, to get the secret.
	chunks := make([]*big.Int, len(chunkedPoints))
	for i, points := range chunkedPoints {
		chunk, err := polynomial.InterpolateConst(meta.K-1, meta.P, points...)
		if err != nil {
			return nil, err
		}
		chunks[i] = chunk
	}

	// Now get the secret from the byte representation.
	var secret []byte
	for idx, chunk := range chunks {
		// Make sure that the secret chunk we reconstruct is the correct size.
		// We assume it's the blocksize, otherwise it's size (mod blocksize).
		minLength := meta.BS
		if idx == len(chunks)-1 {
			minLength = meta.S % meta.BS
		}
		secret = append(secret, paddedBigint(chunk, minLength)...)
	}
	if uint(len(secret)) != meta.S {
		err = ErrCombineWrongSize
	}
	return secret, err
}

// Extend takes a given set of shares and constructs n additional shares which
// are compatible with the ones provided. This allows for the "recovery" of any
// lost shares while k shares are still available (note that this
// implementation generates random X-coordinates, so the "recovered" shares are
// almost certainly different from the originally lost shares). The value of n
// is *not* limited by the original n-value used when Split-ing the secret.
func Extend(n uint, shares ...Share) ([]Share, error) {
	// Get the set of points for each chunk.
	chunkedPoints, meta, err := combineSharePoints(shares)
	if err != nil {
		return nil, err
	}

	// Interpolate the entire polynomial so we can construct additional shares.
	polys := make([]polynomial.Polynomial, len(chunkedPoints))
	for i, points := range chunkedPoints {
		poly, err := polynomial.Interpolate(meta.K-1, meta.P, points...)
		if err != nil {
			return nil, err
		}
		polys[i] = poly
	}

	// Now we construct each share.
	var newShares []Share
	for i := uint(0); i < n; i++ {
		// TODO: While very unlikely, we should ensure that we don't generate
		//       any duplicate shares here. Otherwise we may end up giving a
		//       "false sense of redundancy" to the caller.
		newShare, err := constructShare(meta, polys)
		if err != nil {
			return nil, err
		}
		newShares = append(newShares, newShare)
	}
	return newShares, nil
}
