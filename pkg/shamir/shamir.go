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
// It should be noted that we have added some additional protections to this
// sharing scheme outside of the original outline of Shamir's paper. These
// protections were added as a reaction to the concerns raied by Pieprzyk and
// Zhang[2]. While their paper describes a probabilistic method of protecting
// against "cheating" in secret sharing, we instead take a much simpler
// approach. On the generation of the shards we create an ed25519 keypair and
// sign each shard using that keypair. The public key and signature are stored
// with each shard (this allows for the detection of fraudulent shares by
// checking whether all shares use the same public key and if the signatures
// are valid). The private key is stored as part of the secret -- this allows
// for the set of shares to be extended (if extension were not a needed
// feature, the key could be destroyed rather than stored in the secret to
// prevent forging of shares *after* the secret has been revealed). One major
// benefit of this scheme is that honest participants can identify whose shares
// are fraudulent. The private key used for our cheating prevention is not
// provided to users of this library, to avoid incorrectly re-using the private
// key for message data where the forgability requirements are different.
//
// [1]: Shamir, Adi (1979), "How to share a secret",
//      Communications of the ACM, 22 (11): 612–613,
//      doi:10.1145/359168.359176
// [2]: Pieprzyk J. and Zhang XM. (2002), "Cheating Prevention in Linear Secret
//      Sharing", Lecture Notes in Computer Science, vol 2384.
//      doi:10.1007/3-540-45450-0_9
package shamir

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"reflect"

	"github.com/cyphar/paperback/pkg/polynomial"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
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

	// ErrCombineBadSignature is returned if any of the shares' signatures are
	// invalid for the public key they claim to have been signed with.
	ErrCombineBadSignature = errors.New("some shares have invalid signatures -- this may indicate they were forged")

	// ErrCombineWrongSize is returned when the reconstruction succeeded for
	// the share, but the size of the share is not the expected size.
	// TODO: We should add a checksum for the share, so we can also check that.
	ErrCombineWrongSize = errors.New("reconstructed secret is the wrong size")

	// ErrUnknownSecretSchema is returned when the internal secret's schema
	// representation is not known.
	ErrUnknownSecretSchema = errors.New("reconstructed secret has unknown schema")
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
// from the provided ShareMeta (which is embedded in the returned Share). The
// share is also signed.
func constructShare(meta ShareMeta, polys []polynomial.Polynomial, key ed25519.PrivateKey) (Share, error) {
	// Compute the polynomial values for the share.
	x, err := rand.Int(rand.Reader, meta.P)
	if err != nil {
		return Share{}, errors.Wrap(err, "generate share x")
	}
	ys := make([]*big.Int, len(polys))
	for j, poly := range polys {
		y, err := poly.EvaluateMod(x, meta.P)
		if err != nil {
			return Share{}, errors.Wrapf(err, "evaluate poly %d", j)
		}
		ys[j] = y
	}

	// We now have the share.
	payload := SharePayload{
		Meta: meta,
		X:    x,
		Ys:   ys,
	}
	signature, err := payload.Sign(key)
	if err != nil {
		return Share{}, errors.Wrap(err, "sign payload")
	}
	return Share{
		Safe:      payload,
		Signature: signature,
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
		return nil, errors.Wrap(err, "generate prime field")
	}

	// Sanity checks for the generated prime.
	if !prime.ProbablyPrime(80) {
		return nil, ErrNotPrime
	}
	if prime.Cmp(maxBlockValue(blockSize)) <= 0 {
		return nil, ErrPrimeTooSmall
	}

	// Convert the secret into our internal secret representation, and generate
	// an ed25519 key for said secret. The original secret data is effectively
	// dropped so we don't accidentally use it...
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "generate share validity key")
	}
	secret, err = json.Marshal(secretFormat{
		Version: schemaVersion,
		Key:     privateKey,
		Data:    secret,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal payload")
	}

	// First we split the secret into blockSize-sized blocks. Each block is
	// handled as a separate Shamir secret, but they have the same X
	// coordinate. We also generate a new Polynomial for each block (this is
	// required for security).
	var secretPolys []polynomial.Polynomial
	for _, block := range blockBytes(secret, blockSize) {
		poly, err := polynomial.RandomPolynomial(k-1, prime)
		if err != nil {
			return nil, errors.Wrap(err, "generate random polynomial")
		}
		poly.SetConst(big.NewInt(0).SetBytes(block))
		secretPolys = append(secretPolys, poly)
	}

	// Each share shares the same metadata.
	meta := ShareMeta{
		Size:      uint(len(secret)),
		BlockSize: blockSize,
		P:         prime,
		K:         k,
		PublicKey: publicKey,
	}

	// Now we construct each share.
	var shares []Share
	for i := uint(0); i < n; i++ {
		share, err := constructShare(meta, secretPolys, privateKey)
		if err != nil {
			return nil, errors.Wrapf(err, "construct share %d", i)
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
	shareGroupings := GroupShares(shares)

	// Apply checks to ensure that the shares are not mismatched, as well as
	// figure out how many unique "usable" shares are available.
	shareMap := map[string]int{}
	numBlocks := len(shares[0].Safe.Ys)
	for idx, share := range shares {
		// Must have identical metadata.
		if !reflect.DeepEqual(share.Safe.Meta, shares[0].Safe.Meta) {
			return nil, ShareMeta{}, errors.Wrap(ErrCombineMismatchShares, "mismatch meta")
		}
		// Must have equal numbers of parts.
		if len(share.Safe.Ys) != numBlocks {
			return nil, ShareMeta{}, errors.Wrap(ErrCombineMismatchShares, "mismatch num blocks")
		}
		// Must be in the same logical group (same public key).
		if shareGroupings[idx].GroupIdx != shareGroupings[0].GroupIdx {
			return nil, ShareMeta{}, errors.Wrap(ErrCombineMismatchShares, "mismatch group index")
		}
		// Public key verification should have succeeded.
		if shareGroupings[idx].Bad {
			return nil, ShareMeta{}, errors.Wrap(ErrCombineBadSignature, "check signature")
		}
		// Keep track of unique "usable" shares and whether duplicates Xs are
		// identical in other respects.
		shareKey := share.Safe.X.String()
		if oldIdx, ok := shareMap[shareKey]; !ok {
			shareMap[shareKey] = idx
		} else if !reflect.DeepEqual(share, shares[oldIdx]) {
			return nil, ShareMeta{}, errors.Wrap(ErrCombineMismatchShares, "mismatch duplicate shares")
		}
	}

	// Get the "usable" shares.
	var usableShares []Share
	for _, idx := range shareMap {
		usableShares = append(usableShares, shares[idx])
	}
	shares = usableShares

	// Do we have enough usable shares?
	meta := shares[0].Safe.Meta
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
				X: share.Safe.X,
				Y: share.Safe.Ys[i],
			})
		}
		chunkedPoints[i] = points
	}
	return chunkedPoints, meta, nil
}

// combineChunks takes a set of chunks and then converts them to the
// secretFormat (after being concatenated and unmarshalled). It also checks for
// errors in the internal schema.
func combineChunks(meta ShareMeta, chunks []*big.Int) (secretFormat, error) {
	// Get the secret from the byte representation.
	var internalSecretBytes []byte
	for idx, chunk := range chunks {
		// Make sure that the secret chunk we reconstruct is the correct size.
		// We assume it's the blocksize, otherwise it's size (mod blocksize).
		minLength := meta.BlockSize
		if idx == len(chunks)-1 {
			minLength = meta.Size % meta.BlockSize
		}
		internalSecretBytes = append(internalSecretBytes, paddedBigint(chunk, minLength)...)
	}

	// TODO: It is now safe for us to include a checksum in the metadata. We
	//       should do that, so that size checking isn't our defense.
	if uint(len(internalSecretBytes)) != meta.Size {
		return secretFormat{}, ErrCombineWrongSize
	}

	// Now we have to be careful to note that the above secret is our
	// *internal* secret data. We have to extract the original.
	var internalSecret secretFormat
	if err := json.Unmarshal(internalSecretBytes, &internalSecret); err != nil {
		return secretFormat{}, errors.Wrap(err, "get internal secret")
	}
	if internalSecret.Version != schemaVersion {
		// TODO: We might need backwards compatibility here.
		return secretFormat{}, ErrUnknownSecretSchema
	}
	return internalSecret, nil
}

// Combine takes k Shares in an (k, n) threshold scheme and derives the secret
// associated with the shares. If the shares are malformed, do not correspond
// to the same secret, or have some evidence of forgery an error is returned.
func Combine(shares ...Share) ([]byte, error) {
	// Get the set of points of each chunk.
	chunkedPoints, meta, err := combineSharePoints(shares)
	if err != nil {
		return nil, errors.Wrap(err, "combine share points")
	}

	// Interpolate the constant in each of the chunks, to get the secret.
	chunks := make([]*big.Int, len(chunkedPoints))
	for i, points := range chunkedPoints {
		chunk, err := polynomial.InterpolateConst(meta.K-1, meta.P, points...)
		if err != nil {
			return nil, errors.Wrapf(err, "interpolate chunk %d", i)
		}
		chunks[i] = chunk
	}
	// Get the internal secret representation and get the actual user secret
	// from it.
	internalSecret, err := combineChunks(meta, chunks)
	if err != nil {
		return nil, errors.Wrap(err, "combine chunks")
	}
	return internalSecret.Data, nil
}

// Extend takes a given set of shares and constructs n additional shares which
// are compatible with the ones provided. This allows for the "recovery" of any
// lost shares while k shares are still available (note that this
// implementation generates random X-coordinates, so the "recovered" shares are
// almost certainly different from the originally lost shares -- however the
// new shares are compatible with old shares). The value of n is *not* limited
// by the original n-value used when Split-ing the secret.
func Extend(n uint, shares ...Share) ([]Share, error) {
	// Get the set of points for each chunk.
	chunkedPoints, meta, err := combineSharePoints(shares)
	if err != nil {
		return nil, errors.Wrap(err, "combine share points")
	}

	// Interpolate the entire polynomial so we can construct additional shares.
	polys := make([]polynomial.Polynomial, len(chunkedPoints))
	for i, points := range chunkedPoints {
		poly, err := polynomial.Interpolate(meta.K-1, meta.P, points...)
		if err != nil {
			return nil, errors.Wrapf(err, "interpolate chunk poly %d", i)
		}
		polys[i] = poly
	}

	// We have to get the private key, which is stored in the internal secret
	// representation. We already have the reconstructed polynomials, so we
	// just need to get the constants and we can get the internal data that
	// way.
	chunks := make([]*big.Int, len(polys))
	for i, poly := range polys {
		chunks[i] = poly.Const()
	}
	internalSecret, err := combineChunks(meta, chunks)
	if err != nil {
		return nil, errors.Wrap(err, "combine chunks")
	}
	privateKey := internalSecret.Key

	// Now we construct each share.
	var newShares []Share
	for i := uint(0); i < n; i++ {
		// TODO: While very unlikely, we should ensure that we don't generate
		//       any duplicate shares here. Otherwise we may end up giving a
		//       "false sense of redundancy" to the caller.
		newShare, err := constructShare(meta, polys, privateKey)
		if err != nil {
			return nil, errors.Wrapf(err, "construct new share %d", i)
		}
		newShares = append(newShares, newShare)
	}
	return newShares, nil
}
