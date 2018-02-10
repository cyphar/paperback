/*
 * paperback: resilient paper backups for the very paranoid
 * copyright (c) 2018 aleksa sarai <cyphar@cyphar.com>
 *
 * this program is free software: you can redistribute it and/or modify
 * it under the terms of the gnu general public license as published by
 * the free software foundation, either version 3 of the license, or
 * (at your option) any later version.
 *
 * this program is distributed in the hope that it will be useful,
 * but without any warranty; without even the implied warranty of
 * merchantability or fitness for a particular purpose.  see the
 * gnu general public license for more details.
 *
 * you should have received a copy of the gnu general public license
 * along with this program.  if not, see <https://www.gnu.org/licenses/>.
 */

package shamir

import (
	"encoding/base64"
	"math/big"

	"github.com/pkg/errors"
)

// paddedBigint returns the padded version of the given *big.Int's big-endian
// byte representation. The resulting byte slice will always have the same
// meaning as the original, but may have zero-padding. The returned byte slice
// is not truncated, so the length may exceed minLength.
func paddedBigint(x *big.Int, minLength uint) []byte {
	b := x.Bytes()
	if uint(len(b)) < minLength {
		prefix := make([]byte, minLength-uint(len(b)))
		b = append(prefix, b...)
	}
	return b
}

// encodeBigint returns a JSON-safe string encoding of the given *big.Int.
func encodeBigInt(x *big.Int) string {
	return base64.StdEncoding.EncodeToString(x.Bytes())
}

// decodeBigInt returns the *big.Int associated with the encoded value given,
// matching the format given by encodeBigInt.
func decodeBigInt(s string) (*big.Int, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.Wrap(err, "decode *big.Int")
	}
	return new(big.Int).SetBytes(b), nil
}

// copyBigInt make a copy of a given *big.Int.
func copyBigInt(x *big.Int) *big.Int {
	xCopy := new(big.Int)
	return xCopy.Add(xCopy, x)
}
