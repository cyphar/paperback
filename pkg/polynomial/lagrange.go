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
	"errors"
	"math/big"
)

var (
	// ErrInvalidDegree is returned if a function was told to create a
	// polynomial with an invalid degree (<= 1).
	ErrInvalidDegree = errors.New("degree must be at least one")

	// ErrTooFewPoints is returned if we were asked to interpolate a polynomial
	// with too few points given the requested degree.
	ErrTooFewPoints = errors.New("too few points for lagrange interpolation")

	// ErrInconsistentPoints is returned if the given set of points were
	// inconsistent (in other words, at least two points had the same X-value
	// but different Y-values.
	ErrInconsistentPoints = errors.New("detected inconsistent points")

	// ErrInvalidModulus is returned if the modulus provided isn't valid for a
	// finite field (it must be prime, and non-zero).
	ErrInvalidModulus = errors.New("modulus not provided or isn't prime")
)

// Point represents an (x, y) pair, used for Lagrange interpolation.
type Point struct {
	X, Y *big.Int
}

// uniquePoints returns the set of points that are unique (this is determined
// by checking the X-value). The returned "inconsistent" boolean indicates
// whether there were any "inconsistent" points present (two coordinates that
// had the same X-values but different Y-values).
func uniquePoints(points []Point) (unique []Point, inconsistent bool) {
	uniqueMap := map[string]int{}
	for idx, point := range points {
		pointKey := point.X.String()
		if oldIdx, ok := uniqueMap[pointKey]; !ok {
			unique = append(unique, point)
			uniqueMap[pointKey] = idx
		} else if points[oldIdx].Y.Cmp(point.Y) != 0 {
			inconsistent = true
		}
	}
	return unique, inconsistent
}

// InterpolateConst interpolates the constant of the polynomial which fits all
// the provided points using Lagrange interpolation. It operates over the
// finite field given by the modulus |m| (note that due to how Lagrange
// interpolation is implemented, the modulus must be relatively prime to |x_m -
// x_j| -- in order to avoid undefined behaviour we require |m| to be prime).
//
// In order to avoid the overhead of computing all the coefficients of the
// polynomial (which would be quite slow), we use the following optimised
// formula to only calulate L(0) -- which is the constant of the polynomial. In
// the following expression, k is the degree of the polynomial.
//     L(0) = \sum_{j=0}^{k} f(x_j) \prod_{m=0,m!=j}^{k} \frac{x_m}{x_m-x_j}
func InterpolateConst(degree uint, mod *big.Int, points ...Point) (*big.Int, error) {
	if degree < 1 {
		return nil, ErrInvalidDegree
	}
	if mod == nil || !mod.ProbablyPrime(20) {
		return nil, ErrInvalidModulus
	}

	// We only need the first (degree+1) unique points.
	points, inconsistent := uniquePoints(points)
	if inconsistent {
		return nil, ErrInconsistentPoints
	}
	k := degree + 1
	if uint(len(points)) < k {
		return nil, ErrTooFewPoints
	}
	points = points[:k]

	// L0 = \sum ...
	L0 := new(big.Int)
	for j := range points {
		// f(x_j) ...
		yj := copyInt(points[j].Y)
		// \prod_{m=0,m!=j}^k ...
		prod := big.NewInt(1)
		for m := 0; uint(m) < k; m++ {
			if m == j {
				continue
			}
			// \frac{1}{x_m-x_j} -- We need to explicitly do this so we can
			// apply the modular inverse in modular arithmetic.
			XmXj := new(big.Int).Sub(points[m].X, points[j].X)
			invXmXj := new(big.Int).ModInverse(XmXj, mod)
			// \frac{x_m}{x_m-x_j}
			Xm := points[m].X
			frac := new(big.Int).Mul(Xm, invXmXj)
			frac.Mod(frac, mod)
			// Add to product.
			prod.Mul(prod, frac)
			prod.Mod(prod, mod)
		}
		// f(x_j) \prod ...
		L0_elem := new(big.Int).Mul(yj, prod)
		// Add to L0 accumulator.
		L0.Add(L0, L0_elem)
		L0.Mod(L0, mod)
	}
	return L0, nil
}

// copyIntSlice makes a deep copy of a given []int.
func copyIntSlice(s []int) []int { return append([]int{}, s...) }

// combinations computes the set of in-original-order n-length combinations of
// the given pool of items' indices, without replacement. This matches the
// semantics of Python's itertools.combinations(range(n), r).
func combinations(n, r int) [][]int {
	// Handle base-cases.
	switch {
	case n < 0, r < 0, r > n:
		return nil
	case r == 0:
		return [][]int{{}}
	}

	// The set of indices we're going to permute.
	idxs := make([]int, r)
	for i := range idxs {
		idxs[i] = i
	}
	// We construct each index set from the rear. We start with the "trivial"
	// combination (range(r)).
	combs := [][]int{copyIntSlice(idxs)}
	for {
		// Find the last index which is the "maximum".
		var i int
		for i = r - 1; i >= 0; i-- {
			if idxs[i] != i+n-r {
				break
			}
		}
		// None left.
		if i < 0 {
			break
		}
		// Increment the current index, then work forwards and set them to the
		// lowest value (which is one higher than the one to the left).
		idxs[i]++
		for j := i + 1; j < r; j++ {
			idxs[j] = idxs[j-1] + 1
		}
		// This is our combination index set.
		combs = append(combs, copyIntSlice(idxs))
	}
	return combs
}

func copyBigint(x *big.Int) *big.Int { return new(big.Int).Add(new(big.Int), x) }

// Interpolate constructs a new Polynomial using the provided points. This is
// significantly less efficient than InterpolateConst, which only interpolates
// the constant term of the polynomial. However, as Interpolate produces the
// entire Polynomial it is possible to compute new (x,y) points using the
// reconstructed Polynomial. In the context of Shamir Secret Sharing this
// allows new shards to be created that are compatible with the old shards.
// This interpolation is done by re-arranging the traditional expression for
// the lagrange polynomials of a function, and then computing the coefficients
// of each power of x.
func Interpolate(degree uint, mod *big.Int, points ...Point) (Polynomial, error) {
	if degree < 1 {
		return nil, ErrInvalidDegree
	}
	if mod == nil || !mod.ProbablyPrime(20) {
		return nil, ErrInvalidModulus
	}

	// We only need the first (degree+1) unique points.
	points, inconsistent := uniquePoints(points)
	if inconsistent {
		return nil, ErrInconsistentPoints
	}
	k := degree + 1
	if uint(len(points)) < k {
		return nil, ErrTooFewPoints
	}
	points = points[:k]

	// We re-arrange the classical Lagrange interpolation expression (k is
	// number of points)
	//
	//     L(x) = \sum_{j=0}^k f(x_j) l_j(x)
	//   l_j(x) = \prod_{m=0,m!=j}^k \frac{x-x_m}{x_j-x_m} ,
	//
	//   into something a bit easier to handle when you expand it as a
	// polynomial
	//
	//   l_j(x) = \frac{\prod_m x-x_m}{\prod_m x_j-x_m} ,
	//
	//   where the denominator is a constant, and the numerator can be expanded
	// using multi-index notation. In normal arithmetic this look like
	//
	//   (x+a_1) (x+a_2) \dots (x+a_n) = \sum_{i=0}^n COMB(a,i} x^i ,
	//
	//   where COMB(a,i) gives the sum over the set of combinations of a_* with
	// length i (without replacement). Proof for the last line is left to the
	// reader (if you expand the polynomial manually you'll notice this pattern
	// pretty quickly, and it's a special case of multi-binomial expansion).

	var lagrangePolynomials []Polynomial
	for j := range points {
		// \frac{f(x_j)}{\prod_m x_j-x_m}
		scaleFactor := copyBigint(points[j].Y)
		prodXjXm := big.NewInt(1)
		for m := 0; uint(m) < k; m++ {
			if m == j {
				continue
			}
			XjXm := new(big.Int).Sub(points[j].X, points[m].X)
			prodXjXm.Mul(prodXjXm, XjXm)
			prodXjXm.Mod(prodXjXm, mod)
		}
		prodXjXmInv := new(big.Int).ModInverse(prodXjXm, mod)
		scaleFactor.Mul(scaleFactor, prodXjXmInv)
		scaleFactor.Mod(scaleFactor, mod)

		// \prod_m x-x_m
		var Xms []*big.Int
		for m := 0; uint(m) < k; m++ {
			if m == j {
				continue
			}
			Xms = append(Xms, new(big.Int).Neg(points[m].X))
		}
		// The polynomial expansion looks like the following sequence, if we
		// take p_n(x) = \prod_{i=1}^n (x+i).
		//   p_1(x) =                                                                x + a
		//   p_2(x) =                                         x^2 +             (a+b)x + ab
		//   p_3(x) =                x^3 +             (a+b+c)x^2 +        (ab+ac+bc)x + abc
		//   p_4(x) = x^4 + (a+b+c+d)x^3 + (ab+ac+ad+bc+bd+cd)x^2 + (abc+abd+acd+bcd)x + abcd
		//   ... and so on ...
		// Note that the size of the "groups" of coefficients increases as the
		// power of x decreases. The coefficient groupings are the sum of the
		// products of each combination of the "other" terms in the polynomial.
		polynomial := make(Polynomial, k)
		for m := 0; uint(m) < k; m++ {
			coeff := new(big.Int)
			for _, set := range combinations(len(Xms), int(k-1)-m) {
				part := big.NewInt(1)
				for _, setIdx := range set {
					part.Mul(part, Xms[setIdx])
					part.Mod(part, mod)
				}
				coeff.Add(coeff, part)
				coeff.Mod(coeff, mod)
			}
			coeff.Mul(coeff, scaleFactor)
			coeff.Mod(coeff, mod)
			polynomial[m] = coeff
		}
		lagrangePolynomials = append(lagrangePolynomials, polynomial)
	}

	// The final polynomial is just the lagrange polynomial.
	return SumPolynomials(mod, lagrangePolynomials...)
}
