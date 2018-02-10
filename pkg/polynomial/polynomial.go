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
	"crypto/rand"
	"errors"
	"math/big"
)

// Polynomial represents a polynomial of a degree len(p)-1, with real integer
// coefficients. The coefficients are stored in *increasing* power of x, like
//                  p_0 + p_1 x^1 + p_2 x^2 + ... + p_n x^n.
type Polynomial []*big.Int

// RandomPolynomial generates a new polynomial with random integer coefficients
// (all coefficients are guaranteed to be in the range (0,max)) and the given
// degree. len(polynomial) = degree+1
func RandomPolynomial(degree uint, max *big.Int) (Polynomial, error) {
	poly := make(Polynomial, degree+1)
	for i := 0; i < cap(poly); i++ {
		coeff := new(big.Int)
		// We don't permit coefficients that are zero. This is purely for our
		// own safety, to avoid having a polynomial that has a small enough
		// number of zeros in "bad" places to allow for easier interpolation.
		for coeff.Sign() == 0 {
			var err error
			coeff, err = rand.Int(rand.Reader, max)
			if err != nil {
				return nil, err
			}
		}
		poly[i] = coeff
	}
	return poly, nil
}

// SumPolynomials takes a set of polynomials {p_0(x), p_1(x), ... p_n(x)} and
// then computes the polynomial P(x) = \sum_{i=0}^n p_i(x) mod |m|. The
// polynomials need not be the same degree.
func SumPolynomials(m *big.Int, polynomials ...Polynomial) (Polynomial, error) {
	// m must be a prime otherwise we're in trouble.
	if m == nil || !m.ProbablyPrime(20) {
		return nil, errors.New("modulus not provided or modulus isn't prime")
	}

	// Find the largest degree.
	var degree uint
	for _, poly := range polynomials {
		if poly.Degree() > degree {
			degree = poly.Degree()
		}
	}

	// Sum together the polynomials.
	P := make(Polynomial, degree+1)
	for idx := range P {
		P[idx] = new(big.Int)
	}
	for _, poly := range polynomials {
		for idx := range poly {
			P[idx].Add(P[idx], poly[idx])
			P[idx].Mod(P[idx], m)
		}
	}
	return P, nil
}

// copyInt creates a copy of the given *big.Int.
func copyInt(x *big.Int) *big.Int { return new(big.Int).Add(new(big.Int), x) }

// SetConst sets the "constant" term of the polynomial (or rather the
// coefficient of x^0). This is just a convenience function for assigning to
// [0], but it protects against making mistakes when referencing the Polynomial
// slice.
func (p Polynomial) SetConst(a0 *big.Int) {
	if len(p) < 1 {
		panic("tried to SetConst on empty Polynomial")
	}
	p[0] = copyInt(a0)
}

// Const gets the constant term of hte polynomial. This is a convenience
// function to make sure that users don't depend on our internal
// representation.
func (p Polynomial) Const() *big.Int {
	if len(p) < 1 {
		panic("tried to Const on empty Polynomial")
	}
	return p[0]
}

// Degree returns the "real" degree of the given polynomial p(x), which is the
// highest power of x that has a non-zero coefficient.
func (p Polynomial) Degree() uint {
	degree := uint(len(p) - 1)
	for degree > 0 && p[degree].Sign() == 0 {
		degree--
	}
	return degree
}

// EvaluateMod evaluates p(x0) mod |m|. This is done using Horner's method with
// modular arithmetic. This method is arguably more efficient than just
// evaluating the polynomial and then taking the modulus of the result
// (especially if the coeffients are quite large) and then taking the modulus
// afterwards. For our own sanity we require |m| to be a prime.
func (p Polynomial) EvaluateMod(x0, m *big.Int) (*big.Int, error) {
	// m must be a prime otherwise we're in trouble.
	if m == nil || !m.ProbablyPrime(20) {
		return nil, errors.New("modulus not provided or modulus isn't prime")
	}
	// Make sure that x0 isn't larger than m.
	x0.Mod(x0, m)

	// Horner's method is applied in the opposite order to how we store our
	// polynomials. So we must iterate it in reverse. We apply (mod m) at each
	// operation, which is fine in a finite field because (+) and (*) are
	// compatible with (mod m).
	result := new(big.Int)
	for i := len(p) - 1; i >= 0; i-- {
		result.Mul(result, x0)
		result.Add(result, p[i])
		result.Mod(result, m)
	}
	return result, nil
}
