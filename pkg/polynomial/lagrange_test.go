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
	"fmt"
	"math/big"
	"reflect"
	"testing"
)

func testInterpolateHelper(t *testing.T, fn func(t *testing.T, poly Polynomial, prime *big.Int, points []Point)) {
	prime, err := rand.Prime(rng, 16)
	if err != nil {
		t.Fatalf("failed to get random prime for field")
	}

	const trials = 32
	const maxDegree = 16
	for i := 0; i < trials; i++ {
		tn := fmt.Sprintf("trial_%d", i)
		t.Run(tn, func(t *testing.T) {
			// Add degree.
			degree := uint(rng.Intn(maxDegree))
			poly, err := RandomPolynomial(degree, prime)
			if err != nil {
				t.Fatalf("failed to get RandomPolynomial(%d, %v): %v", degree, prime, err)
			}

			// Try different numbers of points.
			for n := degree - 3; n < degree+3; n++ {
				tn := fmt.Sprintf("points_n=%d", n)
				t.Run(tn, func(t *testing.T) {
					// Get a random set of points.
					points := make([]Point, n)
					for idx := range points {
						x, err := rand.Int(rng, prime)
						if err != nil {
							t.Fatalf("failed to get random x value: %v", err)
						}
						y, err := poly.EvaluateMod(x, prime)
						if err != nil {
							t.Fatalf("failed to evaluate p(%v) mod %v: %v", x, prime, err)
						}
						points[idx] = Point{X: x, Y: y}
					}

					fn(t, poly, prime, points)
				})
			}
		})
	}

}

// TestInterpolate does a bunch of sanity checks to ensure that a series of
// random polynomials will still produce the correct polynomial when
// interpolated. This is done through a series of random trials.
func TestInterpolate(t *testing.T) {
	testInterpolateHelper(t, func(t *testing.T, poly Polynomial, prime *big.Int, points []Point) {
		// Interpolate P and check that we ge the right value (or an error
		// if we don't have enough points).
		interpolatedPoly, err := Interpolate(poly.Degree(), prime, points...)
		if uint(len(points)) > poly.Degree() {
			if err != nil {
				t.Errorf("interpolation failed unexpectedly: %v", err)
			} else if !reflect.DeepEqual(poly, interpolatedPoly) {
				t.Errorf("incorrect interpolation: expected %v got %v", poly, interpolatedPoly)
			}
		} else {
			if err == nil {
				t.Errorf("interpolation succeeded unexpectedly")
			}
		}
	})
}

// TestInterpolateConst does a bunch of sanity checks to ensure that a series
// of random polynomials will still produce the correct L0 value when
// interpolated. This is done through a series of random trials.
func TestInterpolateConst(t *testing.T) {
	testInterpolateHelper(t, func(t *testing.T, poly Polynomial, prime *big.Int, points []Point) {
		// Get p(0) from the original polynomial.
		p0, err := poly.EvaluateMod(new(big.Int), prime)
		if err != nil {
			t.Fatalf("evaluation of polynomial failed unexpectedly: %v", err)
		}
		// Interpolate L0 and check that we get the right value (or an error if
		// we don't have enough points).
		L0, err := InterpolateConst(poly.Degree(), prime, points...)
		if uint(len(points)) > poly.Degree() {
			if err != nil {
				t.Errorf("interpolation failed unexpectedly: %v", err)
			} else if !reflect.DeepEqual(p0, L0) {
				t.Errorf("incorrect interpolation: expected %v got %v", p0, L0)
			}
		} else {
			if err == nil {
				t.Errorf("interpolation succeeded unexpectedly")
			}
		}
	})
}

// TestCombinations ensures that our combinations generation code actually does
// the right thing. It's used inside Interpolate.
func TestCombinations(t *testing.T) {
	for n := 0; n < 10; n++ {
		for r := 0; r < 10; r++ {
			tn := fmt.Sprintf("C_n=%v_r=%v", n, r)
			t.Run(tn, func(t *testing.T) {
				t.Parallel()

				sets := combinations(n, r)
				for idx, set := range sets {
					if len(set) != r {
						t.Errorf("set[%d] %v has unexpected length: expected %d got %d", idx, set, r, len(set))
					}
				}
				expectedSetLen := new(big.Int).Binomial(int64(n), int64(r))
				if expectedSetLen.Cmp(big.NewInt(int64(len(sets)))) != 0 {
					t.Errorf("set length is not expected nCr: expected %v got %d", expectedSetLen, len(sets))
				}
			})
		}
	}
}
