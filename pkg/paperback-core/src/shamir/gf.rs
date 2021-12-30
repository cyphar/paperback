/*
 * paperback: paper backup generator suitable for long-term storage
 * Copyright (C) 2018-2020 Aleksa Sarai <cyphar@cyphar.com>
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

use std::{
    cmp, fmt, mem,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use itertools::Itertools;
use rand::{CryptoRng, RngCore};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "wrong number of points for interpolation: polynomial needs {needed} but was given {num_points}"
    )]
    NumPointsMismatch { needed: usize, num_points: usize },

    #[error("[critical security issue] all points must have an invertible (non-zero) x value")]
    NonInvertiblePoint,
}

/// Primitive uint type for GfElems.
pub type GfElemPrimitive = u32;

/// A field element of `GF(2^32)`, with characteristic polynomial
/// `x^32 + x^22 + x^2 + x^1 + 1`.
///
/// This is a home-brew implementation of GF mathematics that hopefully runs in
/// constant-enough time. It appears there are no clearly-good-to-use
/// implementations of `GF(2^n)` fields (and `GF(2^8)` is not suitable for our
/// purposes).
// NOTE: PartialEq is not timing-safe.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct GfElem(GfElemPrimitive);

/// (x, y) in GF.
pub type GfPoint = (GfElem, GfElem);

impl GfElem {
    // Can be an arbitrary polynomial, but this one was chosen because it is the
    // smallest (both numerically and in terms of the number of bits set)
    // degree-32 polynomial which is both irreducible and primitive in GF(2).
    //
    // x^32 + x^22 + x^2 + x^1 + 1
    const POLYNOMIAL: u64 = 0b1_0000_0000_0100_0000_0000_0000_0000_0111;

    // Self::POLYNOMIAL but with the top-most bit unset.
    const TRUNC_POLYNOMIAL: u32 = 0b0000_0000_0100_0000_0000_0000_0000_0111;

    /// Additive identity.
    pub const ZERO: GfElem = GfElem(0);

    /// Multiplicative identity.
    pub const ONE: GfElem = GfElem(1);

    pub fn new_rand<R: CryptoRng + RngCore + ?Sized>(r: &mut R) -> Self {
        Self(r.next_u32())
    }

    pub(crate) fn inner(&self) -> GfElemPrimitive {
        self.0
    }

    pub(crate) fn from_inner(v: GfElemPrimitive) -> Self {
        Self(v)
    }

    pub fn from_bytes_partial(bytes: &[u8]) -> (Self, &[u8]) {
        let len = cmp::min(bytes.len(), mem::size_of::<GfElemPrimitive>());

        // Pad with zeroes.
        let mut padded = [0u8; mem::size_of::<GfElemPrimitive>()];
        padded[..len].copy_from_slice(bytes);

        // Convert to GfElem.
        (
            GfElem(GfElemPrimitive::from_le_bytes(padded)),
            &bytes[len..],
        )
    }

    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Self {
        let (elem, remain) = Self::from_bytes_partial(bytes.as_ref());
        assert!(remain.is_empty());
        elem
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    // NOTE: Definitely not constant-time.
    #[allow(dead_code)]
    pub fn pow(self, mut n: usize) -> Self {
        // Multiplication is not really cheap, so we optimise it by doing it
        // with an O(log(n)) worst case rather than the obvious O(n).
        let mut mult = self;
        let mut result = Self::ONE;
        while n != 0 {
            if n & 1 == 1 {
                result *= mult;
            }
            mult *= mult;
            n >>= 1;
        }
        result
    }

    // Implementation of Euclidean division for GF(2) polynomials (a = bq + r),
    // useful for computing the inverses with the Extended Euclid GCD Algorithm.
    // Returns (q, r). If carry is set, a is treated like (a + x^32).
    fn polynomial_div(
        a: GfElemPrimitive,
        b: GfElemPrimitive,
        carry: bool,
    ) -> (GfElemPrimitive, GfElemPrimitive) {
        // Don't call me for division by zero. This code would loop forever.
        assert_ne!(b, 0, "tried to divide by zero in internal function");

        fn msb(p: GfElemPrimitive) -> isize {
            // TODO: Use u32::BITS.
            32 - (p.leading_zeros() as isize)
        }

        let (mut q, mut r) = (0, a);
        let bmsb = msb(b);

        // The "carry" is only used for the first EEA iteration where you're
        // dividing Self::POLYNOMIAL.
        if carry {
            let shift = 33 /* 32 + 1 */ - bmsb;
            if shift < 32 {
                q ^= 1 << shift; // q += s
                r ^= b << shift; // r -= s*b (= b*x^(deg(r)-d))
            }
        }

        let mut rmsb = msb(r);
        while rmsb >= bmsb {
            // Because rd is the degree, we know that lc (1 << (rd-1)) is 1.
            let shift = rmsb - bmsb; // lc/c * x^(deg(r)-d) (= x^(deg(r)-d))
            q ^= 1 << shift; // q += s
            r ^= b << shift; // r -= s*b (= b*x^(deg(r)-d))
            rmsb = msb(r);
        }

        (q, r)
    }

    fn polynomial_mul(mut a: GfElemPrimitive, mut b: GfElemPrimitive) -> GfElemPrimitive {
        // A modified and hopefully-constant-time implementation of Russian
        // Peasant Multiplication which avoids branching by using masks instead.
        //   <https://en.wikipedia.org/wiki/Finite_field_arithmetic#D_programming_example>
        let mut p: GfElemPrimitive = 0;
        for _ in 0..32 {
            let mask = ((a >> 31) & 1).wrapping_neg() as u64;
            p ^= a & (b & 1).wrapping_neg();
            a = (((a as u64) << 1) ^ (Self::POLYNOMIAL & mask)) as GfElemPrimitive;
            b >>= 1;
        }
        p
    }

    pub fn inverse(self) -> Option<Self> {
        let a = self.0;

        // We cannot invert 0 for obvious reasons.
        if a == 0 {
            return None;
        }

        // This is an implementation of the Extended Euclid Algorithm, in order
        // to get the multiplicative inverse of self. The full description of
        // why this works can be found on Wikipedia[1]. The short version is
        // that you can extend the GCD algorithm with some extra bookkeeping and
        // this allows you to extract the coefficients of Bézout's identity
        //
        //     ns + at = gcd(a, n)
        //
        // but in modular arithmetic, if you take n as the prime field as the
        // ring of integers modulo n, then a and n must be coprime giving us:
        //
        //     ns + at = 1
        //     at = 1 (mod n)
        //
        // which means that if we can find t, we have the modular multiplicative
        // inverse of a -- and the GCD algorithm (or rather the EEA algorithm)
        // can be used to find t in a fairly efficient manner.
        //
        // Note that the above is straight-forward for regular modular
        // arithmetic, but we're in GF(2^32) which is a simple algebraic field
        // expansion of GF(2). However, luckily the algorithm is pretty much the
        // same in GF(2^32), except that:
        //
        //  * The p we take is the characteristic polynomial (irreducible
        //    polynomials are like prime numbers in polynomial fields).
        //  * We use polynomial definitions of the addition, multiplication, and
        //    Euclidian division operations.
        //
        // [1]: <https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm>

        // Technically this algorithm can be cleanly done entirely in the loop,
        // but becasue we first need to divide the characteristic polynomial
        // (which is by definition larger than u32), it's much cleaner to do the
        // first iteration outside.
        let (q1, r1) = Self::polynomial_div(Self::TRUNC_POLYNOMIAL, a, true);

        let (mut t, mut newt) = (1, q1); // (0, 1) -> (1, 0 - q1 * 1)
        let (mut r, mut newr) = (a, r1); // (P, a) -> (a, P - q1 * a) -> (a, r1)

        while newr != 0 {
            // The trick with updating newr is to notice that (r - qi*newr) is
            // undoing part of the polynomial_div calculation and you can just
            // reuse that result. Recall that by definition (r = qi*newr + ri).
            //
            //    newr := r - qi*newr
            //          = r - (r - ri)    [r = qi*newr + ri => r - ri = q*newr]
            //          = ri
            let (qi, ri) = Self::polynomial_div(r, newr, false);

            // TODO: Switch this once destructuring_assignment is stable.

            // (t, newt) = (newt, t - qi * newt)
            let tmpt = newt;
            newt = t ^ Self::polynomial_mul(qi, newt);
            t = tmpt;

            // (r, newr) = (newr, r - qi * newr) = (newr, ri)
            let tmpr = newr;
            newr = ri;
            r = tmpr;
        }

        // If gcd(a, Self::POLYNOMIAL) != 1, that means the polynomial is
        // not an irreducible polynomial of order (at least) 32 in GF(2).
        assert_eq!(r, 1, "Self::POLYNOMIAL not irreducible in GF(2)!");
        Some(Self(t))
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for GfElem {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        Self(GfElemPrimitive::arbitrary(g))
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        Box::new(self.0.shrink().into_iter().map(Self))
    }
}

impl Add for GfElem {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl AddAssign for GfElem {
    fn add_assign(&mut self, rhs: Self) {
        // Addition in GF(2^n) is actually XOR.
        #![allow(clippy::suspicious_op_assign_impl)]
        self.0 ^= rhs.0
    }
}

impl Sub for GfElem {
    type Output = Self;
    fn sub(mut self, rhs: Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl SubAssign for GfElem {
    fn sub_assign(&mut self, rhs: Self) {
        // Subtraction in GF(2^n) is identical to addition.
        #![allow(clippy::suspicious_op_assign_impl)]
        *self += rhs
    }
}

impl Neg for GfElem {
    type Output = Self;
    fn neg(self) -> Self::Output {
        // In GF(2^n) addition is the same as subtraction, so everything is its
        // own additive inverse.
        self
    }
}

impl Mul for GfElem {
    type Output = Self;
    fn mul(mut self, rhs: Self) -> Self::Output {
        self *= rhs;
        self
    }
}

impl MulAssign for GfElem {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = Self::polynomial_mul(self.0, rhs.0);
    }
}

impl Div for GfElem {
    type Output = Self;
    fn div(mut self, rhs: Self) -> Self::Output {
        self /= rhs;
        self
    }
}

impl DivAssign for GfElem {
    fn div_assign(&mut self, rhs: Self) {
        // In order to divide, we need to compute the inverse and multiply (like
        // we would with regular arthimetic in R).
        #![allow(clippy::suspicious_op_assign_impl)]
        *self *= rhs.inverse().expect("rhs cannot be inverted")
    }
}

pub trait EvaluablePolynomial: fmt::Debug {
    /// Evaluate the polynomial at a given `x` value.
    fn evaluate(&self, x: GfElem) -> GfElem;

    /// Return the degree of the polynomial (the largest power of x).
    fn degree(&self) -> GfElemPrimitive;

    /// Retreive the constant term of the polynomial.
    ///
    /// This is equivalent to `self.evaluate(GfElem::ZERO)` but might be
    /// implemented in a more efficient manner than straight-forward evaluation.
    fn constant(&self) -> GfElem {
        self.evaluate(GfElem::ZERO)
    }

    // Implementation detail required to allow us to make Box<dyn Trait>
    // clonable while still permitting the trait to be made into a trait object.
    #[doc(hidden)]
    fn box_clone(&self) -> Box<dyn EvaluablePolynomial>;
}

impl Clone for Box<dyn EvaluablePolynomial> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

/// A polynomial in `GF(2^32)`.
// The coefficients are in *increasing* degree (x^0, x^1, ..., x^n).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GfPolynomial(Vec<GfElem>);

impl GfPolynomial {
    pub fn new_rand<R: CryptoRng + RngCore + ?Sized>(n: GfElemPrimitive, r: &mut R) -> Self {
        let k = n + 1;
        Self(
            (0..k)
                .map(|_| {
                    // We must make sure that none of the coefficients are zero
                    // elements. This is purely an abundance of caution, but it
                    // ensures we don't accidentally end up with a polynomial
                    // that doesn't have enough coefficients (resulting it being
                    // easy to invert).
                    let mut elem = GfElem::ZERO;
                    while elem == GfElem::ZERO {
                        elem = GfElem::new_rand(r);
                    }
                    elem
                })
                .collect::<Vec<_>>(),
        )
    }

    /// Yield a mutable reference to the constant term of the polynomial.
    ///
    /// This allows you to modify the constant term of the polynomial. Note that
    /// this invalidates all previously computed `GfPolynomial::evaluate`
    /// results.
    pub fn constant_mut(&mut self) -> &mut GfElem {
        self.0
            .first_mut()
            .expect("GfPolynomial must have at least one element")
    }

    /// Interpolate a polynomial of degree `n` in `GF(2^32)`, given a set of
    /// points along that polynomial.
    ///
    /// The process for this computation is [Lagrange interpolation][lagrange].
    ///
    /// NOTE: This method is much slower than `GfBarycentric::recover` with
    /// little to no extra benefit (you don't need the full polyomial recovered
    /// in most cases). In addition, if you need just the constant term then use
    /// `lagrange_constant`.
    ///
    /// [lagrange]: https://en.wikipedia.org/wiki/Lagrange_polynomial
    // TODO: Add a warning for using this.
    #[allow(unused)]
    pub fn recover<P: AsRef<[GfPoint]>>(n: GfElemPrimitive, points: P) -> Result<Self, Error> {
        let points = points.as_ref();
        let k = points.len();
        // TODO: Handle n+1 > k points.
        if k != (n + 1) as usize {
            return Err(Error::NumPointsMismatch {
                needed: (n + 1) as usize,
                num_points: k,
            });
        }

        let (xs, ys): (Vec<_>, Vec<_>) = points.iter().copied().unzip();

        // To make full polynomial interpolation more efficient (and to allow us
        // to deal with the binomial expansion more easily), we have to
        // rearrange the Lagrange polynomial expressions
        //
        //     L(x) = \sum_{j_0}^k y_j l_j(x)
        //   l_j(x) = \prod_{m=0,m!=j}^{k} \frac{x-x_m}{x_j-x_m}
        //
        // where k is the number of points (which is equal to the threshold, or
        // the polynomial degree + 1), and turn it into something a little bit
        // easier to handle (by reducing the number of operations and making the
        // denominator a constant term)
        //
        //   l_j(x) = \frac{\prod_{m=0,m!=j}^{k} x-x_m}
        //                 {\prod_{m=0,m!=j}^{k} x_j-x_m}
        //
        // if you stare long enough at the (x-x_m) product, you might notice
        // that the coefficents form a pattern. For a general multi-binomial
        // like
        //
        //   p_k(x) = \sum_{i=0}^{k} (x + C[i])
        //
        // you find the following pattern
        //
        //   p_1(x) =                                                                x + a
        //   p_2(x) =                                         x^2 +             (a+b)x + ab
        //   p_3(x) =                x^3 +             (a+b+c)x^2 +        (ab+ac+bc)x + abc
        //   p_4(x) = x^4 + (a+b+c+d)x^3 + (ab+ac+ad+bc+bd+cd)x^2 + (abc+abd+acd+bcd)x + abcd
        //
        // thus we can conclude that for the l_j(x) product that the
        // coefficients come out to
        //
        //   (x-a_1) \dots (x-a_m) = \sum_{i=0}^{n} SUM_COMB({-a}, i) x^i
        //
        // where SUM_COMB({x}, n) is the sum of all combinations of length n of
        // the set {x} (without replacement). The proof is left to the reader,
        // but this is just a special-case of multi-binomial expansion.
        let polys = (0..k).map(|j| {
            let idxs = (0..k).filter(|&m| m != j).collect::<Vec<_>>();

            // \frac{y_j}{\prod_{m=0,m!=j}^{k} x_j-x_m}
            let scale = ys[j]
                / idxs
                    .iter()
                    .fold(GfElem::ONE, |acc, &m| acc * (xs[j] - xs[m]));

            // \sum_{i=0}^{k} SUM_COMB({-a}, i) x^i
            let coeffs = (0..k)
                .map(|i| {
                    idxs.iter()
                        .map(|&i| -xs[i])
                        .combinations(i)
                        .map(|xs| xs.iter().fold(GfElem::ONE, |acc, &x| acc * x))
                        .reduce(Add::add)
                        .unwrap_or(GfElem::ZERO)
                })
                .map(|x| scale * x)
                // We store coefficients in increasing order of x powers (the
                // opposite of the formula outlined above).
                .rev()
                .collect::<Vec<_>>();

            GfPolynomial(coeffs)
        });

        Ok(polys
            .reduce(Add::add)
            .expect("must be at least one polynomial"))
    }
}

impl EvaluablePolynomial for GfPolynomial {
    fn evaluate(&self, x: GfElem) -> GfElem {
        // Implementation of Horner's method for evaluating a polynomial, which
        // results in only O(n) operations (n additions, and n multiplications)
        // rather than the far less optimal. Since we order the polynomial
        // terms in terms of increasing degree, we need to do it in reverse.
        self.0
            .iter()
            .rev()
            .copied()
            .reduce(|acc, coeff| coeff + x * acc)
            .expect("polynomial has at least one term")
    }

    fn degree(&self) -> GfElemPrimitive {
        match self.0.len() {
            0 => panic!("GfPolynomial must have at least one element"),
            n => (n - 1) as GfElemPrimitive,
        }
    }

    fn constant(&self) -> GfElem {
        *self
            .0
            .first()
            .expect("GfPolynomial must have at least one element")
    }

    fn box_clone(&self) -> Box<dyn EvaluablePolynomial> {
        Box::new((*self).clone())
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for GfPolynomial {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        GfPolynomial(
            (0..g.size())
                .map(|_| GfElem::arbitrary(g))
                .collect::<Vec<_>>(),
        )
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        Box::new(
            self.0
                .shrink()
                .into_iter()
                .filter(|p| p.len() > 0)
                .map(Self),
        )
    }
}

impl Add for GfPolynomial {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl AddAssign for GfPolynomial {
    fn add_assign(&mut self, rhs: Self) {
        for (i, rhs_coeff) in rhs.0.iter().enumerate() {
            match self.0.get_mut(i) {
                Some(lhs_coeff) => *lhs_coeff += *rhs_coeff,
                None => {
                    self.0.extend(&rhs.0[i..]);
                    break;
                }
            }
        }
    }
}

/// A barycentric-form representation of a Lagrange-interpolated polynomial.
///
/// By representing the lagrange interpolation of a polynomial in this manner,
/// we can very efficiently calculate multiple `x` values without having to go
/// through a full interpolation each time or constructing the original
/// polynomial from scratch (as in `GfPolynomial::recover`).
#[derive(Clone, Debug)]
pub struct GfBarycentric {
    xs: Vec<GfElem>, // x co-ordinates
    ys: Vec<GfElem>, // y co-ordinates
    ws: Vec<GfElem>, // barycentric weights (w_j = \prod_{i=0;i!=j}^k (x_j - x_i))
}

impl EvaluablePolynomial for GfBarycentric {
    fn evaluate(&self, x: GfElem) -> GfElem {
        // We use the second form of the barycentric interpolation formula so we
        // don't need to evaluate l(x) = (x-x_0)...(x-x_k) at all. This means we
        // just need to evaluate:
        //
        //   L(x) = \frac{\sum_{j=0}^k \frac{w_j}{x-x_j} y_j}
        //               {\sum_{j=0}^k \frac{w_j}{x-x_j}}
        //
        // Since the \sum_{j=0}^k \frac{w_j}{x-x_j} calculation is common, we
        // can first caclulate the terms and dot-product a copy by y_j.

        // Terms of \sum_{j=0}^k \frac{w_j}{x-x_j}.
        let sum_terms = self
            .xs
            .iter()
            .zip(&self.ws)
            .map(|(&xj, &wj)| wj / (x - xj))
            .collect::<Vec<_>>();

        // Sum(sum_terms . ys)
        let numerator = sum_terms
            .iter()
            .zip(&self.ys)
            .map(|(&t, &yj)| t * yj)
            .reduce(GfElem::add)
            .expect("barycentric form has at least one term");

        // Sum(sum_terms)
        let denominator = sum_terms
            .iter()
            .copied()
            .reduce(GfElem::add)
            .expect("barycentric form has at least one term");

        numerator / denominator
    }

    fn degree(&self) -> GfElemPrimitive {
        self.ws.len() as GfElemPrimitive - 1
    }

    // TODO: Should we cache the constant term and have an optimised constant()
    // method? I'm not sure it'd save us much time since once we've computed the
    // barycentric weights we can compute any value in O(n).

    fn box_clone(&self) -> Box<dyn EvaluablePolynomial> {
        Box::new((*self).clone())
    }
}

impl GfBarycentric {
    pub fn recover<P: AsRef<[GfPoint]>>(n: GfElemPrimitive, points: P) -> Result<Self, Error> {
        let points = points.as_ref();
        let k = points.len();
        // TODO: Handle n+1 > k points.
        if k != (n + 1) as usize {
            return Err(Error::NumPointsMismatch {
                needed: (n + 1) as usize,
                num_points: k,
            });
        }
        let (xs, ys): (Vec<_>, Vec<_>) = points.iter().copied().unzip();

        // Calculate the barycentric weights. Given
        //   l(x)    = (x-x_0)...(x-x_j)
        //   l'(x_j) = dl(x)/dx|x=x_j
        //           = \prod_{i=0,i!=j}^k (x_j - x_i)
        //
        // We can rewrite the basis polynomials as
        //
        //   l_j(x) = \frac{l(x)}{l'(x_j)(x-x_j)}
        //
        // And if we define w_j = \frac{1}{l_j(x_j)} we get
        //
        //   l_j(x) = l(x) \frac{w_j}{x-x_j}
        //   L(x) = l(x) \sum_{j=0}^k \frac{w_j}{x-x_j} y_j
        //
        // Which is the barycentric interpolation formula of the first kind. We
        // can optimise this to the second kind (or "true form") of the formula
        // by considering g(x) = 1 (evaluated at the same x values) and how
        // diving L(x) by the barycentric form of g(x) eliminates l(x) entirely.
        //
        //   L(x) = \frac{\sum_{j=0}^k \frac{w_j}{x-x_j} y_j}
        //               {\sum_{j=0}^k \frac{w_j}{x-x_j}}
        let ws = xs
            .iter()
            .enumerate()
            .map(|(j, &xj)| {
                xs.iter()
                    .enumerate()
                    .filter(|&(i, _)| i != j)
                    .map(|(_, &xi)| xj - xi)
                    .reduce(Mul::mul)
                    .map_or_else(
                        || {
                            // In this situation, any w_0 value is acceptable
                            // because it will be cancelled out in L(x) since
                            //   L(x) = y = secret     V x E ...
                            assert!(
                                n == 0,
                                "zero-length weights should only happen with degree-0 polynomial"
                            );
                            Some(GfElem::ONE)
                        },
                        GfElem::inverse,
                    )
                    .expect("barycentric weights should not be zero")
            })
            .collect::<Vec<_>>();

        Ok(Self { xs, ys, ws })
    }
}

/// Interpolate the constant term of a polynomial of degree `n` in
/// `GF(2^32)`, given a set of points along that polynomial.
///
/// The process for this computation is [Lagrange interpolation][lagrange].
///
/// This much more efficient than both `GfBarycentric::recover(...).constant`
/// and `GfPolynomial::recover(...).constant()`, and thus should be used if you
/// only need to retreive the constant term of an unknown polynomial.
///
/// [lagrange]: https://en.wikipedia.org/wiki/Lagrange_polynomial
pub fn lagrange_constant<P: AsRef<[GfPoint]>>(
    n: GfElemPrimitive,
    points: P,
) -> Result<GfElem, Error> {
    let points = points.as_ref();
    let k = points.len();
    if k != (n + 1) as usize {
        return Err(Error::NumPointsMismatch {
            needed: (n + 1) as usize,
            num_points: k,
        });
    }

    let (xs, ys): (Vec<_>, Vec<_>) = points.iter().copied().unzip();

    // Pre-invert all x values to avoid recalculating it n times.
    let xs_inv = xs
        .iter()
        .map(|x| x.inverse().ok_or(Error::NonInvertiblePoint))
        .collect::<Result<Vec<_>, _>>()?;

    // To interpolate only the constant term of a polynomial, you can take
    // the full Lagrange polynomial expressions (which requires expanding a
    // multi binomial expression)
    //
    //     L(x) = \sum_{j_0}^k y_j l_j(x)
    //   l_j(x) = \prod_{m=0,m!=j}^{k} \frac{x-x_m}{x_j-x_m}
    //
    // where k is the number of points (which is equial to the threshold, or
    // the polynomial degree + 1), and simplify it. By substituting x=0
    // (removing all of the x terms) we get a simpler expression with no
    // multi binomial expansion
    //
    //     L(0) = \sum_{j_0}^k y_j l_j(0)
    //   l_j(0) = \prod_{m=0,m!=j}^{k} \frac{x_m}{x_m-x_j}
    //
    // and then you can make an additional simplification (to reduce the
    // number of numerical operations -- notably division because computing
    // the multiplicative inverse is currently fairly expensive) by
    // re-arranging the fraction so that we only need a single division at
    // the end and divisions are by individual x_m values, which we can
    // pre-compute the multiplicative inverse of
    //
    //        L(0) = \sum_{j_0}^k \frac{y_j}{linv_j(0)}
    //   linv_j(0) = \prod_{m=0,m!=j}^{k} (1-\frac{x_j}{x_m})
    //
    // giving us the final expression
    //
    //   L(0) = \sum_{j=0}^{k} \frac{y_j}
    //                              {\prod_{m=0,m!=j}^{k}
    //                                    (1-\frac{x_j}{x_m})}
    Ok((0..k).fold(GfElem::ZERO, |acc, j| {
        // \sum_{j=0}^{k} \frac{y_j}...
        acc + ys[j]
            // ...{linv_j(0)}
            / (0..k as usize)
                .filter(|&m| m != j)
                .fold(GfElem::ONE, |acc, m| {
                    // (1-frac{x_j}{x_m}) == (1-x_j*xinv_m)
                    acc * (GfElem::ONE - xs[j] * xs_inv[m])
                })
    }))
}

#[cfg(test)]
mod test {
    use super::*;

    use quickcheck::TestResult;
    use rand::rngs::OsRng;

    #[quickcheck]
    fn add_associativity(a: GfElem, b: GfElem) -> bool {
        (a + b) == (b + a)
    }

    #[quickcheck]
    fn mul_associativity(a: GfElem, b: GfElem) -> bool {
        (a * b) == (b * a)
    }

    #[quickcheck]
    fn add_commutativity(a: GfElem, b: GfElem, c: GfElem) -> bool {
        ((a + b) + c) == (a + (b + c))
    }

    #[quickcheck]
    fn mul_commutativity(a: GfElem, b: GfElem, c: GfElem) -> bool {
        ((a * b) * c) == (a * (b * c))
    }

    #[quickcheck]
    fn div_commutativity(a: GfElem, b: GfElem, c: GfElem, d: GfElem) -> TestResult {
        match (b, d) {
            (GfElem::ZERO, _) | (_, GfElem::ZERO) => TestResult::discard(),
            _ => TestResult::from_bool(((a / b) * (c / d)) == ((a * c) / (b * d))),
        }
    }

    #[quickcheck]
    fn add_identity(a: GfElem) -> bool {
        (a + GfElem::ZERO) == a
    }

    #[quickcheck]
    fn mul_identity(a: GfElem) -> bool {
        (a * GfElem::ONE) == a
    }

    #[quickcheck]
    fn mul_zero_identity(a: GfElem) -> bool {
        (a * GfElem::ZERO) == GfElem::ZERO
    }

    #[quickcheck]
    fn add_inverse(a: GfElem) -> bool {
        let a_inv = GfElem::ZERO - a;
        a + a_inv == GfElem::ZERO
    }

    #[quickcheck]
    fn add_inverse_alt(a: GfElem) -> bool {
        a - a == GfElem::ZERO
    }

    #[quickcheck]
    fn mul_inverse(a: GfElem) -> bool {
        match (a, a.inverse()) {
            (GfElem::ZERO, None) => true,
            (_, Some(a_inv)) => a * a_inv == GfElem::ONE,
            _ => false,
        }
    }

    #[quickcheck]
    fn div_inverse(a: GfElem) -> bool {
        match (a, a.inverse()) {
            (GfElem::ZERO, None) => true,
            (_, Some(a_inv)) => GfElem::ONE / a == a_inv,
            _ => false,
        }
    }

    #[quickcheck]
    fn div_inverse_alt(a: GfElem) -> bool {
        match a {
            GfElem::ZERO => true,
            _ => (a / a) == GfElem::ONE,
        }
    }

    #[quickcheck]
    fn div_mul_invertibility(a: GfElem, b: GfElem) -> TestResult {
        match b {
            GfElem::ZERO => TestResult::discard(),
            _ => TestResult::from_bool((a / b) * b == a),
        }
    }

    #[quickcheck]
    fn distributivity(a: GfElem, b: GfElem, c: GfElem) -> bool {
        (a * (b + c)) == ((a * b) + (a * c))
    }

    #[quickcheck]
    fn fractions(a: GfElem, b: GfElem, c: GfElem, d: GfElem) -> TestResult {
        match (b, d) {
            (GfElem::ZERO, _) | (_, GfElem::ZERO) => TestResult::discard(),
            _ => TestResult::from_bool(((a / b) + (c / d)) == (((a * d) + (c * b)) / (b * d))),
        }
    }

    // Inefficient, but "obviously correct" implementation of
    // GfPolynomial::evaluate(), to compare against for the test.
    fn manual_poly(poly: GfPolynomial, x: GfElem) -> GfElem {
        poly.0
            .iter()
            .enumerate()
            .map(|current| {
                let (n, &coeff) = current;
                coeff * x.pow(n)
            })
            .reduce(Add::add)
            .expect("must be at least one coefficient")
    }

    #[quickcheck]
    fn polynomial_evaluate(poly: GfPolynomial, x: GfElem) -> bool {
        poly.evaluate(x) == manual_poly(poly, x)
    }

    #[quickcheck]
    fn polynomial_add_distributivity(a: GfPolynomial, b: GfPolynomial, x: GfElem) -> bool {
        let ab = a.clone() + b.clone();
        ab.evaluate(x) == a.evaluate(x) + b.evaluate(x)
    }

    #[quickcheck]
    fn polynomial_constant(poly: GfPolynomial) -> bool {
        poly.evaluate(GfElem::ZERO) == poly.constant()
    }

    #[quickcheck]
    fn polynomial_lagrange_constant(poly: GfPolynomial) -> bool {
        let n = poly.degree();
        let xs = (0..n + 1)
            .map(|_| GfElem::new_rand(&mut OsRng))
            .collect::<Vec<_>>();
        let ys = xs.iter().map(|&x| poly.evaluate(x));
        let points = xs.iter().copied().zip(ys).collect::<Vec<_>>();
        let constant = lagrange_constant(n, points.as_slice())
            .expect("should not get errors from lagrange_constant");

        poly.constant() == constant
    }

    #[quickcheck]
    fn polynomial_lagrange_recover(poly: GfPolynomial) -> TestResult {
        let n = poly.degree();
        // Really large n values take a very long time to fully recover.
        if n > 85 {
            return TestResult::discard();
        }
        let xs = (0..n + 1)
            .map(|_| GfElem::new_rand(&mut OsRng))
            .collect::<Vec<_>>();
        let ys = xs.iter().map(|&x| poly.evaluate(x));
        let points = xs.iter().copied().zip(ys).collect::<Vec<_>>();
        let interpolated_poly =
            GfPolynomial::recover(n, points).expect("should not get errors from lagrange");

        TestResult::from_bool(poly == interpolated_poly)
    }

    #[quickcheck]
    fn polynomial_barycentric_recover(poly: GfPolynomial, test_xs: Vec<GfElem>) -> TestResult {
        let n = poly.degree();
        let xs = (0..n + 1)
            .map(|_| GfElem::new_rand(&mut OsRng))
            .collect::<Vec<_>>();
        let ys = xs.iter().map(|&x| poly.evaluate(x));
        let points = xs.iter().copied().zip(ys).collect::<Vec<_>>();
        let interpolated_poly = GfBarycentric::recover(n, points)
            .expect("should not get errors from barycentric recovery");

        TestResult::from_bool(
            test_xs
                .iter()
                .all(|&x| interpolated_poly.evaluate(x) == poly.evaluate(x)),
        )
    }
}
