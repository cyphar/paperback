/*
 * paperback: paper backup generator suitable for long-term storage
 * Copyright (C) 2018-2022 Aleksa Sarai <cyphar@cyphar.com>
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

#![forbid(unsafe_code)]

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use]
extern crate quickcheck_macros;

/// Implementation of Shamir Secret Sharing.
#[cfg(not(feature = "donotuse_expose_internal_modules"))]
mod shamir;

// Expose the module so we can benchmark it with criterion. This feature is only enabled as a
// dev-dependency.
#[cfg(feature = "donotuse_expose_internal_modules")]
pub mod shamir;

/// Initial version of paperback wire format types.
///
/// This module also includes all of the necessary code to serialise and
/// interact with the relevant structures.
pub mod v0;

/// Re-export of the newest paperback wire format types.
pub use v0 as latest;
