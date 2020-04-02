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

#![allow(dead_code)]

use nom::{error::ErrorKind, Err as NomErr, IResult, Needed};
use unsigned_varint::decode::{self, Error};

// This is copied from a PR I wrote to add a nom parser to unsigned-varint:
//   <https://github.com/paritytech/unsigned-varint/pull/27>
macro_rules! gen {
    ($($type:ident, $d:expr, $b:ident);*) => {
        $(
            #[doc = " `nom` combinator to decode a variable-length encoded "]
            #[doc = $d]
            #[doc = "."]
            pub fn $type(input: &[u8]) -> IResult<&[u8], $type> {
                let (n, remain) = decode::$type(input).map_err(|err| match err {
                    Error::Insufficient => NomErr::Incomplete(Needed::Unknown),
                    Error::Overflow | _ => NomErr::Error((input, ErrorKind::TooLarge)),
                })?;
                Ok((remain, n))
            }
        )*
    }
}

gen! {
    u8,    "`u8`",    u8_buffer;
    u16,   "`u16`",   u16_buffer;
    u32,   "`u32`",   u32_buffer;
    u64,   "`u64`",   u64_buffer;
    u128,  "`u128`",  u128_buffer;
    usize, "`usize`", usize_buffer
}
