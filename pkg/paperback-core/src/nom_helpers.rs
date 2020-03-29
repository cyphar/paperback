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

use multihash::{DecodeError, MultihashRef};
use nom::{error::ErrorKind, Err as NomErr, IResult, Needed};
use unsigned_varint::decode::{self, Error};

pub(crate) fn multihash() -> impl Fn(&[u8]) -> IResult<&[u8], MultihashRef> {
    move |input: &[u8]| {
        use nom::sequence::pair;

        // Annoyingly, mulithash doesn't let you partially-read a slice so we
        // have to manually decode the length (the second parameter).
        let (partial, (_, length)) = pair(u64(), usize())(input)?;

        // The length doesn't include the (type, length) prefix, so calculate
        // that based on the partially-parsed input.
        let length = length + (input.len() - partial.len());
        let (hash_input, hash_remain) = input.split_at(length);

        let hash = MultihashRef::from_slice(hash_input).map_err(|err| match err {
            DecodeError::BadInputLength => NomErr::Incomplete(Needed::Unknown),
            DecodeError::UnknownCode => NomErr::Error((input, ErrorKind::Tag)),
        })?;

        Ok((hash_remain, hash))
    }
}

// This is copied from a PR I wrote to add a nom parser to unsigned-varint:
//   <https://github.com/paritytech/unsigned-varint/pull/27>
macro_rules! gen {
    ($($name:ident, $name_tag:ident, $d:expr, $t:ident, $b:ident);*) => {
        $(
            pub(crate) fn $name() -> impl Fn(&[u8]) -> IResult<&[u8], $t> {
                move |input: &[u8]| {
                    let (n, remain) = decode::$t(input).map_err(|err| match err {
                        Error::Insufficient => NomErr::Incomplete(Needed::Unknown),
                        _ => NomErr::Error((input, ErrorKind::TooLarge)),
                    })?;
                    Ok((remain, n))
                }
            }

            pub(crate) fn $name_tag(tag: $t) -> impl Fn(&[u8]) -> IResult<&[u8], $t> {
                move |input: &[u8]| {
                    match $name()(input)? {
                        (remain, n) if n == tag => Ok((remain, tag)),
                        _ => Err(NomErr::Error((input, ErrorKind::Tag))),
                    }
                }
            }
        )*
    }
}

gen! {
    u8,    u8_tag,    "`u8`",    u8,    u8_buffer;
    u16,   u16_tag,   "`u16`",   u16,   u16_buffer;
    u32,   u32_tag,   "`u32`",   u32,   u32_buffer;
    u64,   u64_tag,   "`u64`",   u64,   u64_buffer;
    u128,  u128_tag,  "`u128`",  u128,  u128_buffer;
    usize, usize_tag, "`usize`", usize, usize_buffer
}
