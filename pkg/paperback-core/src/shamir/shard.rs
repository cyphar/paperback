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

use crate::{
    shamir::gf::{GfElem, GfElemPrimitive},
    v0::{FromWire, ShardId, ToWire},
};

use unsigned_varint::{encode as varuint_encode, nom as varuint_nom};

/// Piece of a secret which has been sharded with [Shamir Secret Sharing][sss].
///
/// [sss]: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Shard {
    pub(super) x: GfElem,
    pub(super) ys: Vec<GfElem>,
    pub(super) secret_len: usize,
    pub(super) threshold: GfElemPrimitive,
}

impl Shard {
    pub const ID_LENGTH: usize = 8;

    /// Returns the *unique* identifier for a given `Shard`.
    ///
    /// If two shards have the same identifier, they cannot be used together for
    /// secret recovery.
    pub fn id(&self) -> ShardId {
        multibase::encode(multibase::Base::Base32Z, &self.x.to_bytes())
    }

    /// Returns the number of *unique* sister `Shard`s required to recover the
    /// stored secret.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }
}

pub fn parse_id(id: ShardId) -> Result<GfElem, multibase::Error> {
    let (_, data) = multibase::decode(id)?;
    Ok(GfElem::from_bytes(data))
}

impl ToWire for Shard {
    fn to_wire(&self) -> Vec<u8> {
        let mut bytes = vec![];

        // Encode x-value.
        varuint_encode::u32(self.x.inner(), &mut varuint_encode::u32_buffer())
            .iter()
            .for_each(|b| bytes.push(*b));

        // Encode y-values (length-prefixed).
        varuint_encode::usize(self.ys.len(), &mut varuint_encode::usize_buffer())
            .iter()
            .copied()
            .chain(self.ys.iter().flat_map(|y| {
                varuint_encode::u32(y.inner(), &mut varuint_encode::u32_buffer()).to_owned()
            }))
            .for_each(|b| bytes.push(b));

        // Encode threshold.
        varuint_encode::u32(self.threshold, &mut varuint_encode::u32_buffer())
            .iter()
            .for_each(|b| bytes.push(*b));

        // Encode secret length.
        varuint_encode::usize(self.secret_len, &mut varuint_encode::usize_buffer())
            .iter()
            .for_each(|b| bytes.push(*b));

        bytes
    }
}

impl FromWire for Shard {
    fn from_wire_partial(input: &[u8]) -> Result<(&[u8], Self), String> {
        use nom::{combinator::complete, multi::many_m_n, IResult};

        fn parse(input: &[u8]) -> IResult<&[u8], Shard> {
            let (input, x) = varuint_nom::u32(input)?;
            let x = GfElem::from_inner(x);

            let (input, ys_length) = varuint_nom::usize(input)?;
            let (input, ys) = many_m_n(ys_length, ys_length, varuint_nom::u32)(input)?;
            let ys = ys
                .iter()
                .copied()
                .map(GfElem::from_inner)
                .collect::<Vec<_>>();

            let (input, threshold) = varuint_nom::u32(input)?;
            let (input, secret_len) = varuint_nom::usize(input)?;

            Ok((
                input,
                Shard {
                    x,
                    ys,
                    secret_len,
                    threshold,
                },
            ))
        }
        let mut parse = complete(parse);

        let (input, shard) = parse(input).map_err(|err| format!("{:?}", err))?;

        Ok((input, shard))
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for Shard {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        Self {
            x: GfElem::arbitrary(g),
            ys: (0..g.size()).map(|_| GfElem::arbitrary(g)).collect(),
            secret_len: usize::arbitrary(g),
            threshold: u32::arbitrary(g),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[quickcheck]
    fn shard_bytes_roundtrip(shard: Shard) {
        let shard2 = Shard::from_wire(&shard.to_wire()).unwrap();
        assert_eq!(shard, shard2);
    }
}
