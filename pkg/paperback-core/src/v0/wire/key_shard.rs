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

use crate::{
    shamir::Shard,
    v0::{
        wire::{prefixes::*, FromWire, ToWire},
        ChaChaPolyNonce, EncryptedKeyShard, Identity, KeyShard, KeyShardBuilder,
        CHACHAPOLY_NONCE_LENGTH, CHECKSUM_ALGORITHM,
    },
};

use multihash::Multihash;
use unsigned_varint::{encode as varuint_encode, nom as varuint_nom};

// Internal only -- users can't see KeyShardBuilder.
#[doc(hidden)]
impl ToWire for KeyShardBuilder {
    fn to_wire(&self) -> Vec<u8> {
        let mut buffer = varuint_encode::u32_buffer();
        let mut bytes = vec![];

        // Encode version.
        varuint_encode::u32(self.version, &mut buffer)
            .iter()
            .for_each(|b| bytes.push(*b));

        // Encode multihash checksum.
        self.doc_chksum
            .to_bytes()
            .iter()
            .for_each(|b| bytes.push(*b));

        // Encode shard data.
        bytes.append(&mut self.shard.to_wire());

        bytes
    }
}

// Internal only -- users can't see KeyShardBuilder.
#[doc(hidden)]
impl FromWire for KeyShardBuilder {
    fn from_wire_partial(input: &[u8]) -> Result<(Self, &[u8]), String> {
        use crate::v0::wire::helpers::multihash;
        use nom::{combinator::complete, IResult};

        fn parse(input: &[u8]) -> IResult<&[u8], (u32, Multihash)> {
            let (input, version) = varuint_nom::u32(input)?;
            let (input, doc_chksum) = multihash(input)?;

            Ok((input, (version, doc_chksum.to_owned())))
        }
        let mut parse = complete(parse);

        let (input, (version, doc_chksum)) = parse(input).map_err(|err| format!("{:?}", err))?;
        let (shard, remain) = Shard::from_wire_partial(input)?;

        Ok((
            KeyShardBuilder {
                version,
                doc_chksum,
                shard,
            },
            remain,
        ))
    }
}

/// Internal only -- users should use EncryptedKeyShard's ToWire.
#[doc(hidden)]
impl ToWire for KeyShard {
    fn to_wire(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.append(&mut self.inner.to_wire());
        bytes.append(&mut self.identity.to_wire());

        bytes
    }
}

/// Internal only -- users should use EncryptedKeyShard's FromWire.
#[doc(hidden)]
impl FromWire for KeyShard {
    fn from_wire_partial(input: &[u8]) -> Result<(Self, &[u8]), String> {
        let (inner, input) = KeyShardBuilder::from_wire_partial(input)?;
        let (identity, input) = Identity::from_wire_partial(input)?;

        if inner.doc_chksum.code() != CHECKSUM_ALGORITHM.into() {
            return Err(format!("document checksum must be Blake2b-256",));
        }

        if inner.version != 0 {
            return Err(format!(
                "key shard version must be '0' not '{}'",
                inner.version
            ));
        }

        Ok((KeyShard { inner, identity }, input))
    }
}

impl ToWire for EncryptedKeyShard {
    fn to_wire(&self) -> Vec<u8> {
        let mut buffer = varuint_encode::u64_buffer();
        let mut bytes = vec![];

        // Encode ChaCha20-Poly1305 nonce.
        varuint_encode::u64(PREFIX_CHACHA20POLY1305_NONCE, &mut buffer)
            .iter()
            .chain(&self.nonce)
            .for_each(|b| bytes.push(*b));
        assert_eq!(self.nonce.len(), CHACHAPOLY_NONCE_LENGTH);

        // Encode ChaCha20-Poly1305 ciphertext (length-prefixed).
        varuint_encode::u64(PREFIX_CHACHA20POLY1305_CIPHERTEXT, &mut buffer)
            .iter()
            .chain(varuint_encode::usize(
                self.ciphertext.len(),
                &mut varuint_encode::usize_buffer(),
            ))
            .chain(&self.ciphertext)
            .for_each(|b| bytes.push(*b));

        bytes
    }
}

impl FromWire for EncryptedKeyShard {
    fn from_wire_partial(input: &[u8]) -> Result<(Self, &[u8]), String> {
        use crate::v0::wire::helpers::{take_chachapoly_ciphertext, take_chachapoly_nonce};
        use nom::{combinator::complete, IResult};

        fn parse(input: &[u8]) -> IResult<&[u8], (ChaChaPolyNonce, &[u8])> {
            let (input, nonce) = take_chachapoly_nonce(input)?;
            let (input, ciphertext) = take_chachapoly_ciphertext(input)?;

            Ok((input, (nonce, ciphertext)))
        }
        let mut parse = complete(parse);

        let (remain, (nonce, ciphertext)) = parse(input).map_err(|err| format!("{:?}", err))?;

        Ok((
            EncryptedKeyShard {
                nonce,
                ciphertext: ciphertext.into(),
            },
            remain,
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[quickcheck]
    fn key_shard_builder_roundtrip(inner: KeyShardBuilder) {
        let inner2 = KeyShardBuilder::from_wire(inner.to_wire()).unwrap();
        assert_eq!(inner, inner2);
    }

    #[quickcheck]
    fn key_shard_roundtrip(shard: KeyShard) {
        let shard2 = KeyShard::from_wire(shard.to_wire()).unwrap();
        assert_eq!(shard, shard2);
    }

    #[quickcheck]
    fn encrypted_key_shard_roundtrip(shard: EncryptedKeyShard) {
        let shard2 = EncryptedKeyShard::from_wire(shard.to_wire()).unwrap();
        assert_eq!(shard, shard2);
    }
}
