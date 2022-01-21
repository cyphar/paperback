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

use crate::v0::{
    wire::{prefixes::*, FromWire, ToWire},
    ChaChaPolyKey, Identity, ShardSecret,
};

use ed25519_dalek::{PublicKey, SecretKey, Signature, SignatureError};
use unsigned_varint::encode as varuint_encode;

// TODO: Completely rewrite this code. This is a very quick-and-dirty
//       implementation of the main serialisation code, but we'll need to
//       properly implement it to be both compact and contain self-describing
//       information such as multi-base and multi-hash prefixes.
//

// Internal only -- users can't see Identity.
impl ToWire for Identity {
    fn to_wire(&self) -> Vec<u8> {
        let mut buffer = varuint_encode::u32_buffer();
        let mut bytes = vec![];

        // Encode ed25519 public key (with multicodec prefix).
        varuint_encode::u32(PREFIX_ED25519_PUB, &mut buffer)
            .iter()
            .chain(self.id_public_key.as_bytes())
            .for_each(|b| bytes.push(*b));

        // Encode ed25519 signature (with multicodec prefix).
        varuint_encode::u32(PREFIX_ED25519_SIG, &mut buffer)
            .iter()
            .chain(&self.id_signature.to_bytes()[..])
            .for_each(|b| bytes.push(*b));

        bytes
    }
}

type IdentityParseResult = (
    Result<PublicKey, SignatureError>,
    Result<Signature, SignatureError>,
);

// Internal only -- users can't see Identity.
impl FromWire for Identity {
    fn from_wire_partial(input: &[u8]) -> Result<(&[u8], Self), String> {
        use crate::v0::wire::helpers::{take_ed25519_pub, take_ed25519_sig};
        use nom::{combinator::complete, IResult};

        fn parse(input: &[u8]) -> IResult<&[u8], IdentityParseResult> {
            let (input, public_key) = take_ed25519_pub(input)?;
            let (input, signature) = take_ed25519_sig(input)?;

            Ok((input, (public_key, signature)))
        }
        let mut parse = complete(parse);

        let (input, (public_key, signature)) = parse(input).map_err(|err| format!("{:?}", err))?;

        Ok((
            input,
            Identity {
                id_public_key: public_key.map_err(|err| format!("{:?}", err))?,
                id_signature: signature.map_err(|err| format!("{:?}", err))?,
            },
        ))
    }
}

// Internal only -- users can't see ShardSecret.
impl ToWire for ShardSecret {
    fn to_wire(&self) -> Vec<u8> {
        let mut buffer = varuint_encode::u64_buffer();
        let mut bytes = vec![];

        // Encode ChaCha20-Poly1305 key.
        varuint_encode::u64(PREFIX_CHACHA20POLY1305_KEY, &mut buffer)
            .iter()
            .chain(&self.doc_key)
            .for_each(|b| bytes.push(*b));

        let (prefix, id_private_key) = match &self.id_private_key {
            Some(key) => (PREFIX_ED25519_SECRET, key.as_bytes()),
            None => (
                PREFIX_ED25519_SECRET_SEALED,
                &[0u8; ed25519_dalek::SECRET_KEY_LENGTH],
            ),
        };

        // Encode ed25519 private key.
        // NOTE: Not actually upstream.
        varuint_encode::u64(prefix, &mut buffer)
            .iter()
            .chain(&id_private_key[..])
            .for_each(|b| bytes.push(*b));

        bytes
    }
}

type ShardSecretParseResult = (ChaChaPolyKey, Option<Result<SecretKey, SignatureError>>);

// Internal only -- users can't see ShardSecret.
impl FromWire for ShardSecret {
    fn from_wire_partial(input: &[u8]) -> Result<(&[u8], Self), String> {
        use crate::v0::wire::helpers::{take_chachapoly_key, take_ed25519_sec};
        use nom::{combinator::complete, IResult};

        fn parse(input: &[u8]) -> IResult<&[u8], ShardSecretParseResult> {
            let (input, doc_key) = take_chachapoly_key(input)?;
            let (input, private_key) = take_ed25519_sec(input)?;

            Ok((input, (doc_key, private_key)))
        }
        let mut parse = complete(parse);

        let (input, (doc_key, private_key)) = parse(input).map_err(|err| format!("{:?}", err))?;

        let id_private_key = match private_key {
            Some(Ok(key)) => Some(key),
            None => None,
            Some(Err(err)) => return Err(format!("{:?}", err)),
        };

        Ok((
            input,
            ShardSecret {
                doc_key,
                id_private_key,
            },
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use ed25519_dalek::{Keypair, Signer};
    use rand::{rngs::OsRng, RngCore};

    // TODO: Get rid of this ugliness.
    impl PartialEq for ShardSecret {
        fn eq(&self, other: &Self) -> bool {
            self.doc_key == other.doc_key
                && match (&self.id_private_key, &other.id_private_key) {
                    (Some(left), Some(right)) => left.to_bytes() == right.to_bytes(),
                    (None, None) => true,
                    _ => false,
                }
        }
    }

    #[quickcheck]
    fn identity_roundtrip(data: Vec<u8>) -> bool {
        let id_keypair = Keypair::generate(&mut OsRng);

        let id_public_key = id_keypair.public.clone();
        let id_signature = id_keypair.sign(&data);

        let identity = Identity {
            id_public_key,
            id_signature,
        };
        let identity2 = Identity::from_wire(identity.to_wire()).unwrap();

        identity == identity2
    }

    #[quickcheck]
    fn shard_secret_roundtrip(_: u32, sealed: bool) -> bool {
        let mut doc_key = ChaChaPolyKey::default();
        OsRng.fill_bytes(&mut doc_key);

        let secret = ShardSecret {
            doc_key: doc_key,
            id_private_key: match sealed {
                true => None,
                false => Some(Keypair::generate(&mut OsRng).secret),
            },
        };
        let secret2 = ShardSecret::from_wire(secret.to_wire()).unwrap();

        secret == secret2
    }
}
