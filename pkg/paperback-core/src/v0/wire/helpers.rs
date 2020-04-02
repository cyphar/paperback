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
    nom_helpers,
    v0::{
        wire::prefixes::*, ChaChaPolyKey, ChaChaPolyNonce, CHACHAPOLY_KEY_LENGTH,
        CHACHAPOLY_NONCE_LENGTH,
    },
};

use ed25519_dalek::{PublicKey, SecretKey, Signature, SignatureError};
use multihash::{DecodeError, MultihashRef};
use nom::{
    branch::alt,
    bytes::streaming::{tag, take},
    combinator::{map, verify},
    error::ErrorKind,
    sequence::tuple,
    Err as NomErr, IResult, Needed,
};

pub(super) fn multihash(input: &[u8]) -> IResult<&[u8], MultihashRef> {
    use nom::sequence::pair;

    // Annoyingly, mulithash doesn't let you partially-read a slice so we
    // have to manually decode the length (the second parameter).
    let (partial, (_, length)) = pair(nom_helpers::u64, nom_helpers::usize)(input)?;

    // The length doesn't include the (type, length) prefix, so calculate
    // that based on the partially-parsed input.
    let length = length + (input.len() - partial.len());
    let (hash, input) = input.split_at(length);

    let hash = MultihashRef::from_slice(hash).map_err(|err| match err {
        DecodeError::BadInputLength => NomErr::Incomplete(Needed::Unknown),
        DecodeError::UnknownCode => NomErr::Error((input, ErrorKind::Tag)),
    })?;

    Ok((input, hash))
}

pub(super) fn take_ed25519_pub(input: &[u8]) -> IResult<&[u8], Result<PublicKey, SignatureError>> {
    let (input, _) = verify(nom_helpers::u32, |x| *x == PREFIX_ED25519_PUB)(input)?;
    let (input, public_key) = take(ed25519_dalek::PUBLIC_KEY_LENGTH)(input)?;

    Ok((input, PublicKey::from_bytes(public_key)))
}

pub(super) fn take_ed25519_sig(input: &[u8]) -> IResult<&[u8], Result<Signature, SignatureError>> {
    let (input, _) = verify(nom_helpers::u32, |x| *x == PREFIX_ED25519_SIG)(input)?;
    let (input, public_key) = take(ed25519_dalek::SIGNATURE_LENGTH)(input)?;

    Ok((input, Signature::from_bytes(public_key)))
}

pub(super) fn take_ed25519_sec(
    input: &[u8],
) -> IResult<&[u8], Option<Result<SecretKey, SignatureError>>> {
    let (input, (_, private_key)) = alt((
        tuple((
            // Unsealed document -- fetch the key.
            verify(nom_helpers::u64, |x| *x == PREFIX_ED25519_SECRET),
            map(take(ed25519_dalek::SECRET_KEY_LENGTH), Option::Some),
        )),
        tuple((
            // Sealed document -- ensure the key is all zeroes.
            verify(nom_helpers::u64, |x| *x == PREFIX_ED25519_SECRET_SEALED),
            map(tag(&[0u8; ed25519_dalek::SECRET_KEY_LENGTH][..]), |_| None),
        )),
    ))(input)?;

    Ok((input, private_key.map(SecretKey::from_bytes)))
}

pub(super) fn take_chachapoly_key(input: &[u8]) -> IResult<&[u8], ChaChaPolyKey> {
    let (input, _) = verify(nom_helpers::u64, |x| *x == PREFIX_CHACHA20POLY1305_KEY)(input)?;
    let (input, key) = take(CHACHAPOLY_KEY_LENGTH)(input)?;

    Ok((input, {
        let mut buffer = ChaChaPolyKey::default();
        buffer.copy_from_slice(key);
        buffer
    }))
}

pub(super) fn take_chachapoly_nonce(input: &[u8]) -> IResult<&[u8], ChaChaPolyNonce> {
    let (input, _) = verify(nom_helpers::u64, |x| *x == PREFIX_CHACHA20POLY1305_NONCE)(input)?;
    let (input, nonce) = take(CHACHAPOLY_NONCE_LENGTH)(input)?;

    Ok((input, {
        let mut buffer = ChaChaPolyNonce::default();
        buffer.copy_from_slice(nonce);
        buffer
    }))
}

pub(super) fn take_chachapoly_ciphertext(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, _) = verify(nom_helpers::u64, |x| {
        *x == PREFIX_CHACHA20POLY1305_CIPHERTEXT
    })(input)?;
    let (input, length) = nom_helpers::usize(input)?;

    take(length)(input)
}
