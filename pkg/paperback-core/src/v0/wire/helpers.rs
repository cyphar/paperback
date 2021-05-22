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

use crate::v0::{
    wire::prefixes::*, ChaChaPolyKey, ChaChaPolyNonce, CHACHAPOLY_KEY_LENGTH,
    CHACHAPOLY_NONCE_LENGTH,
};

use ed25519_dalek::{PublicKey, SecretKey, Signature, SignatureError};
use multihash::Multihash;
use nom::{
    branch::alt,
    bytes::streaming::{tag, take},
    combinator::{map, verify},
    error::{Error as NomError, ErrorKind},
    sequence::tuple,
    Err as NomErr, IResult, Needed,
};
use signature::Signature as SignatureTrait;
use unsigned_varint::nom as varuint_nom;

pub(super) fn multihash(input: &[u8]) -> IResult<&[u8], Multihash> {
    use nom::sequence::pair;

    // Annoyingly, mulithash doesn't let you partially-read a slice so we
    // have to manually decode the length (the second parameter).
    let (partial, (_, length)) = pair(varuint_nom::u64, varuint_nom::usize)(input)?;

    // The length doesn't include the (type, length) prefix, so calculate that
    // based on the partially-parsed input. We return an Incomplete if there
    // isn't enough bytes for the hash (split_at would panic otherwise).
    let length = length + (input.len() - partial.len());
    if length > input.len() {
        return Err(NomErr::Incomplete(Needed::new(length - input.len())));
    }
    let (hash, input) = input.split_at(length);

    // All errors are just treated as format ("tag") errors. Sadly we can't
    // return much more context through nom at the moment (due to how
    // restrictive nom::error::ErrorKind is). Note that an InvalidSize error
    // from multihash actually is a format error -- we checked that we had
    // enough bytes above.
    let hash = Multihash::from_bytes(hash)
        .map_err(|_| NomErr::Error(NomError::new(input, ErrorKind::Tag)))?;
    Ok((input, hash))
}

pub(super) fn take_ed25519_pub(input: &[u8]) -> IResult<&[u8], Result<PublicKey, SignatureError>> {
    let (input, _) = verify(varuint_nom::u32, |x| *x == PREFIX_ED25519_PUB)(input)?;
    let (input, public_key) = take(ed25519_dalek::PUBLIC_KEY_LENGTH)(input)?;

    Ok((input, PublicKey::from_bytes(public_key)))
}

pub(super) fn take_ed25519_sig(input: &[u8]) -> IResult<&[u8], Result<Signature, SignatureError>> {
    let (input, _) = verify(varuint_nom::u32, |x| *x == PREFIX_ED25519_SIG)(input)?;
    let (input, public_key) = take(ed25519_dalek::SIGNATURE_LENGTH)(input)?;

    Ok((input, Signature::from_bytes(public_key)))
}

pub(super) fn take_ed25519_sec(
    input: &[u8],
) -> IResult<&[u8], Option<Result<SecretKey, SignatureError>>> {
    let (input, (_, private_key)) = alt((
        tuple((
            // Unsealed document -- fetch the key.
            verify(varuint_nom::u64, |x| *x == PREFIX_ED25519_SECRET),
            map(take(ed25519_dalek::SECRET_KEY_LENGTH), Option::Some),
        )),
        tuple((
            // Sealed document -- ensure the key is all zeroes.
            verify(varuint_nom::u64, |x| *x == PREFIX_ED25519_SECRET_SEALED),
            map(tag(&[0u8; ed25519_dalek::SECRET_KEY_LENGTH][..]), |_| None),
        )),
    ))(input)?;

    Ok((input, private_key.map(SecretKey::from_bytes)))
}

pub(super) fn take_chachapoly_key(input: &[u8]) -> IResult<&[u8], ChaChaPolyKey> {
    let (input, _) = verify(varuint_nom::u64, |x| *x == PREFIX_CHACHA20POLY1305_KEY)(input)?;
    let (input, key) = take(CHACHAPOLY_KEY_LENGTH)(input)?;

    Ok((input, {
        let mut buffer = ChaChaPolyKey::default();
        buffer.copy_from_slice(key);
        buffer
    }))
}

pub(super) fn take_chachapoly_nonce(input: &[u8]) -> IResult<&[u8], ChaChaPolyNonce> {
    let (input, _) = verify(varuint_nom::u64, |x| *x == PREFIX_CHACHA20POLY1305_NONCE)(input)?;
    let (input, nonce) = take(CHACHAPOLY_NONCE_LENGTH)(input)?;

    Ok((input, {
        let mut buffer = ChaChaPolyNonce::default();
        buffer.copy_from_slice(nonce);
        buffer
    }))
}

pub(super) fn take_chachapoly_ciphertext(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, _) = verify(varuint_nom::u64, |x| {
        *x == PREFIX_CHACHA20POLY1305_CIPHERTEXT
    })(input)?;
    let (input, length) = varuint_nom::usize(input)?;

    take(length)(input)
}
