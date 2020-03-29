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

mod internal;
mod key_shard;
mod main_document;

pub(crate) mod prefixes {
    /// Prefix for an ed25519 public key.
    pub(crate) const PREFIX_ED25519_PUB: u32 = 0xed;

    /// Prefix for an ed25519 signature.
    // NOTE: Not actually upstream -- see multiformats/multicodec#142.
    pub(super) const PREFIX_ED25519_SIG: u32 = 0xef;

    /// Prefix for an ed25519 secret key.
    // NOTE: Entirely our own creation and not remotely upstreamable.
    pub(super) const PREFIX_ED25519_SECRET: u64 = 0xff_ed25519_5ec;

    /// Prefix for an ed25519 secret key which has been sealed (equivalent to None).
    // NOTE: Entirely our own creation and not remotely upstreamable.
    pub(super) const PREFIX_ED25519_SECRET_SEALED: u64 = 0xff_ed25519_000;

    /// Prefix for a ChaCha20-Poly1305 key.
    // NOTE: Entirely our own creation and not remotely upstreamable.
    pub(super) const PREFIX_CHACHA20POLY1305_KEY: u64 = 0xff_caca20_1305;

    /// Prefix for a ChaCha20-Poly1305 nonce.
    // NOTE: Entirely our own creation and not remotely upstreamable.
    pub(super) const PREFIX_CHACHA20POLY1305_NONCE: u64 = 0xfe_caca20_1305;

    /// Prefix for a ChaCha20-Poly1305 nonce.
    // NOTE: Entirely our own creation and not remotely upstreamable.
    pub(super) const PREFIX_CHACHA20POLY1305_CIPHERTEXT: u64 = 0xfc_caca20_1305;
}

pub trait ToWire {
    fn to_wire(&self) -> Vec<u8>;
}

pub trait FromWire: Sized {
    fn from_wire_partial(input: &[u8]) -> Result<(Self, &[u8]), String>;

    fn from_wire<B: AsRef<[u8]>>(input: B) -> Result<Self, String> {
        match Self::from_wire_partial(input.as_ref())? {
            (ret, []) => Ok(ret),
            _ => Err("trailing bytes left after deseralisation".into()),
        }
    }
}
