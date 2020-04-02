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

use crate::{shamir::Shard, v0::wire::prefixes::*};

use aead::{generic_array::GenericArray, Aead, NewAead};
use bip39::{Language, Mnemonic};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::{Keypair, PublicKey, Signature};
use multihash::{Blake2b256, Multihash, MultihashDigest};
use rand::{rngs::OsRng, RngCore};
use unsigned_varint::encode;

pub type ShardId = String;
pub type DocumentId = String;

type ChaChaPolyKey = GenericArray<u8, <ChaCha20Poly1305 as NewAead>::KeySize>;
const CHACHAPOLY_KEY_LENGTH: usize = 32usize;

type ChaChaPolyNonce = GenericArray<u8, <ChaCha20Poly1305 as Aead>::NonceSize>;
const CHACHAPOLY_NONCE_LENGTH: usize = 12usize;

#[cfg(test)]
#[test]
fn check_length_consts() {
    // GenericArray doesn't give us a way to get the size, so we need to do this
    // in a test...
    assert_eq!(CHACHAPOLY_KEY_LENGTH, ChaChaPolyKey::default().len());
    assert_eq!(CHACHAPOLY_NONCE_LENGTH, ChaChaPolyNonce::default().len());
}

const CHECKSUM_ALGORITHM: Blake2b256 = Blake2b256;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Identity {
    id_public_key: PublicKey,
    id_signature: Signature,
}

#[cfg(test)]
impl quickcheck::Arbitrary for Identity {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
        let bytes = Vec::<u8>::arbitrary(g);

        let id_keypair = Keypair::generate(&mut OsRng);
        let id_signature = id_keypair.sign(&bytes);

        Self {
            id_public_key: id_keypair.public,
            id_signature,
        }
    }
}

#[derive(Debug)]
struct ShardSecret {
    doc_key: ChaChaPolyKey,
    id_private_key: Option<ed25519_dalek::SecretKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeyShardBuilder {
    version: u32, // must be 0 for this version
    doc_chksum: Multihash,
    shard: Shard,
}

impl KeyShardBuilder {
    fn signable_bytes(&self, id_public_key: &PublicKey) -> Vec<u8> {
        let mut bytes = self.to_wire();

        // Append the Ed25519 public key used for signing.
        encode::u32(PREFIX_ED25519_PUB, &mut encode::u32_buffer())
            .iter()
            .chain(id_public_key.as_bytes())
            .for_each(|b| bytes.push(*b));
        bytes
    }

    fn sign(self, id_keypair: &Keypair) -> KeyShard {
        let bytes = self.signable_bytes(&id_keypair.public);
        KeyShard {
            inner: self,
            identity: Identity {
                id_public_key: id_keypair.public.clone(),
                id_signature: id_keypair.sign(&bytes),
            },
        }
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for KeyShardBuilder {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
        let bytes = Vec::<u8>::arbitrary(g);
        Self {
            version: 0,
            doc_chksum: CHECKSUM_ALGORITHM.digest(&bytes[..]),
            shard: Shard::arbitrary(g),
        }
    }
}

const CODEWORD_LANGUAGE: Language = Language::English;
pub type KeyShardCodewords = [String; 24];

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct KeyShard {
    inner: KeyShardBuilder,
    identity: Identity,
}

#[cfg(test)]
impl quickcheck::Arbitrary for KeyShard {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
        let id_keypair = Keypair::generate(&mut OsRng);
        KeyShardBuilder::arbitrary(g).sign(&id_keypair)
    }
}

impl KeyShard {
    pub const ID_LENGTH: usize = Shard::ID_LENGTH;

    pub fn id(&self) -> ShardId {
        self.inner.shard.id()
    }

    pub fn encrypt(self) -> Result<(EncryptedKeyShard, KeyShardCodewords), String> {
        // Serialise.
        let wire_shard = self.to_wire();

        // Generate key and nonce.
        let mut shard_key = ChaChaPolyKey::default();
        OsRng.fill_bytes(&mut shard_key);
        let mut shard_nonce = ChaChaPolyNonce::default();
        OsRng.fill_bytes(&mut shard_nonce);

        // Encrypt the contents.
        let aead = ChaCha20Poly1305::new(shard_key);
        let wire_shard = aead
            .encrypt(&shard_nonce, wire_shard.as_slice())
            .map_err(|err| format!("{:?}", err))?; // XXX: Ugly, fix this.

        // Convert key to a BIP-39 mnemonic.
        let phrase = Mnemonic::from_entropy(&shard_key, CODEWORD_LANGUAGE)
            .map_err(|e| format!("{:?}", e))? // XXX: Ugly, fix this.
            .into_phrase();
        let mut codewords = KeyShardCodewords::default();
        codewords.clone_from_slice(
            phrase
                .split_whitespace()
                .map(|s| s.to_owned())
                .collect::<Vec<_>>()
                .as_slice(),
        );

        // Create wrapper shard.
        let shard = EncryptedKeyShard {
            nonce: shard_nonce,
            ciphertext: wire_shard,
        };

        Ok((shard, codewords))
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct EncryptedKeyShard {
    nonce: ChaChaPolyNonce,
    ciphertext: Vec<u8>,
}

impl EncryptedKeyShard {
    pub fn decrypt(self, codewords: &KeyShardCodewords) -> Result<KeyShard, String> {
        // Convert BIP-39 mnemonic to a key.
        let phrase = codewords[..].join(" ").to_lowercase();
        let mnemonic =
            Mnemonic::from_phrase(&phrase, CODEWORD_LANGUAGE).map_err(|e| format!("{:?}", e))?; // XXX: Ugly, fix this.

        let mut shard_key = ChaChaPolyKey::default();
        shard_key.copy_from_slice(mnemonic.entropy());

        // Decrypt the contents.
        let aead = ChaCha20Poly1305::new(shard_key);
        let wire_shard = aead
            .decrypt(&self.nonce, self.ciphertext.as_slice())
            .map_err(|err| format!("{:?}", err))?; // XXX: Ugly, fix this.

        // Deserialise.
        KeyShard::from_wire(wire_shard)
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for EncryptedKeyShard {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
        let mut nonce = ChaChaPolyNonce::default();
        g.fill_bytes(&mut nonce);
        let ciphertext = Vec::<u8>::arbitrary(g);
        Self { nonce, ciphertext }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MainDocumentMeta {
    version: u32, // must be 0 for this version
    quorum_size: u32,
}

impl MainDocumentMeta {
    fn aad(&self, id_public_key: &PublicKey) -> Vec<u8> {
        let mut bytes = self.to_wire();

        // Append the public key used for signing.
        // XXX: Make this much nicer...
        bytes.push('k' as u8);
        id_public_key.as_bytes().iter().for_each(|b| bytes.push(*b));

        bytes
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for MainDocumentMeta {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
        Self {
            version: 0,
            quorum_size: g.next_u32(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MainDocumentBuilder {
    meta: MainDocumentMeta,
    nonce: ChaChaPolyNonce,
    ciphertext: Vec<u8>,
}

impl MainDocumentBuilder {
    fn signable_bytes(&self, id_public_key: &PublicKey) -> Vec<u8> {
        let mut bytes = self.to_wire();

        // Append the Ed25519 public key used for signing.
        encode::u32(PREFIX_ED25519_PUB, &mut encode::u32_buffer())
            .iter()
            .chain(id_public_key.as_bytes())
            .for_each(|b| bytes.push(*b));
        bytes
    }

    fn sign(self, id_keypair: &Keypair) -> MainDocument {
        let bytes = self.signable_bytes(&id_keypair.public);
        MainDocument {
            inner: self,
            identity: Identity {
                id_public_key: id_keypair.public.clone(),
                id_signature: id_keypair.sign(&bytes),
            },
        }
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for MainDocumentBuilder {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
        let mut nonce = ChaChaPolyNonce::default();
        g.fill_bytes(&mut nonce);
        Self {
            meta: MainDocumentMeta::arbitrary(g),
            nonce,
            ciphertext: Vec::<u8>::arbitrary(g),
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct MainDocument {
    inner: MainDocumentBuilder,
    identity: Identity,
}

impl MainDocument {
    pub const ID_LENGTH: usize = 8;

    pub fn checksum(&self) -> Multihash {
        CHECKSUM_ALGORITHM.digest(&self.to_wire())
    }

    pub fn id(&self) -> DocumentId {
        let doc_chksum = self.checksum();
        let encoded_chksum = zbase32::encode_full_bytes(doc_chksum.as_bytes());
        // The *suffix* is the ID.
        let short_id = &encoded_chksum[encoded_chksum.len() - Self::ID_LENGTH..];

        short_id.to_string()
    }

    pub fn quorum_size(&self) -> u32 {
        self.inner.meta.quorum_size
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for MainDocument {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
        let id_keypair = Keypair::generate(&mut OsRng);
        MainDocumentBuilder::arbitrary(g).sign(&id_keypair)
    }
}

mod wire;
pub use wire::*;

mod recover;
pub use recover::*;

mod backup;
pub use backup::*;

#[cfg(test)]
mod test {
    use super::*;

    use quickcheck::TestResult;

    #[quickcheck]
    fn paperback_roundtrip_smoke(quorum_size: u32, secret: Vec<u8>) -> TestResult {
        if quorum_size < 2 || quorum_size > 20 {
            return TestResult::discard();
        }

        // Construct a backup.
        let backup = Backup::new(quorum_size, &secret).unwrap();
        let main_document = backup.main_document().clone();
        let shards = (0..quorum_size)
            .map(|_| backup.next_shard().unwrap())
            .map(|s| s.encrypt().unwrap())
            .collect::<Vec<_>>();

        // Go through a round-trip through serialisation.
        let main_document = {
            let bytes = main_document.to_wire();
            MainDocument::from_wire(bytes).unwrap()
        };
        let shards = shards
            .iter()
            .map(|(shard, codewords)| {
                let bytes = shard.to_wire();
                let shard = EncryptedKeyShard::from_wire(bytes).unwrap();
                (shard, codewords)
            })
            .collect::<Vec<_>>();

        // Construct a quorum.
        let mut quorum = UntrustedQuorum::new();
        quorum.main_document(main_document);
        for (shard, codewords) in shards {
            let shard = shard.decrypt(codewords).unwrap();
            quorum.push_shard(shard.clone());
        }
        let quorum = quorum.validate().unwrap();

        // Recover the secret.
        let recovered_secret = quorum.recover_document().unwrap();

        TestResult::from_bool(recovered_secret == secret)
    }

    #[quickcheck]
    fn key_shard_encryption_roundtrip(shard: KeyShard) {
        let (enc_shard, codewords) = shard.clone().encrypt().unwrap();
        let shard2 = enc_shard.decrypt(&codewords).unwrap();
        assert_eq!(shard, shard2);
    }

    // TODO: Add many more tests...
}
