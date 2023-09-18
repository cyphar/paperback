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
    shamir::{Error as ShamirError, Shard},
    v0::wire::prefixes::*,
};

use aead::{generic_array::GenericArray, Aead, AeadCore, NewAead};
use bip39::{Language, Mnemonic};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use multihash::{Multihash, MultihashDigest};
use rand::RngCore;
use unsigned_varint::encode as varuint_encode;

pub type ShardId = String;
pub type DocumentId = String;

const PAPERBACK_VERSION: u32 = 0;

type ChaChaPolyKey = GenericArray<u8, <ChaCha20Poly1305 as NewAead>::KeySize>;
const CHACHAPOLY_KEY_LENGTH: usize = 32;

type ChaChaPolyNonce = GenericArray<u8, <ChaCha20Poly1305 as AeadCore>::NonceSize>;
const CHACHAPOLY_NONCE_LENGTH: usize = 12;

#[cfg(test)]
#[test]
fn check_length_consts() {
    // GenericArray doesn't give us a way to get the size, so we need to do this
    // in a test...
    assert_eq!(CHACHAPOLY_KEY_LENGTH, ChaChaPolyKey::default().len());
    assert_eq!(CHACHAPOLY_NONCE_LENGTH, ChaChaPolyNonce::default().len());
}

const CHECKSUM_ALGORITHM: multihash::Code = multihash::Code::Blake2b256;
const CHECKSUM_MULTIBASE: multibase::Base = multibase::Base::Base32Z;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("security invariant violated: {0}")]
    InvariantViolation(&'static str),

    #[error("missing necessary cabibilities to complete request: {0}")]
    MissingCapability(&'static str),

    #[error("aead encryption cryptographic error: {0}")]
    AeadEncryption(aead::Error),

    #[error("aead decryption cryptographic error: {0}")]
    AeadDecryption(aead::Error),

    #[error("shamir algorithm operation: {0}")]
    Shamir(#[from] ShamirError),

    #[error("failed to decode shard secret: {0}")]
    ShardSecretDecode(String),

    #[error("failed to decode shard id: {0}")]
    ShardIdDecode(multibase::Error),

    #[error("failed to decode private key: {0}")]
    PrivateKeyDecode(ed25519_dalek::SignatureError),

    #[error("bip39 phrase failure: {0}")]
    Bip39(bip39::ErrorKind),

    #[error("other error: {0}")]
    Other(String),
}

impl From<anyhow::Error> for Error {
    fn from(inner: anyhow::Error) -> Self {
        match inner.downcast::<bip39::ErrorKind>() {
            Ok(err) => Self::Bip39(err),
            Err(err) => Self::Other(err.to_string()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Identity {
    id_public_key: VerifyingKey,
    id_signature: Signature,
}

#[cfg(test)]
impl quickcheck::Arbitrary for Identity {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let bytes = Vec::<u8>::arbitrary(g);

        let id_keypair = SigningKey::generate(&mut rand::thread_rng());
        let id_signature = id_keypair.sign(&bytes);

        Self {
            id_public_key: id_keypair.verifying_key(),
            id_signature,
        }
    }
}

// Copied from <https://github.com/BurntSushi/quickcheck/pull/292/files>.
#[cfg(test)]
pub fn arbitrary_fill_slice<S, T>(g: &mut quickcheck::Gen, mut slice: S)
where
    T: quickcheck::Arbitrary,
    S: AsMut<[T]>,
{
    slice.as_mut().fill_with(|| T::arbitrary(g))
}

#[derive(Debug)]
struct ShardSecret {
    doc_key: ChaChaPolyKey,
    id_keypair: Option<ed25519_dalek::SigningKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeyShardBuilder {
    version: u32, // must be 0 for this version
    doc_chksum: Multihash,
    shard: Shard,
}

impl KeyShardBuilder {
    fn signable_bytes(&self, id_public_key: &VerifyingKey) -> Vec<u8> {
        let mut bytes = self.to_wire();

        // Append the Ed25519 public key used for signing.
        varuint_encode::u32(PREFIX_ED25519_PUB, &mut varuint_encode::u32_buffer())
            .iter()
            .chain(id_public_key.as_bytes())
            .for_each(|b| bytes.push(*b));
        bytes
    }

    fn sign(self, id_keypair: &SigningKey) -> KeyShard {
        let bytes = self.signable_bytes(&id_keypair.verifying_key());
        KeyShard {
            inner: self,
            identity: Identity {
                id_public_key: id_keypair.verifying_key(),
                id_signature: id_keypair.sign(&bytes),
            },
        }
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for KeyShardBuilder {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let bytes = Vec::<u8>::arbitrary(g);
        Self {
            version: PAPERBACK_VERSION,
            doc_chksum: CHECKSUM_ALGORITHM.digest(&bytes[..]),
            shard: Shard::arbitrary(g),
        }
    }
}

const CODEWORD_LANGUAGE: Language = Language::English;
pub type KeyShardCodewords = Vec<String>;

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct KeyShard {
    inner: KeyShardBuilder,
    identity: Identity,
}

#[cfg(test)]
impl quickcheck::Arbitrary for KeyShard {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let id_keypair = SigningKey::generate(&mut rand::thread_rng());
        KeyShardBuilder::arbitrary(g).sign(&id_keypair)
    }
}

impl KeyShard {
    pub const ID_LENGTH: usize = Shard::ID_LENGTH;

    pub fn id(&self) -> ShardId {
        self.inner.shard.id()
    }

    fn document_checksum(&self) -> Multihash {
        self.inner.doc_chksum
    }

    pub fn document_id(&self) -> DocumentId {
        multihash_short_id(self.document_checksum(), MainDocument::ID_LENGTH)
    }

    pub fn quorum_size(&self) -> u32 {
        self.inner.shard.threshold()
    }

    pub fn encrypt(&self) -> Result<(EncryptedKeyShard, KeyShardCodewords), Error> {
        // Serialise.
        let wire_shard = self.to_wire();

        // Generate key and nonce.
        let mut shard_key = ChaChaPolyKey::default();
        rand::thread_rng().fill_bytes(&mut shard_key);
        let mut shard_nonce = ChaChaPolyNonce::default();
        rand::thread_rng().fill_bytes(&mut shard_nonce);

        // Encrypt the contents.
        let aead = ChaCha20Poly1305::new(&shard_key);
        let wire_shard = aead
            .encrypt(&shard_nonce, wire_shard.as_slice())
            .map_err(Error::AeadEncryption)?;

        // Convert key to a BIP-39 mnemonic.
        let phrase = Mnemonic::from_entropy(&shard_key, CODEWORD_LANGUAGE)
            .map_err(Error::from)? // XXX: Ugly, fix this.
            .into_phrase();
        let codewords = phrase
            .split_whitespace()
            .map(|s| s.to_owned())
            .collect::<Vec<_>>();

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
    pub fn checksum(&self) -> Multihash {
        CHECKSUM_ALGORITHM.digest(&self.to_wire())
    }

    pub fn checksum_string(&self) -> String {
        multibase::encode(CHECKSUM_MULTIBASE, self.checksum().to_bytes())
    }

    pub fn decrypt<A: AsRef<[String]>>(&self, codewords: A) -> Result<KeyShard, String> {
        // Convert BIP-39 mnemonic to a key.
        let phrase = codewords.as_ref().join(" ").to_lowercase();
        let mnemonic =
            Mnemonic::from_phrase(&phrase, CODEWORD_LANGUAGE).map_err(|e| format!("{:?}", e))?; // XXX: Ugly, fix this.

        let mut shard_key = ChaChaPolyKey::default();
        shard_key.copy_from_slice(mnemonic.entropy());

        // Decrypt the contents.
        let aead = ChaCha20Poly1305::new(&shard_key);
        let wire_shard = aead
            .decrypt(&self.nonce, self.ciphertext.as_slice())
            .map_err(|err| format!("{:?}", err))?; // XXX: Ugly, fix this.

        // Deserialise.
        KeyShard::from_wire(wire_shard)
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for EncryptedKeyShard {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let mut nonce = ChaChaPolyNonce::default();
        arbitrary_fill_slice(g, &mut nonce);
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
    fn aad(&self, id_public_key: &VerifyingKey) -> Vec<u8> {
        let mut bytes = self.to_wire();

        // Append the public key used for signing.
        // XXX: Make this much nicer...
        bytes.push(b'k');
        id_public_key.as_bytes().iter().for_each(|b| bytes.push(*b));

        bytes
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for MainDocumentMeta {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        Self {
            version: PAPERBACK_VERSION,
            quorum_size: u32::arbitrary(g),
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
    fn signable_bytes(&self, id_public_key: &VerifyingKey) -> Vec<u8> {
        let mut bytes = self.to_wire();

        // Append the Ed25519 public key used for signing.
        varuint_encode::u32(PREFIX_ED25519_PUB, &mut varuint_encode::u32_buffer())
            .iter()
            .chain(id_public_key.as_bytes())
            .for_each(|b| bytes.push(*b));
        bytes
    }

    fn sign(self, id_keypair: &SigningKey) -> MainDocument {
        let bytes = self.signable_bytes(&id_keypair.verifying_key());
        MainDocument {
            inner: self,
            identity: Identity {
                id_public_key: id_keypair.verifying_key(),
                id_signature: id_keypair.sign(&bytes),
            },
        }
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for MainDocumentBuilder {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let mut nonce = ChaChaPolyNonce::default();
        arbitrary_fill_slice(g, &mut nonce);
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

fn multihash_short_id(hash: Multihash, length: usize) -> String {
    let doc_chksum = hash.to_bytes();
    let encoded_chksum = multibase::encode(multibase::Base::Base32Z, &doc_chksum);
    // The *suffix* is the ID.
    let short_id = &encoded_chksum[encoded_chksum.len() - length..];

    short_id.to_string()
}

impl MainDocument {
    pub const ID_LENGTH: usize = 8;

    pub fn checksum(&self) -> Multihash {
        CHECKSUM_ALGORITHM.digest(&self.to_wire())
    }

    pub fn checksum_string(&self) -> String {
        multibase::encode(CHECKSUM_MULTIBASE, self.checksum().to_bytes())
    }

    pub fn id(&self) -> DocumentId {
        multihash_short_id(self.checksum(), Self::ID_LENGTH)
    }

    pub fn quorum_size(&self) -> u32 {
        self.inner.meta.quorum_size
    }

    pub fn version(&self) -> u32 {
        self.inner.meta.version
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for MainDocument {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let id_keypair = SigningKey::generate(&mut rand::thread_rng());
        MainDocumentBuilder::arbitrary(g).sign(&id_keypair)
    }
}

pub mod wire;
pub use wire::{FromWire, ToWire};

pub mod recover;
pub use recover::*;

pub mod backup;
pub use backup::*;

pub mod pdf;
pub use pdf::ToPdf;

#[cfg(test)]
mod test {
    use super::*;

    use multibase::Base;
    use quickcheck::TestResult;

    // NOTE: We use u16s and u8s here (and limit the range) because generating
    //       ridiculously large dealers takes too long because of the amount of
    //       CSPRNG churn it causes. In principle we could have a special
    //       Dealer::new_inner() that takes a CoreRng but that's probably not
    //       necessary.

    #[quickcheck]
    fn paperback_roundtrip_smoke(quorum_size: u8, secret: Vec<u8>) -> TestResult {
        if quorum_size < 2 || quorum_size > 64 {
            return TestResult::discard();
        }

        // Construct a backup.
        let backup = Backup::new(quorum_size.into(), &secret).unwrap();
        let main_document = backup.main_document().clone();
        let shards = (0..quorum_size)
            .map(|_| backup.next_shard().unwrap())
            .map(|s| s.encrypt().unwrap())
            .collect::<Vec<_>>();

        // Go through a round-trip through serialisation.
        let main_document = {
            let zbase32_bytes = main_document.to_wire_multibase(Base::Base32Z);
            MainDocument::from_wire_multibase(zbase32_bytes).unwrap()
        };
        let shards = shards
            .iter()
            .map(|(shard, codewords)| {
                let zbase32_bytes = shard.to_wire_multibase(Base::Base32Z);
                let shard = EncryptedKeyShard::from_wire_multibase(zbase32_bytes).unwrap();
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

    fn inner_paperback_expand_smoke<S: AsRef<[u8]>>(quorum_size: u32, secret: S) -> bool {
        // Construct a backup.
        let backup = Backup::new(quorum_size.into(), secret.as_ref()).unwrap();
        let main_document = backup.main_document().clone();
        let shards = (0..quorum_size)
            .map(|_| backup.next_shard().unwrap())
            .map(|s| s.encrypt().unwrap())
            .collect::<Vec<_>>();

        // Go through a round-trip through serialisation.
        let main_document = {
            let zbase32_bytes = main_document.to_wire_multibase(Base::Base32Z);
            MainDocument::from_wire_multibase(zbase32_bytes).unwrap()
        };
        let shards = shards
            .iter()
            .map(|(shard, codewords)| {
                let zbase32_bytes = shard.to_wire_multibase(Base::Base32Z);
                let shard = EncryptedKeyShard::from_wire_multibase(zbase32_bytes).unwrap();
                (shard, codewords.clone())
            })
            .collect::<Vec<_>>();

        // Construct a quorum *without the main_document*.
        let mut quorum = UntrustedQuorum::new();
        for (shard, codewords) in &shards {
            let shard = shard.decrypt(codewords).unwrap();
            quorum.push_shard(shard.clone());
        }
        let quorum = quorum.validate().unwrap();

        // Secret recovery should fail.
        let _ = quorum.recover_document().unwrap_err();

        // But we can expand it -- take the shards through a round-trip.
        let new_shards = (0..quorum_size)
            .map(|_| quorum.new_shard(NewShardKind::NewShard).unwrap())
            .map(|s| s.encrypt().unwrap())
            .map(|(shard, codewords)| {
                let zbase32_bytes = shard.to_wire_multibase(Base::Base32Z);
                let shard = EncryptedKeyShard::from_wire_multibase(zbase32_bytes).unwrap();
                (shard, codewords.clone())
            })
            .collect::<Vec<_>>();
        // TODO: Consider re-building the original shards, but this increases
        //       the cost of this test to the point where
        //       paperback_expand_smoke_201 takes >2 minutes.
        std::mem::drop(quorum); // make sure it's gone

        // Construct a new quorum with the expanded keys!
        let mut quorum = UntrustedQuorum::new();
        let take_old: usize = (quorum_size as usize) / 2;
        let take_new: usize = (quorum_size as usize) - take_old;
        quorum.main_document(main_document);
        for (shard, codewords) in shards
            .iter()
            .take(take_old)
            .chain(new_shards.iter().take(take_new))
        {
            let shard = shard.decrypt(codewords).unwrap();
            quorum.push_shard(shard.clone());
        }
        let quorum = quorum.validate().unwrap();

        // Recover the secret.
        let recovered_secret = quorum.recover_document().unwrap();

        recovered_secret == secret.as_ref()
    }

    #[cfg(not(debug_assertions))] // is --release?
    #[quickcheck]
    fn paperback_expand_smoke(quorum_size: u8, secret: Vec<u8>) -> TestResult {
        if quorum_size < 1 || quorum_size > 150 {
            return TestResult::discard();
        }
        TestResult::from_bool(inner_paperback_expand_smoke(quorum_size.into(), secret))
    }

    // For non-release test runs, we have to manally test the sizes we want
    // because expansion of a (for instance) 256-threshold scheme can take up to
    // 80s which quickcheck may attempt hundreds of times. However we can use
    // quickcheck for release test runs.
    macro_rules! paperback_expand_test {
        ($func:ident, $quorum_size:expr) => {
            #[cfg(debug_assertions)] // is not --release?
            #[test]
            fn $func() {
                let mut secret = [0; 1024];
                rand::thread_rng().fill_bytes(&mut secret[..]);
                assert!(inner_paperback_expand_smoke($quorum_size, secret))
            }
        };
    }

    paperback_expand_test!(paperback_expand_smoke_002, 2);
    paperback_expand_test!(paperback_expand_smoke_003, 3);
    paperback_expand_test!(paperback_expand_smoke_004, 4);
    paperback_expand_test!(paperback_expand_smoke_005, 5);
    paperback_expand_test!(paperback_expand_smoke_006, 6);
    paperback_expand_test!(paperback_expand_smoke_007, 7);
    paperback_expand_test!(paperback_expand_smoke_008, 8);
    paperback_expand_test!(paperback_expand_smoke_009, 9);
    paperback_expand_test!(paperback_expand_smoke_010, 10);
    paperback_expand_test!(paperback_expand_smoke_011, 11);
    paperback_expand_test!(paperback_expand_smoke_012, 12);
    paperback_expand_test!(paperback_expand_smoke_013, 13);
    paperback_expand_test!(paperback_expand_smoke_014, 14);
    paperback_expand_test!(paperback_expand_smoke_015, 15);
    paperback_expand_test!(paperback_expand_smoke_016, 16);
    paperback_expand_test!(paperback_expand_smoke_017, 17);
    paperback_expand_test!(paperback_expand_smoke_018, 18);
    paperback_expand_test!(paperback_expand_smoke_019, 19);
    paperback_expand_test!(paperback_expand_smoke_020, 20);
    paperback_expand_test!(paperback_expand_smoke_021, 21);
    paperback_expand_test!(paperback_expand_smoke_022, 22);
    paperback_expand_test!(paperback_expand_smoke_023, 23);
    paperback_expand_test!(paperback_expand_smoke_024, 24);
    paperback_expand_test!(paperback_expand_smoke_025, 25);
    paperback_expand_test!(paperback_expand_smoke_026, 26);
    paperback_expand_test!(paperback_expand_smoke_027, 27);
    paperback_expand_test!(paperback_expand_smoke_028, 28);
    paperback_expand_test!(paperback_expand_smoke_029, 29);
    paperback_expand_test!(paperback_expand_smoke_030, 30);
    paperback_expand_test!(paperback_expand_smoke_031, 31);
    paperback_expand_test!(paperback_expand_smoke_032, 32);
    paperback_expand_test!(paperback_expand_smoke_033, 33);
    paperback_expand_test!(paperback_expand_smoke_034, 34);
    paperback_expand_test!(paperback_expand_smoke_035, 35);
    paperback_expand_test!(paperback_expand_smoke_036, 36);
    paperback_expand_test!(paperback_expand_smoke_037, 37);
    paperback_expand_test!(paperback_expand_smoke_038, 38);
    paperback_expand_test!(paperback_expand_smoke_039, 39);
    paperback_expand_test!(paperback_expand_smoke_040, 40);
    paperback_expand_test!(paperback_expand_smoke_041, 41);
    paperback_expand_test!(paperback_expand_smoke_042, 42);
    paperback_expand_test!(paperback_expand_smoke_043, 43);
    paperback_expand_test!(paperback_expand_smoke_044, 44);
    paperback_expand_test!(paperback_expand_smoke_045, 45);
    paperback_expand_test!(paperback_expand_smoke_046, 46);
    paperback_expand_test!(paperback_expand_smoke_047, 47);
    paperback_expand_test!(paperback_expand_smoke_048, 48);
    paperback_expand_test!(paperback_expand_smoke_049, 49);
    paperback_expand_test!(paperback_expand_smoke_050, 50);
    paperback_expand_test!(paperback_expand_smoke_051, 51);
    paperback_expand_test!(paperback_expand_smoke_052, 52);
    paperback_expand_test!(paperback_expand_smoke_053, 53);
    paperback_expand_test!(paperback_expand_smoke_054, 54);
    paperback_expand_test!(paperback_expand_smoke_055, 55);
    paperback_expand_test!(paperback_expand_smoke_056, 56);
    paperback_expand_test!(paperback_expand_smoke_057, 57);
    paperback_expand_test!(paperback_expand_smoke_058, 58);
    paperback_expand_test!(paperback_expand_smoke_059, 59);
    paperback_expand_test!(paperback_expand_smoke_060, 60);
    paperback_expand_test!(paperback_expand_smoke_061, 61);
    paperback_expand_test!(paperback_expand_smoke_062, 62);
    paperback_expand_test!(paperback_expand_smoke_063, 63);
    paperback_expand_test!(paperback_expand_smoke_064, 64);
    paperback_expand_test!(paperback_expand_smoke_128, 128);
    paperback_expand_test!(paperback_expand_smoke_201, 201);

    #[quickcheck]
    fn key_shard_encryption_roundtrip(shard: KeyShard) -> bool {
        let (enc_shard, codewords) = shard.clone().encrypt().unwrap();
        let shard2 = enc_shard.decrypt(&codewords).unwrap();
        shard == shard2
    }

    #[quickcheck]
    fn paperback_recreate_shards(quorum_size: u8) -> TestResult {
        #[cfg(debug_assertions)] // not --release
        const RECREATE_UPPER: u8 = 32;
        #[cfg(not(debug_assertions))] // --release
        const RECREATE_UPPER: u8 = 180;

        if quorum_size < 1 || quorum_size > RECREATE_UPPER {
            return TestResult::discard();
        }

        let mut secret = [0; 16];
        rand::thread_rng().fill_bytes(&mut secret[..]);

        // Construct a backup.
        let backup = Backup::new(quorum_size.into(), secret.as_ref()).unwrap();
        let shards = (0..quorum_size as usize + 8)
            .map(|_| backup.next_shard().unwrap())
            .map(|s| s.encrypt().unwrap())
            .collect::<Vec<_>>();

        // Go through a round-trip through serialisation then decrypt the shards.
        let shards = shards
            .iter()
            .map(|(shard, codewords)| {
                let zbase32_bytes = shard.to_wire_multibase(Base::Base32Z);
                let shard = EncryptedKeyShard::from_wire_multibase(zbase32_bytes).unwrap();
                shard.decrypt(codewords).unwrap()
            })
            .collect::<Vec<_>>();

        // Construct a quorum *without the main_document*.
        let mut quorum = UntrustedQuorum::new();
        for shard in &shards[..quorum_size as usize] {
            quorum.push_shard(shard.clone());
        }
        let quorum = quorum.validate().unwrap();

        // Secret recovery should fail.
        let _ = quorum.recover_document().unwrap_err();

        // However we should be able to recover all of the shards correctly.
        if !shards.iter().all(|s| {
            s.clone()
                == quorum
                    .new_shard(NewShardKind::ExistingShard(s.id()))
                    .unwrap()
        }) {
            return TestResult::failed();
        }

        // Make a second quorum and make sure we can consistently recover a
        // never-before-seen shard with an arbitrary id.
        let mut quorum2 = UntrustedQuorum::new();
        for shard in &shards[..quorum_size as usize] {
            quorum2.push_shard(shard.clone());
        }
        let quorum2 = quorum2.validate().unwrap();

        let new_shard_id = "hayyayyy";
        let new_shard = quorum
            .new_shard(NewShardKind::ExistingShard(new_shard_id.to_string()))
            .unwrap();
        let new_shard2 = quorum2
            .new_shard(NewShardKind::ExistingShard(new_shard_id.to_string()))
            .unwrap();

        TestResult::from_bool(
            new_shard == new_shard2
                && new_shard.id() == new_shard_id
                && new_shard2.id() == new_shard_id,
        )
    }

    // TODO: Add many more tests...
}
