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
    shamir::{shard, Dealer},
    v0::{Error, FromWire, KeyShard, KeyShardBuilder, MainDocument, ShardId, ShardSecret},
};

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
};

use aead::{Aead, NewAead, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::VerifyingKey;
use multihash::Multihash;
use once_cell::unsync::OnceCell;

#[derive(Debug, Clone)]
pub enum Type {
    MainDocument(MainDocument),
    ForgedMainDocument(MainDocument),
    KeyShard(KeyShard),
    ForgedKeyShard(KeyShard),
}

impl Type {
    fn main_document(&self) -> Option<&MainDocument> {
        match self {
            Type::MainDocument(m) => Some(m),
            _ => None,
        }
    }

    fn key_shard(&self) -> Option<&KeyShard> {
        match self {
            Type::KeyShard(k) => Some(k),
            _ => None,
        }
    }
}

impl From<MainDocument> for Type {
    fn from(main: MainDocument) -> Self {
        let id_public_key = main.identity.id_public_key;
        match id_public_key.verify_strict(
            &main.inner.signable_bytes(&id_public_key),
            &main.identity.id_signature,
        ) {
            Ok(_) => Type::MainDocument(main),
            Err(_) => Type::ForgedMainDocument(main),
        }
    }
}

impl From<KeyShard> for Type {
    fn from(shard: KeyShard) -> Self {
        let id_public_key = shard.identity.id_public_key;
        match id_public_key.verify_strict(
            &shard.inner.signable_bytes(&id_public_key),
            &shard.identity.id_signature,
        ) {
            Ok(_) => Type::KeyShard(shard),
            Err(_) => Type::ForgedKeyShard(shard),
        }
    }
}

#[derive(Debug, Clone, Eq)]
struct HashablePublicKey(VerifyingKey);

impl<P> From<P> for HashablePublicKey
where
    P: AsRef<VerifyingKey>,
{
    fn from(from: P) -> Self {
        Self(*from.as_ref())
    }
}

impl PartialEq for HashablePublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl Hash for HashablePublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct GroupId {
    // All documents must agree on the paperback version. This could be
    // faked by an attacker but this is just a sanity-check.
    version: u32,
    // All documents must agree on the document checksum.
    doc_chksum: Multihash,
    // All documents must agree on quorum size.
    quorum_size: u32,
    // All documents must use the same public key for their identity.
    id_public_key: HashablePublicKey,
}

impl From<&MainDocument> for GroupId {
    fn from(main: &MainDocument) -> Self {
        Self {
            version: main.inner.meta.version,
            doc_chksum: main.checksum(),
            quorum_size: main.quorum_size(),
            id_public_key: HashablePublicKey(main.identity.id_public_key),
        }
    }
}

impl From<&KeyShard> for GroupId {
    fn from(shard: &KeyShard) -> Self {
        Self {
            version: shard.inner.version,
            doc_chksum: shard.document_checksum(),
            quorum_size: shard.quorum_size(),
            id_public_key: HashablePublicKey(shard.identity.id_public_key),
        }
    }
}

impl From<&Type> for GroupId {
    fn from(document: &Type) -> Self {
        match document {
            Type::MainDocument(main) | Type::ForgedMainDocument(main) => Self::from(main),
            Type::KeyShard(shard) | Type::ForgedKeyShard(shard) => Self::from(shard),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Grouping(pub Vec<Vec<Type>>);

#[derive(Debug, Clone, Default)]
pub struct UntrustedQuorum {
    untrusted_quorum_size: Option<u32>,
    untrusted_main_document: Option<MainDocument>,
    untrusted_shards: HashMap<(GroupId, String), KeyShard>,
}

#[derive(Debug)]
pub struct InconsistentQuorumError {
    pub message: String, // TODO: Switch to an Error...
    groups: Grouping,
}

impl InconsistentQuorumError {
    pub fn as_groups(&self) -> &Grouping {
        &self.groups
    }
}

impl UntrustedQuorum {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn quorum_size(&self) -> Option<u32> {
        self.untrusted_quorum_size
    }

    pub fn push_shard(&mut self, shard: KeyShard) -> &mut Self {
        self.untrusted_quorum_size
            .get_or_insert(shard.quorum_size());
        self.untrusted_shards
            .insert((GroupId::from(&shard), shard.id()), shard);
        self
    }

    pub fn main_document(&mut self, main: MainDocument) -> &mut Self {
        self.untrusted_quorum_size.get_or_insert(main.quorum_size());
        self.untrusted_main_document = Some(main);
        self
    }

    pub fn untrusted_shards(&self) -> impl Iterator<Item = &KeyShard> {
        self.untrusted_shards.values()
    }

    pub fn num_untrusted_shards(&self) -> usize {
        self.untrusted_shards.len()
    }

    fn group(&self) -> Vec<Vec<Type>> {
        let documents = self
            .untrusted_main_document
            .iter()
            .cloned()
            .map(Type::from)
            .chain(self.untrusted_shards.values().cloned().map(Type::from))
            .collect::<Vec<_>>();

        let mut groups: HashMap<GroupId, Vec<Type>> = HashMap::new();
        for document in documents {
            groups
                .entry(GroupId::from(&document))
                .or_insert_with(Vec::new)
                .push(document);
        }
        groups.values().cloned().collect::<Vec<_>>()
    }

    pub fn validate(self) -> Result<Quorum, InconsistentQuorumError> {
        let groups = self.group();

        // Must only have one grouping of documents.
        let documents = match &groups[..] {
            [documents] => documents,
            _ => {
                return Err(InconsistentQuorumError {
                    message: "key shards and documents are inconsistent".into(),
                    groups: Grouping(groups),
                })
            }
        }
        .iter()
        // Must not contain any forged documents.
        .cloned()
        .map(|t| match t {
            Type::ForgedMainDocument(_) | Type::ForgedKeyShard(_) => {
                Err("quorum contains forged document")
            }
            Type::MainDocument(_) | Type::KeyShard(_) => Ok(t),
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| InconsistentQuorumError {
            message: err.into(),
            // NOTE: We have to clone because the compiler doesn't know that if
            //       we hit this line we are guaranteed to return immediately.
            groups: Grouping(groups.clone()),
        })?;

        // Extract the main document from the grouping.
        let main_document = match documents
            .iter()
            .filter_map(Type::main_document)
            .collect::<Vec<_>>()[..]
        {
            // Main document present.
            [main_document] => Some(main_document.clone()),
            // No main document.
            [] => None,
            // Nore than one main document.
            _ => {
                return Err(InconsistentQuorumError {
                    message: "more than one main document in grouping".into(),
                    groups: Grouping(groups),
                });
            }
        };

        // Extract the key shards from the grouping.
        let shards = documents
            .iter()
            .filter_map(Type::key_shard)
            .cloned()
            .collect::<Vec<_>>();

        // Collect the Quorum's id_public_key and doc_chksum, then double-check
        // the values match everything else. If we have no main document, just
        // use the first shard's values.
        let (version, id_public_key, doc_chksum) = if let Some(ref main_document) = main_document {
            (
                main_document.inner.meta.version,
                main_document.identity.id_public_key,
                main_document.checksum(),
            )
        } else if let Some(shard) = shards.get(0) {
            (
                shard.inner.version,
                shard.identity.id_public_key,
                shard.document_checksum(),
            )
        } else {
            return Err(InconsistentQuorumError {
                message: "[internal error] no main documents or shards present in quorum"
                    .to_string(),
                groups: Grouping(groups),
            });
        };

        assert_eq!(shards.len(), self.untrusted_shards.len());
        // TODO: Maybe make a trait for this -- QuorumVerifiable?
        if let Some(ref main_document) = main_document {
            // XXX: Should probably support having more shards than needed, and have
            //      them act as a double-check operation.
            if main_document.quorum_size() as usize != shards.len() {
                return Err(InconsistentQuorumError {
                    message: format!(
                        "quorum size required is {} but had {} shards",
                        main_document.quorum_size(),
                        shards.len()
                    ),
                    groups: Grouping(groups),
                });
            }

            if main_document.checksum() != doc_chksum
                || main_document.identity.id_public_key != id_public_key
                || main_document.inner.meta.version != version
                || self
                    .quorum_size()
                    .map_or(false, |s| s != main_document.quorum_size())
            {
                return Err(InconsistentQuorumError {
                    message: "main document has inconsistent identity".to_string(),
                    groups: Grouping(groups),
                });
            }
        }
        for shard in shards.iter() {
            if shard.document_checksum() != doc_chksum
                || shard.identity.id_public_key != id_public_key
                || shard.inner.version != version
                || self
                    .quorum_size()
                    .map_or(false, |s| s != shard.quorum_size())
            {
                return Err(InconsistentQuorumError {
                    message: "shard has inconsistent identity".to_string(),
                    groups: Grouping(groups),
                });
            }
        }

        Ok(Quorum {
            main_document,
            shards,
            // All shards must have agreed on these properties -- otherwise the
            // grouping checks above would've caused an error.
            version,
            id_public_key,
            doc_chksum,
            dealer: OnceCell::new(),
        })
    }
}

/// The kind of shard expansion being requested in `Quorum::new_shard`.
pub enum NewShardKind {
    /// Create a new shard with a random `ShardId` (x-value).
    NewShard,
    /// Re-create the shard with the provided `ShardId`.
    ExistingShard(ShardId),
}

#[derive(Debug, Clone)]
pub struct Quorum {
    main_document: Option<MainDocument>,
    shards: Vec<KeyShard>,
    // Cached consensus information.
    version: u32,
    id_public_key: VerifyingKey,
    doc_chksum: Multihash,
    // Lazy-initialised dealer, reconstructed from key shards.
    dealer: OnceCell<Dealer>,
}

impl Quorum {
    pub fn has_main_document(&self) -> bool {
        self.main_document.is_some()
    }

    fn get_dealer(&self) -> Result<&Dealer, Error> {
        Ok(self.dealer.get_or_try_init(|| {
            Dealer::recover(
                self.shards
                    .iter()
                    .map(|s| s.inner.shard.clone())
                    .collect::<Vec<_>>(),
            )
        })?)
    }

    pub fn recover_document(&self) -> Result<Vec<u8>, Error> {
        let main_document = self.main_document.clone().ok_or(Error::MissingCapability(
            "no main document in quorum -- cannot recover",
        ))?;
        let shards = self
            .shards
            .iter()
            .map(|s| s.inner.shard.clone())
            .collect::<Vec<_>>();
        let secret = ShardSecret::from_wire(Dealer::recover(shards)?.secret())
            .map_err(Error::ShardSecretDecode)?;

        // Double-check that the private key agrees with the quorum's public key
        // choice.
        if let Some(id_keypair) = secret.id_keypair {
            if id_keypair.verifying_key() != self.id_public_key {
                return Err(Error::InvariantViolation(
                    "private key doesn't match quorum public key",
                ));
            }
        }

        // Decrypt the contents.
        let aead = ChaCha20Poly1305::new(&secret.doc_key);
        let payload = Payload {
            msg: &main_document.inner.ciphertext,
            aad: &main_document.inner.meta.aad(&self.id_public_key),
        };
        aead.decrypt(&main_document.inner.nonce, payload)
            .map_err(Error::AeadDecryption)
    }

    pub fn new_shard(&self, shard_type: NewShardKind) -> Result<KeyShard, Error> {
        // Conduct a complete recovery.
        let dealer = self.get_dealer()?;
        let secret = ShardSecret::from_wire(dealer.secret()).map_err(Error::ShardSecretDecode)?;

        // Get the private key so we can sign the new shards.
        let id_keypair = secret.id_keypair.ok_or(Error::MissingCapability(
            "document is sealed -- no new key shards allowed",
        ))?;

        // Make sure the private key matches the expected public key.
        let id_public_key = id_keypair.verifying_key();
        if id_public_key != self.id_public_key {
            return Err(Error::InvariantViolation(
                "id_secret_key doesn't match expected id_public_key",
            ));
        }

        // Extend new shards.
        Ok(KeyShardBuilder {
            version: self.version,
            doc_chksum: self.doc_chksum,
            shard: match shard_type {
                NewShardKind::NewShard => dealer.next_shard(),
                NewShardKind::ExistingShard(id) => dealer
                    .shard(shard::parse_id(id).map_err(Error::ShardIdDecode)?)
                    .ok_or_else(|| {
                        Error::Other(
                            "requested shard id has x value of 0 -- refusing to create".to_string(),
                        )
                    })?,
            },
        }
        .sign(&id_keypair))
    }
}
