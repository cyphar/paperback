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
    shamir::{self, Dealer},
    v0::{FromWire, KeyShard, KeyShardBuilder, MainDocument, ShardSecret},
};

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
};

use aead::{Aead, NewAead, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::{Keypair, PublicKey};
use multihash::Multihash;

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

#[derive(Debug, Clone)]
pub struct Grouping(pub Vec<Vec<Type>>);

#[derive(Debug, Clone, Default)]
pub struct UntrustedQuorum {
    untrusted_main_document: Option<MainDocument>,
    untrusted_shards: Vec<KeyShard>,
}

#[derive(Debug, Clone, Eq)]
struct HashablePublicKey(PublicKey);

impl<P> From<P> for HashablePublicKey
where
    P: AsRef<PublicKey>,
{
    fn from(from: P) -> Self {
        Self(from.as_ref().clone())
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

#[derive(Debug)]
pub struct InconsistentQuorumError {
    message: String, // TODO: Switch to an Error...
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

    pub fn push_shard(&mut self, shard: KeyShard) -> &mut Self {
        self.untrusted_shards.push(shard);
        self
    }

    pub fn main_document(&mut self, main: MainDocument) -> &mut Self {
        self.untrusted_main_document = Some(main);
        self
    }

    fn group(&self) -> Vec<Vec<Type>> {
        let documents = self
            .untrusted_main_document
            .iter()
            .cloned()
            .map(Type::from)
            .chain(self.untrusted_shards.iter().cloned().map(Type::from))
            .collect::<Vec<_>>();

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

        let mut groups: HashMap<GroupId, Vec<Type>> = HashMap::new();
        for document in documents {
            let group_id = match &document {
                Type::MainDocument(main) | Type::ForgedMainDocument(main) => GroupId {
                    version: main.inner.meta.version,
                    doc_chksum: main.checksum(),
                    quorum_size: main.quorum_size(),
                    id_public_key: HashablePublicKey(main.identity.id_public_key.clone()),
                },
                Type::KeyShard(shard) | Type::ForgedKeyShard(shard) => GroupId {
                    version: shard.inner.version,
                    doc_chksum: shard.inner.doc_chksum.clone(),
                    quorum_size: shard.inner.shard.threshold(),
                    id_public_key: HashablePublicKey(shard.identity.id_public_key.clone()),
                },
            };
            groups.entry(group_id).or_insert(vec![]).push(document);
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
                    groups: Grouping(groups.clone()),
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
            groups: Grouping(groups.clone()),
        })?;

        // Extract the main document from the grouping.
        let main_document = match documents
            .iter()
            .filter_map(Type::main_document)
            .collect::<Vec<_>>()[..]
        {
            [main_document] => main_document.clone(),
            // No main documents.
            [] => {
                return Err(InconsistentQuorumError {
                    message: "no main document specified".into(),
                    groups: Grouping(groups.clone()),
                });
            }
            // Nore than one main document.
            _ => {
                return Err(InconsistentQuorumError {
                    message: "more than one main document in grouping".into(),
                    groups: Grouping(groups.clone()),
                });
            }
        };

        // Extract the key shards from the grouping.
        let shards = documents
            .iter()
            .filter_map(Type::key_shard)
            .cloned()
            .collect::<Vec<_>>();

        // TODO: Sanity-check the shards completely.
        assert_eq!(shards.len(), self.untrusted_shards.len());

        // XXX: Should probably support having more shards than needed, and have
        //      them act as a double-check operation.
        if main_document.quorum_size() as usize != shards.len() {
            return Err(InconsistentQuorumError {
                message: format!(
                    "quorum size required is {} but had {} shards",
                    main_document.quorum_size(),
                    shards.len()
                ),
                groups: Grouping(groups.clone()),
            });
        }

        // TODO: Add a sanity-check for these values.
        let id_public_key = main_document.identity.id_public_key;
        let doc_chksum = main_document.checksum();

        Ok(Quorum {
            main_document,
            shards,
            // All shards must have agreed on these properties -- otherwise the
            // grouping checks above would've caused an error.
            id_public_key,
            doc_chksum,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Quorum {
    main_document: MainDocument,
    shards: Vec<KeyShard>,
    // Cached consensus information.
    id_public_key: PublicKey,
    doc_chksum: Multihash,
}

impl Quorum {
    pub fn recover_document(&self) -> Result<Vec<u8>, String> {
        let shards = self
            .shards
            .iter()
            .map(|s| s.inner.shard.clone())
            .collect::<Vec<_>>();
        let secret = ShardSecret::from_wire(shamir::recover_secret(shards))?;

        // Double-check that the private key agrees with the quorum's public key
        // choice.
        if let Some(id_private_key) = secret.id_private_key {
            if PublicKey::from(&id_private_key) != self.id_public_key {
                return Err("private key doesn't match quorum public key")?;
            }
        }

        // Decrypt the contents.
        let aead = ChaCha20Poly1305::new(secret.doc_key);
        let payload = Payload {
            msg: &self.main_document.inner.ciphertext,
            aad: &self.main_document.inner.meta.aad(&self.id_public_key),
        };
        aead.decrypt(&self.main_document.inner.nonce, payload)
            .map_err(|err| format!("{:?}", err)) // XXX: Ugly, fix this.
    }

    pub fn extend_shards(&self, n: u32) -> Result<Vec<KeyShard>, String> {
        let shards = self
            .shards
            .iter()
            .map(|s| s.inner.shard.clone())
            .collect::<Vec<_>>();

        // Conduct a complete recovery.
        let dealer = Dealer::recover(shards);
        let secret = ShardSecret::from_wire(dealer.secret())?;

        // Get the private key so we can sign the new shards.
        let id_private_key = secret
            .id_private_key
            .ok_or("document is sealed -- no new key shards allowed")?;

        // Make sure the private key matches the expected public key.
        let id_public_key = PublicKey::from(&id_private_key);
        if id_public_key != self.id_public_key {
            return Err("id_secret_key doesn't match expected id_public_key")?;
        }

        // Create the signing keypair.
        let id_keypair = Keypair {
            secret: id_private_key,
            public: id_public_key,
        };

        // Extend new shards.
        Ok((0..n)
            .map(|_| {
                KeyShardBuilder {
                    version: self.main_document.inner.meta.version,
                    doc_chksum: self.doc_chksum.clone(),
                    shard: dealer.next_shard(),
                }
                .sign(&id_keypair)
            })
            .collect::<Vec<_>>())
    }
}
