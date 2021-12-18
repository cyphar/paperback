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
    shamir::Dealer,
    v0::{
        ChaChaPolyKey, ChaChaPolyNonce, Error, KeyShard, KeyShardBuilder, MainDocument,
        MainDocumentBuilder, MainDocumentMeta, ShardSecret, ToWire, PAPERBACK_VERSION,
    },
};

use aead::{Aead, NewAead, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::{Keypair, SecretKey};
use rand::{rngs::OsRng, RngCore};

pub struct Backup {
    main_document: MainDocument,
    dealer: Dealer,
    id_keypair: Keypair,
}

impl Backup {
    // XXX: This internal API is a bit ugly...
    fn inner_new(quorum_size: u32, secret: &[u8], sealed: bool) -> Result<Self, Error> {
        // Generate identity keypair.
        let id_keypair = Keypair::generate(&mut OsRng);

        // Generate key and nonce.
        let mut doc_key = ChaChaPolyKey::default();
        OsRng.fill_bytes(&mut doc_key);
        let mut doc_nonce = ChaChaPolyNonce::default();
        OsRng.fill_bytes(&mut doc_nonce);

        // Construct shard secret and serialise it.
        let shard_secret = {
            let id_private_key = SecretKey::from_bytes(id_keypair.secret.as_bytes())
                .expect("round-trip of ed25519 key to get around non-Copy must never fail");
            ShardSecret {
                doc_key,
                id_private_key: match sealed {
                    false => Some(id_private_key),
                    true => None,
                },
            }
            .to_wire()
        };

        // Construct the MainDocument.
        let main_document_meta = MainDocumentMeta {
            version: PAPERBACK_VERSION,
            quorum_size,
        };

        // Encrypt the contents.
        let aead = ChaCha20Poly1305::new(&doc_key);
        let payload = Payload {
            msg: secret,
            aad: &main_document_meta.aad(&id_keypair.public),
        };
        let ciphertext = aead
            .encrypt(&doc_nonce, payload)
            .map_err(Error::AeadEncryption)?;

        // Continue MainDocument construction.
        let main_document = MainDocumentBuilder {
            meta: main_document_meta,
            nonce: doc_nonce,
            ciphertext,
        }
        .sign(&id_keypair);

        // Construct SSS dealer.
        let dealer = Dealer::new(quorum_size, shard_secret);

        Ok(Backup {
            main_document,
            dealer,
            id_keypair,
        })
    }

    // TODO: Implement this as a BackupBuilder rather than two builder init
    //       functions.

    pub fn new<B: AsRef<[u8]>>(quorum_size: u32, secret: B) -> Result<Self, Error> {
        Self::inner_new(quorum_size, secret.as_ref(), false)
    }

    pub fn new_sealed<B: AsRef<[u8]>>(quorum_size: u32, secret: B) -> Result<Self, Error> {
        Self::inner_new(quorum_size, secret.as_ref(), true)
    }

    pub fn main_document(&self) -> &MainDocument {
        &self.main_document
    }

    pub fn next_shard(&self) -> Result<KeyShard, Error> {
        // Extend new shard.
        Ok(KeyShardBuilder {
            version: self.main_document.inner.meta.version,
            doc_chksum: self.main_document.checksum(),
            shard: self.dealer.next_shard(),
        }
        .sign(&self.id_keypair))
    }
}
