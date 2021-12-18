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

// TODO: Implement FromWire for all the bits and write code to make use of
// Joiner and the other functions.
#![allow(unused)]

use crate::v0::{
    pdf::{Error, QRCODE_MULTIBASE},
    FromWire, ToWire, PAPERBACK_VERSION,
};

use qrcode::QrCode;
use unsigned_varint::{encode as varuint_encode, nom as varuint_nom};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum PartType {
    MainDocumentData,     // 'D'
    MainDocumentChecksum, // 'C'
    KeyShardData,         // 'd'
    KeyShardChecksum,     // 'c'
}

impl ToWire for PartType {
    fn to_wire(&self) -> Vec<u8> {
        match self {
            Self::MainDocumentData => "D",
            Self::MainDocumentChecksum => "C",
            Self::KeyShardData => "d",
            Self::KeyShardChecksum => "c",
        }
        .into()
    }
}

impl FromWire for PartType {
    fn from_wire_partial(input: &[u8]) -> Result<(Self, &[u8]), String> {
        match input.split_first() {
            Some((b'D', rest)) => Ok((Self::MainDocumentData, rest)),
            Some((b'C', rest)) => Ok((Self::MainDocumentChecksum, rest)),
            Some((b'd', rest)) => Ok((Self::KeyShardData, rest)),
            Some((b'c', rest)) => Ok((Self::KeyShardChecksum, rest)),
            None => Err("".into()), // TODO: Insufficient
            Some(_) => Err("".into()),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct PartMeta {
    version: u32,
    data_type: PartType,
    num_parts: usize,
}

impl ToWire for PartMeta {
    fn to_wire(&self) -> Vec<u8> {
        let mut bytes = vec![];

        // Encode version.
        bytes.extend_from_slice(varuint_encode::u32(
            self.version,
            &mut varuint_encode::u32_buffer(),
        ));

        // Encode data type.
        bytes.append(&mut self.data_type.to_wire());

        // Encode number of parts.
        bytes.extend_from_slice(varuint_encode::usize(
            self.num_parts,
            &mut varuint_encode::usize_buffer(),
        ));

        bytes
    }
}

impl FromWire for PartMeta {
    fn from_wire_partial(input: &[u8]) -> Result<(Self, &[u8]), String> {
        todo!();
    }
}

#[derive(Clone, Debug)]
struct Part {
    meta: PartMeta,
    part_idx: usize,
    data: Vec<u8>,
}

impl ToWire for Part {
    fn to_wire(&self) -> Vec<u8> {
        // Start with Pb prefix.
        let mut bytes = Vec::from(&b"Pb"[..]);

        // Encode metadata.
        bytes.append(&mut self.meta.to_wire());

        // Encode part index.
        bytes.extend_from_slice(varuint_encode::usize(
            self.part_idx,
            &mut varuint_encode::usize_buffer(),
        ));

        // Encode data.
        bytes.extend_from_slice(&self.data);

        bytes
    }
}

impl FromWire for Part {
    fn from_wire_partial(input: &[u8]) -> Result<(Self, &[u8]), String> {
        todo!();
    }
}

#[derive(Default, Debug)]
pub(super) struct Joiner {
    meta: Option<PartMeta>,
    parts: Vec<Option<Part>>,
}

impl Joiner {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn remaining(&self) -> usize {
        self.parts.iter().filter(|v| v.is_none()).count()
    }

    fn add_parsed_part(&mut self, part: Part) -> Result<&mut Self, Error> {
        if let Some(meta) = self.meta {
            if meta != part.meta || part.part_idx >= meta.num_parts {
                return Err(Error::MismatchedQrCode);
            }
            if part.meta.version != PAPERBACK_VERSION {
                return Err(Error::WrongPaperbackVersion {
                    version: part.meta.version,
                });
            }
        } else {
            self.meta = Some(part.meta);
            self.parts = vec![None; part.meta.num_parts];
        }
        if part.part_idx >= self.parts.len() {
            return Err(Error::MismatchedQrCode);
        }
        let idx = part.part_idx;
        self.parts[idx] = Some(part);
        Ok(self)
    }

    pub(super) fn add_qr_part<B: AsRef<str>>(&mut self, qr_data: B) -> Result<&mut Self, Error> {
        let part = Part::from_wire_multibase(qr_data.as_ref()).map_err(Error::ParseQrData)?;
        self.add_parsed_part(part)
    }

    pub(super) fn combine_parts(&self) -> Result<Vec<u8>, Error> {
        let mut data_len = 0usize;
        for (idx, part) in self.parts.iter().enumerate() {
            if let Some(part) = part {
                data_len += part.data.len();
            } else {
                return Err(Error::MissingQrSegment { idx });
            }
        }
        let mut bytes = Vec::with_capacity(data_len);
        for part in &self.parts {
            if let Some(part) = part {
                bytes.extend_from_slice(&part.data)
            }
        }
        Ok(bytes)
    }
}

const DATA_OVERHEAD: usize = 1 /* multibase header */ +
                             1 /* (varuint) version = 0 */ +
                             1 /* data type */ +
                             2 * 9 /* 2*varuint length and index */;

// TODO: Make this dynamic based on the error correction mode.
const MAX_DATA_LENGTH: usize = 926 - DATA_OVERHEAD;

fn split_data<B: AsRef<[u8]>>(data_type: PartType, data: B) -> Vec<Part> {
    let data = data.as_ref();
    let chunks = data.chunks(MAX_DATA_LENGTH).collect::<Vec<_>>();
    chunks
        .iter()
        .enumerate()
        .map(|(idx, &chunk)| Part {
            meta: PartMeta {
                version: PAPERBACK_VERSION,
                data_type: data_type,
                num_parts: chunks.len(),
            },
            part_idx: idx,
            data: chunk.into(),
        })
        .collect()
}

pub(super) fn generate_codes<B: AsRef<[u8]>>(
    data_type: PartType,
    data: B,
) -> Result<Vec<QrCode>, Error> {
    Ok(split_data(data_type, data)
        .iter()
        .map(|part| QrCode::new(part.to_wire_multibase(QRCODE_MULTIBASE)))
        .collect::<Result<Vec<_>, _>>()?)
}

pub(super) fn generate_one_code<B: AsRef<[u8]>>(
    data_type: PartType,
    data: B,
) -> Result<QrCode, Error> {
    Ok(QrCode::new(
        Part {
            meta: PartMeta {
                version: PAPERBACK_VERSION,
                data_type: data_type,
                num_parts: 1,
            },
            part_idx: 0,
            data: data.as_ref().into(),
        }
        .to_wire_multibase(QRCODE_MULTIBASE),
    )?)
}
