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
    pdf::{Error, QRCODE_MULTIBASE},
    FromWire, ToWire, PAPERBACK_VERSION,
};

use qrcode::QrCode;
use unsigned_varint::encode as varuint_encode;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum PartType {
    MainDocumentData, // 'D'
}

impl ToWire for PartType {
    fn to_wire(&self) -> Vec<u8> {
        match self {
            Self::MainDocumentData => "D",
        }
        .into()
    }
}

impl FromWire for PartType {
    fn from_wire_partial(input: &[u8]) -> Result<(&[u8], Self), String> {
        match input.split_first() {
            Some((b'D', input)) => Ok((input, Self::MainDocumentData)),
            None => Err("".into()), // TODO
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
    fn from_wire_partial(input: &[u8]) -> Result<(&[u8], Self), String> {
        use nom::{combinator::complete, IResult};
        use unsigned_varint::nom as varuint_nom;

        fn parse(input: &[u8]) -> IResult<&[u8], (u32, PartType, usize)> {
            let (input, version) = varuint_nom::u32(input)?;
            let (input, data_type) = PartType::from_wire_partial(input).unwrap(); // TODO TODO TODO
            let (input, num_parts) = varuint_nom::usize(input)?;

            Ok((input, (version, data_type, num_parts)))
        }
        let mut parse = complete(parse);

        let (input, (version, data_type, num_parts)) =
            parse(input).map_err(|err| format!("{:?}", err))?;

        Ok((
            input,
            PartMeta {
                version,
                data_type,
                num_parts,
            },
        ))
    }
}

#[derive(Clone, Debug)]
pub struct Part {
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
    fn from_wire_partial(input: &[u8]) -> Result<(&[u8], Self), String> {
        use nom::{bytes::streaming::tag, combinator::complete, IResult};
        use unsigned_varint::nom as varuint_nom;

        fn parse(input: &[u8]) -> IResult<&[u8], (PartMeta, usize, Vec<u8>)> {
            let (input, _) = tag(b"Pb")(input)?;
            let (input, meta) = PartMeta::from_wire_partial(input).unwrap(); // TODO TODO TODO
            let (input, part_idx) = varuint_nom::usize(input)?;
            // TODO: Is this correct?
            let (input, data) = (&input[0..0], input.to_vec());

            Ok((input, (meta, part_idx, data)))
        }
        let mut parse = complete(parse);

        let (input, (meta, part_idx, data)) = parse(input).map_err(|err| format!("{:?}", err))?;

        Ok((
            input,
            Part {
                meta,
                part_idx,
                data,
            },
        ))
    }
}

#[derive(Default, Debug)]
pub struct Joiner {
    meta: Option<PartMeta>,
    parts: Vec<Option<Part>>,
}

impl Joiner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn remaining(&self) -> Option<usize> {
        self.meta
            .map(|_| self.parts.iter().filter(|v| v.is_none()).count())
    }

    pub fn complete(&self) -> bool {
        self.remaining() == Some(0)
    }

    pub fn add_part(&mut self, part: Part) -> Result<&mut Self, Error> {
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

    pub fn add_qr_part<B: AsRef<str>>(&mut self, qr_data: B) -> Result<&mut Self, Error> {
        let part = Part::from_wire_multibase(qr_data.as_ref()).map_err(Error::ParseQrData)?;
        self.add_part(part)
    }

    pub fn combine_parts(&self) -> Result<Vec<u8>, Error> {
        let mut data_len = 0usize;
        for (idx, part) in self.parts.iter().enumerate() {
            if let Some(part) = part {
                data_len += part.data.len();
            } else {
                return Err(Error::MissingQrSegment { idx });
            }
        }
        let mut bytes = Vec::with_capacity(data_len);
        for part in self.parts.iter().flatten() {
            bytes.extend_from_slice(&part.data)
        }
        Ok(bytes)
    }
}

const DATA_OVERHEAD: usize = 1 /* multibase header */ +
                             1 /* (varuint) version = 0 */ +
                             1 /* data type */ +
                             2 * 9 /* 2*varuint length and index */;

// TODO: Make this dynamic based on the error correction mode.
//const MAX_DATA_LENGTH: usize = 926 - DATA_OVERHEAD;
const MAX_DATA_LENGTH: usize = 626 - DATA_OVERHEAD;

fn split_data<B: AsRef<[u8]>>(data_type: PartType, data: B) -> Vec<Part> {
    let data = data.as_ref();
    let chunks = data.chunks(MAX_DATA_LENGTH).collect::<Vec<_>>();
    chunks
        .iter()
        .enumerate()
        .map(|(idx, &chunk)| Part {
            meta: PartMeta {
                version: PAPERBACK_VERSION,
                data_type,
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
) -> Result<(Vec<QrCode>, Vec<Vec<u8>>), Error> {
    let codes = split_data(data_type, data)
        .iter()
        .map(ToWire::to_wire)
        .collect::<Vec<_>>();
    Ok((
        codes
            .iter()
            .map(|data| multibase::encode(QRCODE_MULTIBASE, data))
            .map(QrCode::new)
            .collect::<Result<Vec<_>, _>>()?,
        codes,
    ))
}

pub(super) fn generate_one_code<B: AsRef<[u8]>>(data: B) -> Result<(QrCode, Vec<u8>), Error> {
    // NOTE: We don't use a split code for single-QR-code data segments. The
    // reason for this is that the part header takes up space, and it also
    // causes checksums to be encoded differently (meaning that the document ID
    // would no longer be the last x characters of the hash).
    let data = data.as_ref();
    Ok((
        QrCode::new(multibase::encode(QRCODE_MULTIBASE, data))?,
        data.to_vec(),
    ))
}

#[cfg(test)]
mod test {
    use super::*;

    use quickcheck::*;
    use rand::seq::SliceRandom;

    #[quickcheck]
    fn split_join_qr_parts(data: Vec<u8>) -> Result<bool, Error> {
        let mut parts = split_data(PartType::MainDocumentData, &data);
        let mut joiner = Joiner::new();

        parts.shuffle(&mut rand::thread_rng());
        for part in parts {
            joiner.add_part(part)?;
        }
        Ok(joiner.combine_parts()? == data)
    }
}
