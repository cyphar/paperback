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

pub mod pdf;
pub mod qr;

pub use pdf::ToPdf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mismatched qr code data")]
    MismatchedQrCode,

    #[error("missing qr code segment {}", .idx+1)]
    MissingQrSegment { idx: usize },

    #[error("qr code created using unsupported paperback version {version}")]
    WrongPaperbackVersion { version: u32 },

    #[error("failed to parse raw encoded data: {0}")]
    ParseRawData(String),

    #[error("qr code data parsing error: {0}")]
    ParseQrData(String),

    #[error("qr code generation error: {0}")]
    GenerateQr(#[from] qrcode::types::QrError),

    #[error("too many qr codes generated for {0} segment")]
    TooManyCodes(String),

    #[error("svg parsing error: {0:?}")]
    // Cannot use #[from] <https://github.com/fschutt/printpdf/issues/106>.
    ParseSvg(printpdf::SvgParseError),

    #[error("pdf generation error: {0}")]
    GeneratePdf(#[from] printpdf::Error),

    #[error("miscellaneous error: {0}")]
    OtherError(String),
}

// While counter-intuitive, numerical codes give us almost identical density to
// binary (which we can't use due to issues with copy-paste, null bytes, and
// dodgy readers).
//
// Another alternative would be to use the Shift-JIS encoding as a dodgy way to
// get everything out of the two-byte encoding (if we map every 2-byte sequence
// to a kanji, it would allow us to have almost zero overhead encoding).
const QRCODE_MULTIBASE: multibase::Base = multibase::Base::Base10;
