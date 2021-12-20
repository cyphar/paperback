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
    pdf::{qr, qr::PartType, Error},
    EncryptedKeyShard, KeyShardCodewords, MainDocument, ToWire,
};

use multibase::Base;
use printpdf::*;
use qrcode::render::svg;

pub trait ToPdf {
    fn to_pdf(&self) -> Result<PdfDocumentReference, Error>;
}

// TODO: Use azul-text-layout or some other text layout library to reduce the
// hardcoded offsets used here. Unfortunately azul doesn't have a copy of the
// builtin PDF fonts so we will need to switch to another font (and embed the
// font data into the paperback code).

const SVG_DPI: f64 = 300.0;
const MARGIN: Mm = Mm(5.0);

mod colours {
    use printpdf::*;

    pub(super) const BLACK: Color = Color::Rgb(Rgb {
        r: 0.0,
        g: 0.0,
        b: 0.0,
        icc_profile: None,
    });

    pub(super) const GREY: Color = Color::Rgb(Rgb {
        r: 0.4,
        g: 0.4,
        b: 0.4,
        icc_profile: None,
    });

    pub(super) const MAIN_DOCUMENT_TRIM: Color = Color::Rgb(Rgb {
        r: 1.0,
        g: 0.4,
        b: 0.0,
        icc_profile: None,
    });

    pub(super) const KEY_SHARD_TRIM: Color = Color::Rgb(Rgb {
        r: 0.17255,
        g: 0.62745,
        b: 0.17255,
        icc_profile: None,
    });
}

fn px_to_mm(px: Px) -> Mm {
    px.into_pt(SVG_DPI).into()
}

/*
fn banner<S: Into<String>>(
    layer: &PdfLayerReference,
    y: Mm,
    width: Mm,
    text: S,
    font: &IndirectFontRef,
) {
}
*/

fn text_fallback<D: AsRef<[u8]>>(
    layer: &PdfLayerReference,
    (x, y): (Mm, Mm),
    _width: Mm,
    data: D,
    font: &IndirectFontRef,
    font_size: f64,
) {
    let data_lines = multibase::encode(Base::Base32Z, data)
        .into_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c))
        .collect::<Vec<_>>()
        .chunks(9) // TODO: Calculate the right width dynamically using azul-text-layout.
        .map(|c| c.join("-"))
        .collect::<Vec<String>>();

    layer.begin_text_section();
    {
        layer.set_font(font, font_size - 2.0);
        layer.set_line_height((font_size - 2.0) * 1.5);
        layer.set_word_spacing(1.2);
        layer.set_character_spacing(1.0);
        layer.set_text_rendering_mode(TextRenderingMode::Fill);

        layer.set_text_cursor(x, y);
        layer.write_text("text fallback if barcode scanning fails", font);
    }
    layer.end_text_section();
    layer.begin_text_section();
    {
        layer.set_font(font, font_size);
        layer.set_line_height(font_size * 1.5);
        layer.set_word_spacing(1.2);
        layer.set_character_spacing(1.0);
        layer.set_text_rendering_mode(TextRenderingMode::Fill);

        layer.set_text_cursor(x, y);
        layer.add_line_break();
        for (i, line) in data_lines.iter().enumerate() {
            if i % 2 == 0 {
                layer.set_fill_color(colours::BLACK);
            } else {
                layer.set_fill_color(colours::GREY);
            }
            layer.write_text(line, font);
            layer.add_line_break();
        }
    }
    layer.end_text_section();
}

const A4_WIDTH: Mm = Mm(210.0);
const A4_HEIGHT: Mm = Mm(297.0);

impl ToPdf for MainDocument {
    fn to_pdf(&self) -> Result<PdfDocumentReference, Error> {
        // Generate QR codes to embed in the PDF.
        let (data_qrs, data_qr_datas) =
            qr::generate_codes(PartType::MainDocumentData, self.to_wire())?;
        let data_qrs = data_qrs
            .iter()
            .map(|code| code.render::<svg::Color>().build())
            .map(|svg| Svg::parse(&svg))
            .collect::<Result<Vec<_>, _>>()
            .map_err(Error::ParseSvg)?; // TODO: Use (#[from] SvgParseError);

        let (chksum_qr, chksum_qr_data) =
            qr::generate_one_code(PartType::MainDocumentChecksum, &self.checksum().to_bytes())?;
        let chksum_qr =
            Svg::parse(&chksum_qr.render::<svg::Color>().build()).map_err(Error::ParseSvg)?; // TODO: Use (#[from] SvgParseError);

        // Construct an A4 PDF.
        let (doc, page1, layer1) = PdfDocument::new(
            format!("Paperback Main Document {}", self.id()),
            A4_WIDTH,
            A4_HEIGHT,
            "Layer 1",
        );

        let monospace_font = doc.add_builtin_font(BuiltinFont::Courier)?;
        let text_font = doc.add_builtin_font(BuiltinFont::Helvetica)?;

        let current_page = doc.get_page(page1);
        let current_layer = current_page.get_layer(layer1);

        // Header.
        current_layer.begin_text_section();
        {
            current_layer.set_font(&monospace_font, 10.0);
            current_layer.set_word_spacing(1.2);
            current_layer.set_character_spacing(1.0);

            current_layer.set_text_cursor(MARGIN, A4_HEIGHT - MARGIN - Pt(10.0).into());
            current_layer.set_line_height(10.0 + 5.0);

            // "Document".
            current_layer.set_font(&monospace_font, 10.0);
            current_layer.set_fill_color(colours::GREY);
            current_layer.write_text("Document", &monospace_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.add_line_break();
            // <document id>
            current_layer.set_font(&monospace_font, 20.0);
            current_layer.set_fill_color(colours::MAIN_DOCUMENT_TRIM);
            current_layer.write_text(self.id(), &monospace_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.add_line_break();

            // Details.
            current_layer.set_font(&text_font, 10.0);
            current_layer.write_text(
                format!(
                    "This is the main document of a paperback backup. When combined with {} unique",
                    self.quorum_size()
                ),
                &text_font,
            );
            current_layer.add_line_break();
            current_layer.write_text(
                "key shards, this document can be recovered. In order to recover this document,",
                &text_font,
            );
            current_layer.add_line_break();
            current_layer.write_text(
                "download the latest version of paperback from cyphar.com/paperback.",
                &text_font,
            );
        }
        current_layer.end_text_section();

        let data_qr_refs = data_qrs
            .into_iter()
            .map(|code| code.into_xobject(&current_layer))
            .collect::<Vec<_>>();

        // TODO: Get rid of this.
        println!("Main Document:");
        data_qr_datas
            .iter()
            .for_each(|code| println!("{}", multibase::encode(multibase::Base::Base10, code)));

        let (mut current_x, mut current_y) = (Mm(0.0), MARGIN + Mm(35.0));
        for svg in data_qr_refs {
            let target_size = A4_WIDTH / 3.0 - Mm(1.0);
            let (width, height) = (svg.width, svg.height);
            let (scale_x, scale_y) = (
                target_size.0 / px_to_mm(width).0,
                target_size.0 / px_to_mm(height).0,
            );
            if current_x + target_size > A4_WIDTH {
                current_x = Mm(0.0);
                current_y += target_size;
            }
            svg.add_to_layer(
                &current_layer,
                SvgTransform {
                    translate_x: Some(current_x),
                    translate_y: Some(A4_HEIGHT - (current_y + target_size)),
                    dpi: Some(SVG_DPI),
                    scale_x: Some(scale_x),
                    scale_y: Some(scale_y),
                    ..Default::default()
                },
            );
            current_x += target_size;
            if current_x > A4_WIDTH {
                current_x = Mm(0.0);
                current_y += target_size;
            }
        }

        current_y += A4_WIDTH / 3.0;
        {
            let chksum_code_ref = chksum_qr.into_xobject(&current_layer);

            let target_size = A5_WIDTH * 0.3;
            let (scale_x, scale_y) = (
                target_size.0 / px_to_mm(chksum_code_ref.width).0,
                target_size.0 / px_to_mm(chksum_code_ref.height).0,
            );

            // Document checksum.
            chksum_code_ref.add_to_layer(
                &current_layer,
                SvgTransform {
                    translate_x: Some(MARGIN),
                    translate_y: Some(A4_HEIGHT - (current_y + target_size)),
                    scale_x: Some(scale_x),
                    scale_y: Some(scale_y),
                    ..Default::default()
                },
            );
            text_fallback(
                &current_layer,
                (
                    MARGIN + A4_WIDTH * 0.32,
                    A4_HEIGHT - (current_y + target_size / 2.0 - Mm(1.0)),
                ),
                A5_WIDTH,
                chksum_qr_data,
                &monospace_font,
                12.0,
            );
        }

        doc.check_for_errors()?;
        Ok(doc)
    }
}

const A5_WIDTH: Mm = Mm(148.0);
const A5_HEIGHT: Mm = Mm(210.0);

impl ToPdf for (&EncryptedKeyShard, &KeyShardCodewords) {
    fn to_pdf(&self) -> Result<PdfDocumentReference, Error> {
        let (shard, codewords) = self;
        // TODO: Make this nicer. It's quite ugly we need to decrypt the shard
        // here just to get the document and shard ids. If we cached them that
        // would work, but if you just read the shard data from the user you
        // wouldn't have this information without decrypting it.
        let decrypted_shard = shard
            .decrypt(codewords)
            .map_err(|err| Error::OtherError(format!("failed to decrypt shard: {:?}", err)))?;

        // Generate QR codes to embed in the PDF.
        let (data_qr, data_qr_data) =
            qr::generate_one_code(PartType::KeyShardData, shard.to_wire())?;
        let data_qr =
            Svg::parse(&data_qr.render::<svg::Color>().build()).map_err(Error::ParseSvg)?; // TODO: Use (#[from] SvgParseError);

        let (chksum_qr, chksum_qr_data) =
            qr::generate_one_code(PartType::KeyShardChecksum, &shard.checksum().to_bytes())?;
        let chksum_qr =
            Svg::parse(&chksum_qr.render::<svg::Color>().build()).map_err(Error::ParseSvg)?; // TODO: Use (#[from] SvgParseError);

        // Construct an A5 PDF.
        let (doc, page1, layer1) = PdfDocument::new(
            format!(
                "Paperback Key Shard {}/{}",
                decrypted_shard.document_id(),
                decrypted_shard.id()
            ),
            A5_WIDTH,
            A5_HEIGHT,
            "Layer 1",
        );

        let monospace_font = doc.add_builtin_font(BuiltinFont::Courier)?;
        let monospace_bold_font = doc.add_builtin_font(BuiltinFont::CourierBold)?;
        let text_font = doc.add_builtin_font(BuiltinFont::Helvetica)?;

        let current_page = doc.get_page(page1);
        let current_layer = current_page.get_layer(layer1);

        let mut current_y = MARGIN * 2.0;

        // Header.
        current_layer.begin_text_section();
        {
            current_layer.set_font(&monospace_font, 10.0);
            current_layer.set_word_spacing(1.2);
            current_layer.set_character_spacing(1.0);

            current_layer.set_text_cursor(MARGIN, A5_HEIGHT - current_y);
            current_layer.set_line_height(10.0 + 5.0);

            // "Document".
            current_layer.set_font(&monospace_font, 10.0);
            current_layer.set_fill_color(colours::GREY);
            current_layer.write_text("Document", &monospace_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.add_line_break();
            // <document id>
            current_layer.set_font(&monospace_font, 20.0);
            current_layer.set_fill_color(colours::MAIN_DOCUMENT_TRIM);
            current_layer.write_text(decrypted_shard.document_id(), &monospace_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.add_line_break();

            // "Shard".
            current_layer.set_font(&monospace_font, 10.0);
            current_layer.set_fill_color(colours::GREY);
            current_layer.write_text("Shard", &monospace_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.add_line_break();
            // <shard id>
            current_layer.set_font(&monospace_font, 20.0);
            current_layer.set_fill_color(colours::KEY_SHARD_TRIM);
            current_layer.write_text(decrypted_shard.id(), &monospace_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.add_line_break();
        }
        current_layer.end_text_section();
        current_layer.begin_text_section();
        {
            // Details.
            current_layer.set_text_cursor(MARGIN + Mm(45.0), A5_HEIGHT - current_y);
            current_layer.set_font(&text_font, 10.0);
            current_layer.set_line_height(10.0 + 5.0);
            current_layer.write_text("This is a key shard of a paperback backup.", &text_font);
            current_layer.add_line_break();
            current_layer.write_text("See cyphar.com/paperback for more details.", &text_font);
        }
        current_layer.end_text_section();

        current_y += Mm(40.0);
        {
            let data_qr_ref = data_qr.into_xobject(&current_layer);

            let target_size = A5_WIDTH * 0.3;
            let (scale_x, scale_y) = (
                target_size.0 / px_to_mm(data_qr_ref.width).0,
                target_size.0 / px_to_mm(data_qr_ref.height).0,
            );

            // Shard data.
            data_qr_ref.add_to_layer(
                &current_layer,
                SvgTransform {
                    translate_x: Some(MARGIN),
                    translate_y: Some(A5_HEIGHT - (current_y + target_size)),
                    scale_x: Some(scale_x),
                    scale_y: Some(scale_y),
                    ..Default::default()
                },
            );
            text_fallback(
                &current_layer,
                (MARGIN + A5_WIDTH * 0.32, A5_HEIGHT - current_y),
                A5_WIDTH,
                data_qr_data,
                &monospace_font,
                8.0,
            );
        }

        current_y += Mm(60.0);
        {
            let chksum_qr_ref = chksum_qr.into_xobject(&current_layer);

            let target_size = A5_WIDTH * 0.3;
            let (scale_x, scale_y) = (
                target_size.0 / px_to_mm(chksum_qr_ref.width).0,
                target_size.0 / px_to_mm(chksum_qr_ref.height).0,
            );

            // Shard checksum.
            chksum_qr_ref.add_to_layer(
                &current_layer,
                SvgTransform {
                    translate_x: Some(MARGIN),
                    translate_y: Some(A5_HEIGHT - (current_y + target_size)),
                    scale_x: Some(scale_x),
                    scale_y: Some(scale_y),
                    ..Default::default()
                },
            );
            text_fallback(
                &current_layer,
                (
                    MARGIN + A5_WIDTH * 0.32,
                    A5_HEIGHT - (current_y + target_size / 2.0 - Mm(1.0)),
                ),
                A5_WIDTH,
                chksum_qr_data,
                &monospace_font,
                8.0,
            );
        }

        // Shard codewords.
        current_y = A5_HEIGHT - Mm(40.0);
        current_layer.begin_text_section();
        {
            current_layer.set_font(&monospace_font, 10.0);
            current_layer.set_word_spacing(1.2);
            current_layer.set_character_spacing(1.0);
            current_layer.set_line_height(10.0 + 5.0);

            current_layer.set_text_cursor(MARGIN, A5_HEIGHT - current_y);

            // "Document".
            current_layer.set_font(&monospace_font, 10.0);
            current_layer.set_fill_color(colours::GREY);
            current_layer.write_text("Document", &monospace_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.add_line_break();
            // <document id>
            current_layer.set_font(&monospace_font, 20.0);
            current_layer.set_fill_color(colours::MAIN_DOCUMENT_TRIM);
            current_layer.write_text(decrypted_shard.document_id(), &monospace_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.add_line_break();

            // "Shard".
            current_layer.set_font(&monospace_font, 10.0);
            current_layer.set_fill_color(colours::GREY);
            current_layer.write_text("Shard", &monospace_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.add_line_break();
            // <shard id>
            current_layer.set_font(&monospace_font, 20.0);
            current_layer.set_fill_color(colours::KEY_SHARD_TRIM);
            current_layer.write_text(decrypted_shard.id(), &monospace_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.add_line_break();
        }
        current_layer.end_text_section();
        current_layer.begin_text_section();
        {
            current_layer.set_word_spacing(1.2);
            current_layer.set_character_spacing(1.0);
            current_layer.set_line_height(10.0 + 5.0);

            // Codewords.
            current_layer.set_font(&monospace_font, 10.0);
            current_layer.set_text_cursor(MARGIN + Mm(45.0), A5_HEIGHT - current_y);
            for (i, codeword) in codewords.iter().enumerate() {
                let font = if i % 2 == 0 {
                    current_layer.set_font(&monospace_font, 10.0);
                    &monospace_font
                } else {
                    current_layer.set_font(&monospace_bold_font, 10.0);
                    &monospace_bold_font
                };
                current_layer.write_text(codeword, &font);
                if i % 5 == 4 {
                    current_layer.add_line_break();
                } else {
                    current_layer.write_text(" ", &font);
                }
            }
        }
        current_layer.end_text_section();

        doc.check_for_errors()?;
        Ok(doc)
    }
}

impl ToPdf for (EncryptedKeyShard, KeyShardCodewords) {
    fn to_pdf(&self) -> Result<PdfDocumentReference, Error> {
        let (shard, codewords) = self;
        (shard, codewords).to_pdf()
    }
}
