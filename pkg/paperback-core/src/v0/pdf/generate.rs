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

mod colours {
    use printpdf::*;

    // #000000
    pub(super) const BLACK: Color = Color::Rgb(Rgb {
        r: 0.0,
        g: 0.0,
        b: 0.0,
        icc_profile: None,
    });

    // #666666
    pub(super) const GREY: Color = Color::Rgb(Rgb {
        r: 0.4,
        g: 0.4,
        b: 0.4,
        icc_profile: None,
    });

    // #999999
    pub(super) const LIGHT_GREY: Color = Color::Rgb(Rgb {
        r: 0.6,
        g: 0.6,
        b: 0.6,
        icc_profile: None,
    });

    // #ff6600
    pub(super) const MAIN_DOCUMENT_TRIM: Color = Color::Rgb(Rgb {
        r: 1.0,
        g: 0.4,
        b: 0.0,
        icc_profile: None,
    });

    // #2c9f2c
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

fn text_fallback<D: AsRef<[u8]>>(
    layer: &PdfLayerReference,
    (x, y): (Mm, Mm),
    _width: Mm,
    data: D,
    font: &IndirectFontRef,
    font_size: f64,
) -> Mm {
    let data_lines = multibase::encode(Base::Base32Z, data)
        // Split the encoded version into 4-char words.
        .into_bytes()
        .chunks(4)
        .map(String::from_utf8_lossy)
        .collect::<Vec<_>>()
        // Split the words into rows for printing.
        // TODO: Calculate the right width dynamically using azul-text-layout.
        .chunks(8)
        // Join the words with "-". This is to work around the fact that
        // printpdf appears to generate PDFs such that horizontally-written
        // words get selected as if they were columns (breaking copy-and-paste
        // for these data sections).
        .map(|ws| ws.join("-"))
        .map(|mut line| match line.len() {
            39 /* 4*8+7 */ => line, // Line is the right length.
            l @ 0..=38 => { // Line needs to be padded.
                line.push_str(&"-".repeat(39-l));
                line
            },
            _ => unreachable!(), // Not possible given how this string was constructed.
        })
        .collect::<Vec<String>>();

    layer.begin_text_section();
    {
        layer.set_font(font, font_size - 2.0);
        layer.set_line_height(font_size - 2.0 + 2.0);
        layer.set_word_spacing(1.2);
        layer.set_character_spacing(1.0);
        layer.set_text_rendering_mode(TextRenderingMode::Fill);

        layer.set_text_cursor(x, y);
        layer.set_fill_color(colours::LIGHT_GREY);
        layer.write_text("text fallback if barcode scanning fails", font);
    }
    layer.end_text_section();
    layer.begin_text_section();
    {
        layer.set_font(font, font_size);
        layer.set_line_height(font_size + 2.0);
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

    Mm::from(Pt(font_size + 2.0)) * (data_lines.len() as f64)
}

const A4_WIDTH: Mm = Mm(210.0);
const A4_HEIGHT: Mm = Mm(297.0);
const A4_MARGIN: Mm = Mm(10.0);
const QR_MARGIN: Mm = Mm(5.0);

const FONT_ROBOTOSLAB: &[u8] = include_bytes!("fonts/RobotoSlab-Regular.ttf");
const FONT_B612MONO: &[u8] = include_bytes!("fonts/B612Mono-Regular.ttf");
const FONT_B612MONO_BOLD: &[u8] = include_bytes!("fonts/B612Mono-Bold.ttf");

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

        let (chksum_qr, chksum_qr_data) = qr::generate_one_code(&self.checksum().to_bytes())?;
        let chksum_qr =
            Svg::parse(&chksum_qr.render::<svg::Color>().build()).map_err(Error::ParseSvg)?; // TODO: Use (#[from] SvgParseError);

        // Construct an A4 PDF.
        let (doc, page1, layer1) = PdfDocument::new(
            format!("Paperback Main Document {}", self.id()),
            A4_WIDTH,
            A4_HEIGHT,
            "Layer 1",
        );

        let monospace_font = doc.add_external_font(FONT_B612MONO)?;
        let text_font = doc.add_external_font(FONT_ROBOTOSLAB)?;

        let current_page = doc.get_page(page1);
        let current_layer = current_page.get_layer(layer1);

        let mut current_y = A4_MARGIN + Pt(10.0).into();

        // Header.
        current_layer.begin_text_section();
        {
            current_layer.set_font(&monospace_font, 10.0);
            current_layer.set_word_spacing(1.2);
            current_layer.set_character_spacing(1.0);

            current_layer.set_text_cursor(A4_MARGIN, A4_HEIGHT - current_y);

            // "Document".
            current_layer.set_font(&text_font, 10.0);
            current_layer.set_fill_color(colours::GREY);
            current_layer.write_text("Document", &text_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.set_line_height(20.0 + 2.0);
            current_layer.add_line_break();
            // <document id>
            current_layer.set_font(&monospace_font, 20.0);
            current_layer.set_fill_color(colours::MAIN_DOCUMENT_TRIM);
            current_layer.write_text(self.id(), &monospace_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.set_line_height(10.0 + 2.0);

            current_layer.add_line_break();
            current_layer.add_line_break();

            // Details.
            current_layer.set_font(&text_font, 10.0);
            current_layer.set_line_height(10.0 + 2.0);
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
        current_layer.begin_text_section();
        {
            // Header. TODO: Right-align this text.
            current_layer.set_text_cursor(
                A4_WIDTH - (A4_MARGIN + (Pt(15.0) * 12.0).into()),
                A4_HEIGHT - (current_y + Pt(10.0).into()),
            );
            current_layer.set_font(&text_font, 20.0);
            current_layer.set_fill_color(colours::MAIN_DOCUMENT_TRIM);
            current_layer.write_text("Main Document", &text_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.set_line_height(10.0 + 2.0);
            current_layer.add_line_break();

            current_layer.set_font(&monospace_font, 10.0);
            current_layer.set_fill_color(colours::GREY);
            current_layer.write_text("paperback-v0", &monospace_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.set_line_height(10.0 + 2.0);
        }
        current_layer.end_text_section();
        current_y += (Pt(22.0) + Pt(12.0) * 6.0).into();

        // TODO: Get rid of this once we have nice QR code scanning.
        println!("Main Document:");
        data_qr_datas
            .iter()
            .for_each(|code| println!("{}", multibase::encode(multibase::Base::Base10, code)));

        let mut current_x = A4_MARGIN;
        let mut data_qr_refs = data_qrs
            .into_iter()
            .map(|code| code.into_xobject(&current_layer));
        for _ in 0..9 {
            let target_size = (A4_WIDTH - A4_MARGIN * 2.0) / 3.0;
            if current_x + target_size > A4_WIDTH {
                current_x = A4_MARGIN;
                current_y += target_size;
            }
            match data_qr_refs.next() {
                Some(svg) => {
                    let (width, height) = (svg.width, svg.height);
                    let (scale_x, scale_y) = (
                        target_size / px_to_mm(width),
                        target_size / px_to_mm(height),
                    );
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
                }
                None => {
                    // Dashed line box where the QR code would go.
                    let points = vec![
                        (
                            Point::new(
                                current_x + QR_MARGIN / 2.0,
                                A4_HEIGHT - (current_y + QR_MARGIN / 2.0),
                            ),
                            false,
                        ),
                        (
                            Point::new(
                                current_x + target_size - QR_MARGIN / 2.0,
                                A4_HEIGHT - (current_y + QR_MARGIN / 2.0),
                            ),
                            false,
                        ),
                        (
                            Point::new(
                                current_x + target_size - QR_MARGIN / 2.0,
                                A4_HEIGHT - (current_y + target_size - QR_MARGIN / 2.0),
                            ),
                            false,
                        ),
                        (
                            Point::new(
                                current_x + QR_MARGIN / 2.0,
                                A4_HEIGHT - (current_y + target_size - QR_MARGIN / 2.0),
                            ),
                            false,
                        ),
                    ];

                    let line = Line {
                        points,
                        is_closed: true,
                        has_fill: false,
                        has_stroke: true,
                        is_clipping_path: false,
                    };

                    let mut dash_pattern = LineDashPattern::default();
                    dash_pattern.dash_1 = Some(6);
                    dash_pattern.gap_1 = Some(4);

                    current_layer.set_outline_color(colours::LIGHT_GREY);
                    current_layer.set_line_dash_pattern(dash_pattern);
                    current_layer.add_shape(line);
                }
            };
            current_x += target_size;
            if current_x > A4_WIDTH {
                current_x = Mm(0.0);
                current_y += target_size;
            }
        }
        if data_qr_refs.next().is_some() {
            return Err(Error::TooManyCodes(
                "only 9 codes allowed in this version of paperback".to_string(),
            ));
        }

        current_y = A4_HEIGHT - (A4_WIDTH * 0.2 + A4_MARGIN);
        {
            let chksum_code_ref = chksum_qr.into_xobject(&current_layer);

            let target_size = A4_WIDTH * 0.2;
            let (scale_x, scale_y) = (
                target_size / px_to_mm(chksum_code_ref.width),
                target_size / px_to_mm(chksum_code_ref.height),
            );

            // Document checksum.
            text_fallback(
                &current_layer,
                (
                    A4_MARGIN + A4_WIDTH * 0.32,
                    A4_HEIGHT - (current_y + target_size / 2.0 - (Pt(8.0) * 2.0).into()),
                ),
                A4_WIDTH,
                chksum_qr_data,
                &monospace_font,
                10.0,
            );
            chksum_code_ref.add_to_layer(
                &current_layer,
                SvgTransform {
                    translate_x: Some(A4_MARGIN),
                    translate_y: Some(A4_HEIGHT - (current_y + target_size)),
                    scale_x: Some(scale_x),
                    scale_y: Some(scale_y),
                    ..Default::default()
                },
            );
        }

        doc.check_for_errors()?;
        Ok(doc)
    }
}

const A5_WIDTH: Mm = Mm(148.0);
const A5_HEIGHT: Mm = Mm(210.0);
const A5_MARGIN: Mm = Mm(5.0);

const SCISSORS_SVG: &str = include_str!("scissors.svg");

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
        let (data_qr, data_qr_data) = qr::generate_one_code(shard.to_wire())?;
        let data_qr =
            Svg::parse(&data_qr.render::<svg::Color>().build()).map_err(Error::ParseSvg)?; // TODO: Use (#[from] SvgParseError);

        let (chksum_qr, chksum_qr_data) = qr::generate_one_code(&shard.checksum().to_bytes())?;
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

        let monospace_font = doc.add_external_font(FONT_B612MONO)?;
        let monospace_bold_font = doc.add_external_font(FONT_B612MONO_BOLD)?;
        let text_font = doc.add_external_font(FONT_ROBOTOSLAB)?;

        let current_page = doc.get_page(page1);
        let current_layer = current_page.get_layer(layer1);

        let mut current_y = A5_MARGIN + Pt(10.0).into();

        // Header.
        current_layer.begin_text_section();
        {
            current_layer.set_word_spacing(1.2);
            current_layer.set_character_spacing(1.0);

            current_layer.set_text_cursor(A5_MARGIN, A5_HEIGHT - current_y);

            // "Document".
            current_layer.set_font(&text_font, 10.0);
            current_layer.set_fill_color(colours::GREY);
            current_layer.write_text("Document", &text_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.set_line_height(20.0 + 2.0);
            current_layer.add_line_break();
            // <document id>
            current_layer.set_font(&monospace_font, 20.0);
            current_layer.set_fill_color(colours::MAIN_DOCUMENT_TRIM);
            current_layer.write_text(decrypted_shard.document_id(), &monospace_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.set_line_height(10.0 + 2.0);
            current_layer.add_line_break();
            current_layer.add_line_break();

            // "Shard".
            current_layer.set_font(&text_font, 10.0);
            current_layer.set_fill_color(colours::GREY);
            current_layer.write_text("Shard", &text_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.set_line_height(20.0 + 2.0);
            current_layer.add_line_break();
            // <shard id>
            current_layer.set_font(&monospace_font, 20.0);
            current_layer.set_fill_color(colours::KEY_SHARD_TRIM);
            current_layer.write_text(decrypted_shard.id(), &monospace_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.set_line_height(10.0 + 2.0);
            current_layer.add_line_break();
        }
        current_layer.end_text_section();
        current_layer.begin_text_section();
        {
            // Header. TODO: Right-align this text.
            current_layer.set_text_cursor(
                A5_WIDTH - (A5_MARGIN + (Pt(15.0) * 8.0).into()),
                A5_HEIGHT - (current_y + Pt(10.0).into()),
            );
            current_layer.set_font(&text_font, 20.0);
            current_layer.set_fill_color(colours::KEY_SHARD_TRIM);
            current_layer.write_text("Key Shard", &text_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.set_line_height(10.0 + 2.0);
            current_layer.add_line_break();

            current_layer.set_font(&monospace_font, 10.0);
            current_layer.set_fill_color(colours::GREY);
            current_layer.write_text("paperback-v0", &monospace_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.set_line_height(10.0 + 2.0);
        }
        current_layer.end_text_section();
        current_layer.begin_text_section();
        {
            current_layer.set_text_cursor(
                A5_MARGIN + Mm(45.0),
                A5_HEIGHT - (current_y + (Pt(12.0) * 5.0).into()),
            );

            // Details.
            current_layer.set_font(&text_font, 10.0);
            current_layer.set_line_height(10.0 + 2.0);
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
                target_size / px_to_mm(data_qr_ref.width),
                target_size / px_to_mm(data_qr_ref.height),
            );

            // Shard data.
            let text_height = text_fallback(
                &current_layer,
                (A5_MARGIN + A5_WIDTH * 0.32, A5_HEIGHT - current_y),
                A5_WIDTH,
                data_qr_data,
                &monospace_font,
                8.0,
            );
            data_qr_ref.add_to_layer(
                &current_layer,
                SvgTransform {
                    translate_x: Some(A5_MARGIN),
                    translate_y: Some(
                        A5_HEIGHT - (current_y + target_size / 2.0 + text_height / 2.0),
                    ),
                    scale_x: Some(scale_x),
                    scale_y: Some(scale_y),
                    ..Default::default()
                },
            );
            current_y += text_height + A5_MARGIN;
        }

        {
            let chksum_qr_ref = chksum_qr.into_xobject(&current_layer);

            let target_size = A5_WIDTH * 0.3;
            let (scale_x, scale_y) = (
                target_size / px_to_mm(chksum_qr_ref.width),
                target_size / px_to_mm(chksum_qr_ref.height),
            );

            // Shard checksum.
            text_fallback(
                &current_layer,
                (
                    A5_MARGIN + A5_WIDTH * 0.32,
                    A5_HEIGHT - (current_y + target_size / 2.0 - (Pt(8.0) * 2.0).into()),
                ),
                A5_WIDTH,
                chksum_qr_data,
                &monospace_font,
                8.0,
            );
            chksum_qr_ref.add_to_layer(
                &current_layer,
                SvgTransform {
                    translate_x: Some(A5_MARGIN),
                    translate_y: Some(A5_HEIGHT - (current_y + target_size)),
                    scale_x: Some(scale_x),
                    scale_y: Some(scale_y),
                    ..Default::default()
                },
            );
            current_y += target_size;
        }

        // "Cut here" line.
        let cut_here_y = {
            let old_current_y = current_y;
            current_y = A5_HEIGHT - Mm(35.0); // For shard codewords.
            (current_y + old_current_y) / 2.0
        };
        {
            let scissors_svg = Svg::parse(SCISSORS_SVG).map_err(Error::ParseSvg)?; // TODO: Use (#[from] SvgParseError);
            let scissors_svg_ref = scissors_svg.into_xobject(&current_layer);

            // For scissors, scale the height then retain the height:width ratio.
            let target_height = Mm(5.0);
            let scale_y = target_height / px_to_mm(scissors_svg_ref.height);
            let scale_x =
                scale_y * (scissors_svg_ref.width.0 as f64 / scissors_svg_ref.height.0 as f64);

            // Dashed line.
            let points = vec![
                (Point::new(Mm(0.0), A5_HEIGHT - cut_here_y), false),
                (Point::new(A5_WIDTH, A5_HEIGHT - cut_here_y), false),
            ];
            let line = Line {
                points,
                is_closed: false,
                has_fill: false,
                has_stroke: true,
                is_clipping_path: false,
            };

            let mut dash_pattern = LineDashPattern::default();
            dash_pattern.dash_1 = Some(6);
            dash_pattern.gap_1 = Some(4);

            current_layer.set_outline_color(colours::KEY_SHARD_TRIM);
            current_layer.set_line_dash_pattern(dash_pattern);
            current_layer.add_shape(line);

            // Scissors.
            scissors_svg_ref.add_to_layer(
                &current_layer,
                SvgTransform {
                    translate_x: Some(A5_MARGIN),
                    translate_y: Some(A5_HEIGHT - (cut_here_y + target_height / 2.0)),
                    scale_x: Some(scale_x),
                    scale_y: Some(scale_y),
                    ..Default::default()
                },
            );
        }

        // Shard codewords.
        current_layer.begin_text_section();
        {
            current_layer.set_word_spacing(1.2);
            current_layer.set_character_spacing(1.0);
            current_layer.set_text_cursor(A5_MARGIN, A5_HEIGHT - current_y);

            // "Document".
            current_layer.set_font(&text_font, 10.0);
            current_layer.set_fill_color(colours::GREY);
            current_layer.write_text("Document", &text_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.set_line_height(20.0 + 2.0);
            current_layer.add_line_break();
            // <document id>
            current_layer.set_font(&monospace_font, 20.0);
            current_layer.set_fill_color(colours::MAIN_DOCUMENT_TRIM);
            current_layer.write_text(decrypted_shard.document_id(), &monospace_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.set_line_height(10.0 + 2.0);
            current_layer.add_line_break();
            current_layer.add_line_break();

            // "Shard".
            current_layer.set_font(&text_font, 10.0);
            current_layer.set_fill_color(colours::GREY);
            current_layer.write_text("Shard", &text_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.set_line_height(20.0 + 2.0);
            current_layer.add_line_break();
            // <shard id>
            current_layer.set_font(&monospace_font, 20.0);
            current_layer.set_fill_color(colours::KEY_SHARD_TRIM);
            current_layer.write_text(decrypted_shard.id(), &monospace_font);
            current_layer.set_fill_color(colours::BLACK);
            current_layer.set_line_height(10.0 + 2.0);
            current_layer.add_line_break();
        }
        current_layer.end_text_section();
        current_layer.begin_text_section();
        {
            current_layer.set_word_spacing(1.2);
            current_layer.set_character_spacing(1.0);
            current_layer.set_text_cursor(A5_MARGIN + Mm(45.0), A5_HEIGHT - current_y);

            // Codewords.
            current_layer.set_font(&monospace_font, 10.0);
            current_layer.set_line_height(10.0 + 5.0);
            for (i, codeword) in codewords.iter().enumerate() {
                let font = if i % 2 == 0 {
                    current_layer.set_font(&monospace_font, 10.0);
                    &monospace_font
                } else {
                    current_layer.set_font(&monospace_bold_font, 10.0);
                    &monospace_bold_font
                };
                current_layer.write_text(codeword, font);
                if i % 5 == 4 {
                    current_layer.add_line_break();
                } else {
                    current_layer.write_text(" ", font);
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
