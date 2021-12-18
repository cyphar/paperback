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

use std::{
    error::Error as StdError,
    fs::File,
    io,
    io::{prelude::*, BufReader},
};

use anyhow::{anyhow, Context, Error};
use clap::{App, Arg, ArgMatches, SubCommand};

extern crate paperback_core;
use paperback_core::latest as paperback;

const ENCODING_BASE: multibase::Base = multibase::Base::Base32Z;

fn raw_backup(matches: &ArgMatches<'_>) -> Result<(), Error> {
    use paperback::{Backup, ToWire};

    let sealed: bool = matches
        .value_of("sealed")
        .expect("invalid --sealed argument")
        .parse()
        .context("--sealed argument was not a boolean")?;
    let quorum_size: u32 = matches
        .value_of("quorum_size")
        .expect("required --quorum_size argument not given")
        .parse()
        .context("--quorum-size argument was not an unsigned integer")?;
    let num_shards: u32 = matches
        .value_of("shards")
        .expect("required --shards argument not given")
        .parse()
        .context("--shards argument was not an unsigned integer")?;
    let input_path = matches
        .value_of("INPUT")
        .expect("required INPUT argument not given");

    if num_shards < quorum_size {
        return Err(anyhow!("invalid arguments: number of shards cannot be smaller than quorum size (such a backup is unrecoverable)"));
    }

    let input: Box<dyn Read + 'static> = if input_path == "-" {
        Box::new(io::stdin())
    } else {
        Box::new(
            File::open(&input_path)
                .with_context(|| format!("failed to open secret data file '{}'", input_path))?,
        )
    };
    let mut buffer_input = BufReader::new(input);

    let mut secret = Vec::new();
    buffer_input
        .read_to_end(&mut secret)
        .with_context(|| format!("failed to read secret data from '{}'", input_path))?;

    let backup = if sealed {
        Backup::new_sealed(quorum_size.into(), &secret)
    } else {
        Backup::new(quorum_size.into(), &secret)
    }?;
    let main_document = backup.main_document().clone();
    let shards = (0..num_shards)
        .map(|_| backup.next_shard().unwrap())
        .map(|s| s.encrypt().unwrap())
        .collect::<Vec<_>>();

    println!("----- BEGIN MAIN DOCUMENT -----");
    println!("Document-ID: {}", main_document.id());
    println!("Checksum: {}", main_document.checksum_string());
    println!("\n{}", main_document.to_wire_multibase(ENCODING_BASE));
    println!("----- END MAIN DOCUMENT -----");

    for (i, (shard, keyword)) in shards.iter().enumerate() {
        let decrypted_shard = shard.clone().decrypt(keyword).unwrap();
        println!("----- BEGIN SHARD {} OF {} -----", i, quorum_size);
        println!("Document-ID: {}", decrypted_shard.document_id());
        println!("Shard-ID: {}", decrypted_shard.id());
        println!("Keywords: {}", keyword.join(" "));
        println!("\n{}", shard.to_wire_multibase(ENCODING_BASE));
        println!("----- END SHARD {} OF {} -----", i, quorum_size);
    }

    Ok(())
}

fn read_oneline_file(prompt: &str, path_or_stdin: &str) -> Result<String, Error> {
    let input: Box<dyn Read + 'static> = if path_or_stdin == "-" {
        print!("{}: ", prompt);
        io::stdout().flush()?;
        Box::new(io::stdin())
    } else {
        Box::new(
            File::open(&path_or_stdin)
                .with_context(|| format!("failed to open file '{}'", path_or_stdin))?,
        )
    };
    let buffer_input = BufReader::new(input);
    Ok(buffer_input
        .lines()
        .next()
        .ok_or_else(|| anyhow!("no lines read"))??)
}

fn raw_restore(matches: &ArgMatches<'_>) -> Result<(), Error> {
    use paperback::{EncryptedKeyShard, FromWire, MainDocument, UntrustedQuorum};

    let main_document_path = matches
        .value_of("main_document")
        .expect("required --main-document argument not given");
    let shard_paths = matches
        .values_of("shards")
        .expect("required --shard arguments not given");
    let output_path = matches
        .value_of("OUTPUT")
        .expect("required OUTPUT argument not given");

    let main_document = MainDocument::from_wire_multibase(
        read_oneline_file("Main Document Data", main_document_path)
            .context("open main document")?,
    )
    .map_err(|err| anyhow!(err)) // TODO: Fix this once FromWire supports non-String errors.
    .context("decode main document")?;

    println!("Document ID: {}", main_document.id());
    println!("Document Checksum: {}", main_document.checksum_string());

    let mut quorum = UntrustedQuorum::new();
    quorum.main_document(main_document);
    for (idx, shard_path) in shard_paths.enumerate() {
        let encrypted_shard = EncryptedKeyShard::from_wire_multibase(
            read_oneline_file(&format!("Shard {} Data", idx + 1), shard_path)
                .with_context(|| format!("read shard {}", idx + 1))?,
        )
        .map_err(|err| anyhow!(err)) // TODO: Fix this once FromWire supports non-String errors.
        .with_context(|| format!("decode shard {}", idx + 1))?;

        print!("Shard {} Codeword: ", idx + 1);
        io::stdout().flush()?;
        let mut codeword_input = String::new();
        io::stdin().read_line(&mut codeword_input)?;

        let codewords = codeword_input
            .split_whitespace()
            .map(|s| s.to_owned())
            .collect::<Vec<_>>();

        let shard = encrypted_shard
            .decrypt(&codewords)
            .map_err(|err| anyhow!(err)) // TODO: Fix this once FromWire supports non-String errors.
            .with_context(|| format!("decrypting shard {}", idx + 1))?;
        quorum.push_shard(shard);
    }

    let quorum = match quorum.validate() {
        Ok(validated_quorum) => validated_quorum,
        Err(err) => {
            // TODO: Make this error much cleaner.
            return Err(anyhow!(
                "quorum failed to validate -- possible forgery! groupings: {:?}",
                err.as_groups()
            ));
        }
    };

    let secret = quorum
        .recover_document()
        .context("recovering secret data")?;

    let mut output_file: Box<dyn Write + 'static> =
        if output_path == "-" {
            Box::new(io::stdout())
        } else {
            Box::new(File::create(output_path).with_context(|| {
                format!("failed to open output file '{}' for writing", output_path)
            })?)
        };

    output_file
        .write_all(&secret)
        .context("write secret data to file")?;

    Ok(())
}

fn raw_expand(matches: &ArgMatches<'_>) -> Result<(), Error> {
    use paperback::{EncryptedKeyShard, FromWire, ToWire, UntrustedQuorum};

    let shard_paths = matches
        .values_of("shards")
        .expect("required --shard arguments not given");
    let num_new_shards: u32 = matches
        .value_of("new_shards")
        .expect("required --new-shards argument not given")
        .parse()
        .context("--shards argument was not an unsigned integer")?;

    let mut quorum = UntrustedQuorum::new();
    for (idx, shard_path) in shard_paths.enumerate() {
        let encrypted_shard = EncryptedKeyShard::from_wire_multibase(
            read_oneline_file(&format!("Shard {} Data", idx + 1), shard_path)
                .with_context(|| format!("read shard {}", idx + 1))?,
        )
        .map_err(|err| anyhow!(err)) // TODO: Fix this once FromWire supports non-String errors.
        .with_context(|| format!("decode shard {}", idx + 1))?;

        print!("Shard {} Codeword: ", idx + 1);
        io::stdout().flush()?;
        let mut codeword_input = String::new();
        io::stdin().read_line(&mut codeword_input)?;

        let codewords = codeword_input
            .split_whitespace()
            .map(|s| s.to_owned())
            .collect::<Vec<_>>();

        let shard = encrypted_shard
            .decrypt(&codewords)
            .map_err(|err| anyhow!(err)) // TODO: Fix this once FromWire supports non-String errors.
            .with_context(|| format!("decrypting shard {}", idx + 1))?;
        quorum.push_shard(shard);
    }

    let quorum = match quorum.validate() {
        Ok(validated_quorum) => validated_quorum,
        Err(err) => {
            // TODO: Make this error much cleaner.
            return Err(anyhow!(
                "quorum failed to validate -- possible forgery! groupings: {:?}",
                err.as_groups()
            ));
        }
    };

    let new_shards = quorum
        .extend_shards(num_new_shards)
        .context("minting new shards")?
        .iter()
        .map(|s| s.encrypt().unwrap())
        .collect::<Vec<_>>();

    for (i, (shard, keyword)) in new_shards.iter().enumerate() {
        let decrypted_shard = shard.clone().decrypt(keyword).unwrap();
        println!("----- BEGIN SHARD {} OF {} -----", i + 1, num_new_shards);
        println!("Document-ID: {}", decrypted_shard.document_id());
        println!("Shard-ID: {}", decrypted_shard.id());
        println!("Keywords: {}", keyword.join(" "));
        println!("\n{}", shard.to_wire_multibase(ENCODING_BASE));
        println!("----- END SHARD {} OF {} -----", i, num_new_shards);
    }

    Ok(())
}

fn raw(matches: &ArgMatches<'_>) -> Result<(), Error> {
    match matches.subcommand() {
        ("backup", Some(sub_matches)) => raw_backup(sub_matches),
        ("restore", Some(sub_matches)) => raw_restore(sub_matches),
        ("expand", Some(sub_matches)) => raw_expand(sub_matches),
        (subcommand, _) => Err(anyhow!("unknown subcommand 'raw {}'", subcommand)),
    }
}

fn main() -> Result<(), Box<dyn StdError>> {
    let matches = App::new("paperback-cli")
        .version("0.0.0")
        .author( "Aleksa Sarai <cyphar@cyphar.com>")
        .about("Operate on a paperback backup using a basic CLI interface.")
        .subcommand(SubCommand::with_name("raw")
            .about("Operate using raw text data, rather than on PDF documents. This mode is not recommended for general use, since it might be more complicated for inexperienced users to recover the document.")
            // paperback-cli raw backup [--sealed] --quorum-size <QUORUM SIZE> --shards <SHARDS> INPUT
            .subcommand(SubCommand::with_name("backup")
                .about("Create a new paperback backup.")
                .arg(Arg::with_name("sealed")
                    .long("sealed")
                    .help("Create a sealed backup, which cannot be expanded (have new shards be created) after creation.")
                    .possible_values(&["true", "false"])
                    .default_value("false"))
                .arg(Arg::with_name("quorum_size")
                    .short("q")
                    .long("quorum-size")
                    .value_name("QUORUM SIZE")
                    .help("Number of shards required to recover the document (must not be larger than --shards).")
                    .takes_value(true)
                    .required(true))
                .arg(Arg::with_name("shards")
                    .short("s")
                    .long("shards")
                    .value_name("NUM SHARDS")
                    .help("Number of shards to create (must not be smaller than --quorum-size).")
                    .takes_value(true)
                    .required(true))
                .arg(Arg::with_name("INPUT")
                    .help(r#"Path to secret data to backup ("-" to write to stdout)."#)
                    .allow_hyphen_values(true)
                    .required(true)
                    .index(1)))
            // paperback-cli raw restore --main-document <MAIN DOCUMENT> (--shards <SHARD>)... OUTPUT
            .subcommand(SubCommand::with_name("restore")
                .about("Restore the secret data from a paperback backup.")
                .arg(Arg::with_name("main_document")
                    .short("M")
                    .long("main-document")
                    .value_name("MAIN DOCUMENT PATH")
                    .help(r#"Path to paperback main document ("-" to read from stdin)."#)
                    .takes_value(true)
                    .required(true))
                .arg(Arg::with_name("shards")
                    .short("s")
                    .long("shard")
                    .value_name("SHARD PATH")
                    .help(r#"Path to each paperback shard ("-" to read from stdin)."#)
                    .takes_value(true)
                    .multiple(true)
                    .number_of_values(1)
                    .required(true))
                .arg(Arg::with_name("OUTPUT")
                    .help(r#"Path to write recovered secret data to ("-" to write to stdout)."#)
                    .allow_hyphen_values(true)
                    .required(true)
                    .index(1)))
            // paperback-cli raw expand --new-shards <N> (--shards <SHARD>)...
            .subcommand(SubCommand::with_name("expand")
                .about("Restore the secret data from a paperback backup.")
                .arg(Arg::with_name("new_shards")
                    .short("n")
                    .long("new-shards")
                    .value_name("NUM SHARDS")
                    .help(r#"Number of new shards to create."#)
                    .takes_value(true)
                    .required(true))
                .arg(Arg::with_name("shards")
                    .short("s")
                    .long("shard")
                    .value_name("SHARDS")
                    .help(r#"Path to each paperback shard ("-" to read from stdin)."#)
                    .takes_value(true)
                    .multiple(true)
                    .number_of_values(1)
                    .required(true)))
            )
            .get_matches();

    let ret = match matches.subcommand() {
        ("raw", Some(sub_matches)) => raw(sub_matches),
        (subcommand, _) => Err(anyhow!("unknown subcommand '{}'", subcommand)),
    }?;

    Ok(ret)
}
