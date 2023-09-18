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

use std::{
    fs::File,
    io,
    io::{prelude::*, BufReader},
};

use anyhow::{anyhow, Context, Error};
use clap::{Arg, ArgAction, ArgMatches, Command};

extern crate paperback_core;
use paperback_core::latest as paperback;

const ENCODING_BASE: multibase::Base = multibase::Base::Base32Z;

// paperback-cli raw backup [--sealed] --quorum-size <QUORUM SIZE> --shards <SHARDS> INPUT
fn raw_backup_cli() -> Command {
    Command::new("backup")
                .about("Create a new paperback backup.")
                .arg(Arg::new("sealed")
                    .long("sealed")
                    .help("Create a sealed backup, which cannot be expanded (have new shards be created) after creation.")
                    .action(ArgAction::SetTrue))
                .arg(Arg::new("quorum-size")
                    .short('n')
                    .long("quorum-size")
                    .value_name("QUORUM SIZE")
                    .help("Number of shards required to recover the document (must not be larger than --shards).")
                    .action(ArgAction::Set)
                    .required(true))
                .arg(Arg::new("shards")
                    .short('k')
                    .long("shards")
                    .value_name("NUM SHARDS")
                    .help("Number of shards to create (must not be smaller than --quorum-size).")
                    .action(ArgAction::Set)
                    .required(true))
                .arg(Arg::new("INPUT")
                    .help(r#"Path to file containing secret data to backup ("-" to read from stdin)."#)
                    .action(ArgAction::Set)
                    .allow_hyphen_values(true)
                    .required(true)
                    .index(1))
}

fn raw_backup(matches: &ArgMatches) -> Result<(), Error> {
    use paperback::{Backup, ToWire};

    let sealed = matches.get_flag("sealed");
    let quorum_size: u32 = matches
        .get_one::<String>("quorum-size")
        .context("required --quorum-size argument not provided")?
        .parse()
        .context("--quorum-size argument was not an unsigned integer")?;
    let num_shards: u32 = matches
        .get_one::<String>("shards")
        .context("required --quorum-size argument not provided")?
        .parse()
        .context("--shards argument was not an unsigned integer")?;
    let input_path = matches
        .get_one::<String>("INPUT")
        .context("required INPUT argument not provided")?;

    if num_shards < quorum_size {
        return Err(anyhow!("invalid arguments: number of shards cannot be smaller than quorum size (such a backup is unrecoverable)"));
    }

    let (mut stdin_reader, mut file_reader);
    let input: &mut dyn Read = if input_path == "-" {
        stdin_reader = io::stdin();
        &mut stdin_reader
    } else {
        file_reader = File::open(&input_path)
            .with_context(|| format!("failed to open secret data file '{}'", input_path))?;
        &mut file_reader
    };
    let mut buffer_input = BufReader::new(input);

    let mut secret = Vec::new();
    buffer_input
        .read_to_end(&mut secret)
        .with_context(|| format!("failed to read secret data from '{}'", input_path))?;

    let backup = if sealed {
        Backup::new_sealed(quorum_size, &secret)
    } else {
        Backup::new(quorum_size, &secret)
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
        println!("----- BEGIN SHARD {} OF {} -----", i + 1, quorum_size);
        println!("Document-ID: {}", decrypted_shard.document_id());
        println!("Shard-ID: {}", decrypted_shard.id());
        println!("Checksum: {}", shard.checksum_string());
        println!("Keywords: {}", keyword.join(" "));
        println!("\n{}", shard.to_wire_multibase(ENCODING_BASE));
        println!("----- END SHARD {} OF {} -----", i + 1, quorum_size);
    }

    Ok(())
}

fn read_oneline_file(prompt: &str, path_or_stdin: &str) -> Result<String, Error> {
    let (mut stdin_reader, mut file_reader);
    let input: &mut dyn Read = if path_or_stdin == "-" {
        print!("{}: ", prompt);
        io::stdout().flush()?;
        stdin_reader = io::stdin();
        &mut stdin_reader
    } else {
        file_reader = File::open(&path_or_stdin)
            .with_context(|| format!("failed to open file '{}'", path_or_stdin))?;
        &mut file_reader
    };
    let buffer_input = BufReader::new(input);
    Ok(buffer_input
        .lines()
        .next()
        .ok_or_else(|| anyhow!("no lines read"))??)
}

// paperback-cli raw restore --main-document <MAIN DOCUMENT> (--shards <SHARD>)... OUTPUT
fn raw_restore_cli() -> Command {
    Command::new("restore")
        .about("Restore the secret data from a paperback backup.")
        .arg(
            Arg::new("main_document")
                .short('M')
                .long("main-document")
                .value_name("MAIN DOCUMENT PATH")
                .help(r#"Path to paperback main document ("-" to read from stdin)."#)
                .action(ArgAction::Set)
                .allow_hyphen_values(true)
                .required(true),
        )
        .arg(
            Arg::new("shards")
                .short('s')
                .long("shard")
                .value_name("SHARD PATH")
                .help(r#"Path to each paperback shard ("-" to read from stdin)."#)
                .action(ArgAction::Append)
                .allow_hyphen_values(true)
                .required(true),
        )
        .arg(
            Arg::new("OUTPUT")
                .help(r#"Path to write recovered secret data to ("-" to write to stdout)."#)
                .action(ArgAction::Set)
                .allow_hyphen_values(true)
                .required(true)
                .index(1),
        )
}

fn raw_restore(matches: &ArgMatches) -> Result<(), Error> {
    use paperback::{EncryptedKeyShard, FromWire, MainDocument, UntrustedQuorum};

    let main_document_path = matches
        .get_one::<String>("main_document")
        .context("required --main-document argument not provided")?;
    let shard_paths = matches
        .get_many::<String>("shards")
        .context("required --shard argument not provided")?;
    let output_path = matches
        .get_one::<String>("OUTPUT")
        .context("required OUTPUT argument not provided")?;

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

        println!("Shard Checksum: {}", encrypted_shard.checksum_string());
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

    let quorum = quorum.validate().map_err(|err| {
        anyhow!(
            "quorum failed to validate -- possible forgery! groupings: {:?}",
            err.as_groups()
        )
    })?;

    let secret = quorum
        .recover_document()
        .context("recovering secret data")?;

    let (mut stdout_writer, mut file_writer);
    let output_file: &mut dyn Write = if output_path == "-" {
        stdout_writer = io::stdout();
        &mut stdout_writer
    } else {
        file_writer = File::create(output_path)
            .with_context(|| format!("failed to open output file '{}' for writing", output_path))?;
        &mut file_writer
    };

    output_file
        .write_all(&secret)
        .context("write secret data to file")?;

    Ok(())
}

// paperback-cli raw expand --new-shards <N> (--shards <SHARD>)...
fn raw_expand_cli() -> Command {
    Command::new("expand")
        .about("Restore the secret data from a paperback backup.")
        .arg(
            Arg::new("new-shards")
                .short('n')
                .long("new-shards")
                .value_name("NUM SHARDS")
                .help(r#"Number of new shards to create."#)
                .action(ArgAction::Set)
                .required(true),
        )
        .arg(
            Arg::new("shards")
                .short('s')
                .long("shard")
                .value_name("SHARDS")
                .help(r#"Path to each paperback shard ("-" to read from stdin)."#)
                .action(ArgAction::Append)
                .allow_hyphen_values(true)
                .required(true),
        )
}

fn raw_expand(matches: &ArgMatches) -> Result<(), Error> {
    use paperback::{EncryptedKeyShard, FromWire, NewShardKind, ToWire, UntrustedQuorum};

    let shard_paths = matches
        .get_many::<String>("shards")
        .context("required --shard argument not provided")?;
    let num_new_shards: u32 = matches
        .get_one::<String>("new-shards")
        .context("required --new-shards argument not provided")?
        .parse()
        .context("--new-shards argument was not an unsigned integer")?;

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

    let quorum = quorum.validate().map_err(|err| {
        anyhow!(
            "quorum failed to validate -- possible forgery! groupings: {:?}",
            err.as_groups()
        )
    })?;

    let new_shards = (0..num_new_shards)
        .map(|_| {
            Ok(quorum
                .new_shard(NewShardKind::NewShard)
                .context("minting new shards")?
                .encrypt()
                .expect("encrypt new shard"))
        })
        .collect::<Result<Vec<_>, Error>>()?;

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

pub(crate) fn submatch(app: &mut Command, matches: &ArgMatches) -> Result<(), Error> {
    match matches.subcommand() {
        Some(("backup", sub_matches)) => raw_backup(sub_matches),
        Some(("restore", sub_matches)) => raw_restore(sub_matches),
        Some(("expand", sub_matches)) => raw_expand(sub_matches),
        Some((subcommand, _)) => {
            // We should never end up here.
            app.print_help()?;
            Err(anyhow!("unknown subcommand 'raw {}'", subcommand))
        }
        None => {
            app.print_help()?;
            Err(anyhow!("no 'raw' subcommand specified"))
        }
    }
}

pub(crate) fn subcommands() -> Command {
    Command::new("raw")
            .about("Operate using raw text data, rather than on PDF documents. This mode is not recommended for general use, since it might be more complicated for inexperienced users to recover the document.")
            // paperback-cli raw backup [--sealed] --quorum-size <QUORUM SIZE> --shards <SHARDS> INPUT
            .subcommand(raw_backup_cli())
            // paperback-cli raw restore --main-document <MAIN DOCUMENT> (--shards <SHARD>)... OUTPUT
            .subcommand(raw_restore_cli())
            // paperback-cli raw expand --new-shards <N> (--shards <SHARD>)...
            .subcommand(raw_expand_cli())
}
