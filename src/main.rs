//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

mod cli;
mod compute;
mod config;
mod output;
mod value;
mod verify;

use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::str;

use anyhow::{bail, Context, Result};
use indexmap::IndexMap;
use structopt::StructOpt;

use crate::cli::Opt;
use crate::value::{Checksum, HashAlgorithm};
use crate::verify::Verify;

fn main() -> Result<()> {
    let opt = Opt::from_args().apply_config()?;

    if let Some(s) = opt.generate_completion {
        Opt::generate_completion(s);

        return Ok(());
    }

    if opt.list_hash_algorithms {
        println!("{}", HashAlgorithm::Blake2b);
        println!("{}", HashAlgorithm::Blake2s);
        println!("{}", HashAlgorithm::Blake3);
        println!("{}", HashAlgorithm::Gost);
        println!("{}", HashAlgorithm::GostCryptoPro);
        println!("{}", HashAlgorithm::Groestl224);
        println!("{}", HashAlgorithm::Groestl256);
        println!("{}", HashAlgorithm::Groestl384);
        println!("{}", HashAlgorithm::Groestl512);
        println!("{}", HashAlgorithm::Keccak224);
        println!("{}", HashAlgorithm::Keccak256);
        println!("{}", HashAlgorithm::Keccak384);
        println!("{}", HashAlgorithm::Keccak512);
        println!("{}", HashAlgorithm::Md2);
        println!("{}", HashAlgorithm::Md4);
        println!("{}", HashAlgorithm::Md5);
        println!("{}", HashAlgorithm::Ripemd160);
        println!("{}", HashAlgorithm::Ripemd320);
        println!("{}", HashAlgorithm::Sha1);
        println!("{}", HashAlgorithm::Sha224);
        println!("{}", HashAlgorithm::Sha256);
        println!("{}", HashAlgorithm::Sha384);
        println!("{}", HashAlgorithm::Sha512);
        println!("{}", HashAlgorithm::Sha3_224);
        println!("{}", HashAlgorithm::Sha3_256);
        println!("{}", HashAlgorithm::Sha3_384);
        println!("{}", HashAlgorithm::Sha3_512);
        println!("{}", HashAlgorithm::Shabal192);
        println!("{}", HashAlgorithm::Shabal224);
        println!("{}", HashAlgorithm::Shabal256);
        println!("{}", HashAlgorithm::Shabal384);
        println!("{}", HashAlgorithm::Shabal512);
        println!("{}", HashAlgorithm::Streebog256);
        println!("{}", HashAlgorithm::Streebog512);
        println!("{}", HashAlgorithm::Tiger);
        println!("{}", HashAlgorithm::Whirlpool);

        return Ok(());
    }

    let (files, dirs): (Vec<_>, Vec<_>) = opt.input.iter().cloned().partition(|i| i.is_file());

    let inputs = if files.is_empty() {
        if atty::is(atty::Stream::Stdin) {
            bail!("Input from tty is invalid");
        }

        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .context("Failed to read bytes from stdin")?;

        let mut input = IndexMap::new();
        input.insert(Path::new("-").to_path_buf(), buf);

        input
    } else {
        let data: Result<Vec<_>> = files
            .iter()
            .map(|f| {
                fs::read(f).with_context(|| format!("Failed to read bytes from {}", f.display()))
            })
            .collect();
        let data = data?;

        files.into_iter().zip(data.into_iter()).collect()
    };

    if opt.check {
        for input in inputs {
            let data = input.1;
            let checksums =
                str::from_utf8(&data).context("Failed to convert from bytes to a string")?;

            let algo = opt
                .guess_hash_algorithm(checksums)
                .context("Unable to determine hash algorithm")?;

            let checksums: Result<Vec<_>> = checksums
                .lines()
                .map(|c| c.parse().context("Failed to parse a checksum"))
                .collect();
            let checksums = checksums?;

            let result: Result<Vec<_>> = checksums
                .iter()
                .map(|c| Verify::verify(&algo, c).context("Failed to verify a checksum"))
                .collect();
            let result = result?;

            if opt.status {
                if result.iter().all(|r| r.result.unwrap_or_default()) {
                    continue;
                } else {
                    std::process::exit(1);
                }
            }

            if opt.quiet {
                result
                    .iter()
                    .map(|r| r.output())
                    .filter(|o| !o.ends_with("OK"))
                    .for_each(|o| println!("{}", o));
            } else {
                result
                    .iter()
                    .map(|r| r.output())
                    .for_each(|o| println!("{}", o));
            }
        }
    } else {
        let algo = opt
            .hash_algorithm
            .context("Unable to determine hash algorithm")?;

        let output: Vec<_> = inputs
            .iter()
            .map(|(p, d)| (p.as_path(), d.as_slice()))
            .map(|i| Checksum::compute(&algo, i))
            .map(|c| c.output(&algo, &opt.style))
            .collect();
        match opt.output {
            Some(ref f) => fs::write(f, output.join("\n"))
                .with_context(|| format!("Failed to write to {}", f.display()))?,
            None => output.iter().for_each(|o| println!("{}", o)),
        }
    }

    if !dirs.is_empty() {
        dirs.iter()
            .for_each(|d| eprintln!("RSHash: {}: Is a directory", d.as_path().display()));
    }

    Ok(())
}
