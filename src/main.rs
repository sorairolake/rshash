//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

mod cli;
mod compute;
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
    let opt = Opt::from_args();

    if opt.generate_completions {
        Opt::generate_completions()?;

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

    let mut files = opt.input.clone();
    files.retain(|i| i.is_file());
    let files = files;
    let mut dirs = opt.input.clone();
    dirs.retain(|i| i.is_dir());
    let dirs = dirs;

    let input = if files.is_empty() {
        if atty::is(atty::Stream::Stdin) {
            bail!("Input from tty is invalid.")
        }

        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;

        let mut input = IndexMap::new();
        input.insert(Path::new("-").to_path_buf(), buf);

        input
    } else {
        let data: Result<Vec<_>, _> = files.iter().map(fs::read).collect();
        let data = data?;

        files.into_iter().zip(data.into_iter()).collect()
    };

    let output: Vec<_> = if opt.check {
        let input = input.first().context("Failed to read a file.")?;
        let data = input.1;
        let checksums = str::from_utf8(data)?;

        let algo = opt
            .guess_hash_algorithm(checksums)
            .context("Unable to determine hash algorithm.")?;

        if value::INSECURE_HASH_ALGORITHMS.contains(&algo) && !opt.allow_insecure_hash_algorithm {
            bail!("{} is not allowed to use.", algo)
        }

        let checksums: Result<Vec<_>> = checksums.lines().map(|c| c.parse()).collect();
        let checksums = checksums?;

        let result: Result<Vec<_>> = checksums.iter().map(|c| Verify::verify(&algo, c)).collect();
        let result = result?;

        if opt.status {
            let is_all_paths_exist = result.iter().all(|r| r.is_path_exist);
            let is_all_results_successful = result.iter().filter_map(|r| r.result).all(|r| r);
            if is_all_paths_exist && is_all_results_successful {
                return Ok(());
            } else {
                std::process::exit(1);
            }
        }

        if opt.quiet {
            let output: Vec<_> = result.iter().map(|r| r.output()).collect();
            output.into_iter().filter(|o| !o.ends_with("OK")).collect()
        } else {
            result.iter().map(|r| r.output()).collect()
        }
    } else {
        let algo = opt
            .hash_algorithm
            .context("Unable to determine hash algorithm.")?;

        if value::INSECURE_HASH_ALGORITHMS.contains(&algo) && !opt.allow_insecure_hash_algorithm {
            bail!("{} is not allowed to use.", algo)
        }

        input
            .iter()
            .map(|(p, d)| (p.as_path(), d.as_slice()))
            .map(|i| Checksum::compute(&algo, i))
            .map(|c| c.output(&algo, &opt.style))
            .collect()
    };

    match opt.output {
        Some(f) => fs::write(f, output.join("\n"))?,
        None => output.iter().for_each(|v| println!("{}", v)),
    }

    if !dirs.is_empty() {
        dirs.iter()
            .map(|d| d.as_path().display())
            .for_each(|d| eprintln!("RSHash: {}: Is a directory.", d));
    }

    Ok(())
}
