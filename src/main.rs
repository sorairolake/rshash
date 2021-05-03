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
use std::path::{Path, PathBuf};
use std::str;

use anyhow::{bail, Context, Result};
use indexmap::IndexMap;
use structopt::StructOpt;

use crate::cli::Opt;
use crate::value::{Checksum, HashAlgorithm, Style};
use crate::verify::Verify;

fn main() -> Result<()> {
    let opt = Opt::from_args();

    if opt.list_hash_algorithms {
        println!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            HashAlgorithm::Blake2b,
            HashAlgorithm::Blake2s,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha3_256,
            HashAlgorithm::Sha3_512
        );

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

        let inputs: IndexMap<_, _> = files.into_iter().zip(data.into_iter()).collect();

        inputs
    };

    let opt = if opt.check {
        let first_file = input.first().context("Failed to read a file.")?;
        let first_file_data = first_file.1;
        let checksums = str::from_utf8(first_file_data)?;

        opt.guess_hash_algorithm(checksums)
    } else {
        opt
    };

    let algo = match opt.hash_algorithm {
        Some(v) => v,
        None => bail!("Unable to determine hash algorithm."),
    };

    let output = if opt.check {
        let first_file = input.first().context("Failed to read a file.")?;
        let first_file_data = first_file.1;
        let checksums = str::from_utf8(first_file_data)?;

        let checksums: Vec<_> = match opt.style {
            Style::Sfv => {
                let paths: Result<Vec<_>> = checksums
                    .lines()
                    .map(|c| {
                        c.splitn(2, "  ")
                            .nth(1)
                            .context("Invalid format of checksum lines.")
                    })
                    .collect();
                let paths = paths?;
                let paths: Vec<PathBuf> = paths.into_iter().map(|p| p.into()).collect();
                let digests: Result<Vec<_>> = checksums
                    .lines()
                    .map(|c| {
                        c.split_whitespace()
                            .next()
                            .context("Invalid format of checksum lines.")
                    })
                    .collect();
                let digests = digests?;
                let checksums: Vec<_> = paths.into_iter().zip(digests.into_iter()).collect();
                let checksums: Vec<_> = checksums
                    .into_iter()
                    .map(|(p, d)| Checksum::new(&algo, (p.as_path(), d)))
                    .collect();

                checksums
            }
            Style::Bsd => {
                let paths: Result<Vec<_>> = checksums
                    .lines()
                    .map(|c| {
                        c.splitn(2, " (")
                            .nth(1)
                            .context("Invalid format of checksum lines.")
                    })
                    .collect();
                let paths = paths?;
                let paths: Result<Vec<_>> = paths
                    .into_iter()
                    .map(|c| {
                        c.rsplitn(2, ") = ")
                            .nth(1)
                            .context("Invalid format of checksum lines.")
                    })
                    .collect();
                let paths = paths?;
                let paths: Vec<PathBuf> = paths.into_iter().map(|p| p.into()).collect();
                let digests: Result<Vec<_>> = checksums
                    .lines()
                    .map(|c| {
                        c.rsplit(' ')
                            .next()
                            .context("Invalid format of checksum lines.")
                    })
                    .collect();
                let digests = digests?;
                let checksums: Vec<_> = paths.into_iter().zip(digests.into_iter()).collect();
                let checksums: Vec<_> = checksums
                    .into_iter()
                    .map(|(p, d)| Checksum::new(&algo, (p.as_path(), d)))
                    .collect();

                checksums
            }
        };

        let result: Result<Vec<_>> = checksums.iter().map(|c| Verify::verify(c)).collect();
        let result = result?;

        if opt.status {
            let ok_all = result
                .iter()
                .map(|r| r.result)
                .filter(|r| r.is_some())
                .map(|r| r.unwrap())
                .all(|r| r);
            if ok_all {
                return Ok(());
            } else {
                std::process::exit(1);
            }
        }

        let output = if opt.quiet {
            let output: Vec<_> = result.iter().map(|r| r.output()).collect();
            let output: Vec<_> = output.into_iter().filter(|o| !o.ends_with("OK")).collect();

            output
        } else {
            let output: Vec<_> = result.iter().map(|r| r.output()).collect();

            output
        };

        output
    } else {
        let checksums: Vec<_> = input
            .iter()
            .map(|(p, d)| (p.as_path(), d.as_slice()))
            .map(|i| Checksum::compute(&algo, i))
            .map(|c| c.output(&opt.style))
            .collect();

        checksums
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
