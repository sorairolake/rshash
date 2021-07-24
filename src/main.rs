//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

mod cli;
mod config;
mod digest;
mod output;
mod value;
mod verify;

use std::fs;
use std::io::{self, Read};
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
        if let Some(o) = opt.output {
            Opt::generate_completion_to_file(s, o)?;
        } else {
            Opt::generate_completion_to_stdout(s);
        }

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
        println!("{}", HashAlgorithm::Ripemd256);
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
        println!("{}", HashAlgorithm::Sm3);
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
        input.insert("-".into(), buf);

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
        let mut results = IndexMap::with_capacity(inputs.len());
        let mut is_improper = bool::default();

        for (i, (path, data)) in inputs.iter().enumerate() {
            let checksums =
                str::from_utf8(data).context("Failed to convert from bytes to a string")?;

            let algo = opt
                .guess_hash_algorithm(checksums)
                .context("Unable to determine hash algorithm")?;

            let mut impropers = Vec::new();
            for (i, checksum) in checksums.lines().enumerate() {
                if let Err(e) = checksum.parse::<Checksum>() {
                    impropers.push((i, e));
                }
            }
            let impropers = impropers;
            let checksums: Vec<_> = checksums.lines().flat_map(|c| c.parse()).collect();

            let result: Result<Vec<_>> = checksums
                .iter()
                .map(|c| Verify::verify(algo, c).context("Failed to verify a checksum"))
                .collect();
            let result = result?;

            let result: Vec<_> = if opt.ignore_missing {
                result.into_iter().filter(|r| r.exist).collect()
            } else {
                result
            };
            if result.is_empty() {
                eprintln!("RSHash: {}: No file was verified", path.display());
                if i < inputs.len() - 1 {
                    eprintln!();
                }

                continue;
            }

            let result: Vec<_> = if opt.quiet {
                result
                    .into_iter()
                    .filter(|r| !r.success.unwrap_or_default())
                    .collect()
            } else {
                result
            };
            if result.is_empty() {
                continue;
            }

            let (total, missing, success, failure) = (
                result.len(),
                result.iter().filter(|r| !r.exist).count(),
                result
                    .iter()
                    .filter(|r| r.exist)
                    .filter(|r| r.success.unwrap())
                    .count(),
                result
                    .iter()
                    .filter(|r| r.exist)
                    .filter(|r| !r.success.unwrap())
                    .count(),
            );

            results.insert(path, result.clone());

            if opt.strict && !impropers.is_empty() && !is_improper {
                is_improper = true;
            }

            if opt.json {
                continue;
            }

            if opt.status {
                if result.iter().all(|r| r.success.unwrap_or_default()) {
                    continue;
                } else {
                    std::process::exit(exitcode::SOFTWARE);
                }
            }

            let padding: Result<Vec<_>> = result
                .iter()
                .map(|r| {
                    r.file
                        .to_str()
                        .context("Failed to convert from a path to a string")
                })
                .collect();
            let padding = padding?;
            let padding = padding
                .into_iter()
                .map(|p| p.chars().count())
                .max()
                .unwrap()
                * 2;
            println!("Verifying {} checksums from {}", total, path.display());
            println!("{}", "-".repeat(padding * 2));
            result
                .into_iter()
                .map(|r| r.output(padding))
                .for_each(|o| println!("{}", o));
            println!("{}", "-".repeat(padding * 2));
            if total == success && !opt.quiet {
                println!("Everything is successful");
            } else if opt.ignore_missing {
                println!(
                    "{} validations failed (Success:{}; Failure:{})",
                    total - success,
                    success,
                    failure
                );
            } else {
                println!(
                    "{} validations failed (Missing:{}; Success:{}; Failure:{})",
                    total - success,
                    missing,
                    success,
                    failure
                );
            }
            if !impropers.is_empty() {
                if opt.warn {
                    impropers.iter().for_each(|i| {
                        eprintln!("RSHash: {}: {}: {}", path.display(), i.0 + 1, i.1)
                    });
                }

                if impropers.len() == 1 {
                    eprintln!("RSHash: WARNING: 1 line is improperly formatted");
                } else {
                    eprintln!(
                        "RSHash: WARNING: {} lines are improperly formatted",
                        impropers.len()
                    );
                }
            }
            if i < inputs.len() - 1 {
                println!();
            }
        }
        let results = results;
        let is_improper = is_improper;

        if opt.json {
            let json = if opt.pretty {
                serde_json::to_string_pretty(&results)
                    .context("Failed to serialize to a JSON string")?
            } else {
                serde_json::to_string(&results).context("Failed to serialize to a JSON string")?
            };
            println!("{}", json);

            return Ok(());
        }

        if results.values().any(|r| r.is_empty()) {
            std::process::exit(exitcode::NOINPUT);
        }

        if !results
            .values()
            .flatten()
            .all(|r| r.success.unwrap_or_default())
        {
            std::process::exit(exitcode::SOFTWARE);
        }

        if opt.strict && is_improper {
            std::process::exit(exitcode::SOFTWARE);
        }
    } else {
        let algo = opt
            .hash_algorithm
            .context("Unable to determine hash algorithm")?;

        let output: Vec<_> = inputs
            .into_iter()
            .map(|i| Checksum::digest(algo, i))
            .map(|c| c.output(algo, opt.style))
            .collect();
        match opt.output {
            Some(ref f) => fs::write(f, output.join("\n"))
                .with_context(|| format!("Failed to write to {}", f.display()))?,
            None => output.into_iter().for_each(|o| println!("{}", o)),
        }
    }

    if !dirs.is_empty() {
        dirs.into_iter()
            .for_each(|d| eprintln!("RSHash: {}: Is a directory", d.display()));

        std::process::exit(exitcode::NOINPUT);
    }

    Ok(())
}
