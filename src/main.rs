//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

mod cli;
mod config;
mod digest;
mod macros;
mod output;
mod value;
mod verify;

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::str;

use anyhow::{ensure, Context, Result};
use dialoguer::theme::ColorfulTheme;
use maplit::btreemap;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use structopt::StructOpt;

use crate::cli::Opt;
use crate::value::{Checksum, HashAlgorithm, Style};
use crate::verify::{Verify, VERIFICATION_RESULT_WIDTH};

fn main() -> Result<()> {
    let opt = Opt::from_args().apply_config()?;

    if let Some(shell) = opt.generate_completion {
        if let Some(outdir) = opt.output {
            Opt::generate_completion_to_file(shell, outdir)?;
        } else {
            Opt::generate_completion_to_stdout(shell);
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
        ensure!(
            opt.hash_algorithm.is_some(),
            "Unable to determine hash algorithm"
        );

        let input = if atty::is(atty::Stream::Stdin) {
            dialoguer::Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("Input")
                .interact()
                .context("Failed to read a string from stdin")?
                .into_bytes()
        } else {
            let mut buf = Vec::new();
            io::stdin()
                .read_to_end(&mut buf)
                .context("Failed to read bytes from stdin")?;
            buf
        };

        btreemap!("-".into() => input)
    } else {
        let data: Result<Vec<_>> = files
            .iter()
            .map(|f| {
                fs::read(f).with_context(|| format!("Failed to read bytes from {}", f.display()))
            })
            .collect();

        files.into_iter().zip(data?.into_iter()).collect()
    };

    if opt.check {
        let mut results = BTreeMap::new();
        let mut is_improper = bool::default();

        for (i, (path, data)) in inputs.iter().enumerate() {
            let str = str::from_utf8(data).context("Failed to convert from bytes to a string")?;

            let mut impropers = Vec::new();
            let checksums: Vec<_> = if let Ok(checksums) = serde_json::from_str(str) {
                checksums
            } else {
                for (i, line) in str.lines().enumerate() {
                    if let Err(e) = line.parse::<Checksum>() {
                        impropers.push((i, e));
                    }
                }
                str.lines().flat_map(|c| c.parse::<Checksum>()).collect()
            };
            let impropers = impropers;

            let checksums: Vec<_> = checksums
                .into_iter()
                .map(|c| Checksum {
                    algorithm: opt.hash_algorithm.or(c.algorithm),
                    file: c.file,
                    digest: c.digest,
                })
                .collect();
            ensure!(
                checksums.iter().all(|c| c.algorithm.is_some()),
                "Unable to determine hash algorithm"
            );

            let result = checksums
                .par_iter()
                .map(|c| Verify::verify(c).context("Failed to verify a checksum"))
                .collect::<Result<Vec<_>>>()?;

            let result: Vec<_> = if opt.ignore_missing {
                result.into_iter().filter(|r| r.success.is_some()).collect()
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
                result.iter().filter(|r| r.success.is_none()).count(),
                result
                    .iter()
                    .filter_map(|r| r.success)
                    .filter(|s| *s)
                    .count(),
                result
                    .iter()
                    .filter_map(|r| r.success)
                    .filter(|s| !s)
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

            println!("Verifying {} checksums from {}", total, path.display());
            println!("{}", "-".repeat(VERIFICATION_RESULT_WIDTH));
            result
                .into_iter()
                .map(|r| r.output())
                .for_each(|o| println!("{}", o));
            println!("{}", "-".repeat(VERIFICATION_RESULT_WIDTH));
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

        let checksums: Vec<_> = inputs
            .into_par_iter()
            .map(|i| Checksum::digest(algo, i))
            .collect();

        let output = if opt.style == Style::Json {
            serde_json::to_string_pretty(&checksums)
                .context("Failed to serialize to a JSON string")?
        } else {
            checksums
                .into_iter()
                .map(|c| c.output(opt.style))
                .collect::<Vec<_>>()
                .join("\n")
        };
        match opt.output {
            Some(ref file) => fs::write(file, output)
                .with_context(|| format!("Failed to write to {}", file.display()))?,
            None => println!("{}", output),
        }
    }

    if !dirs.is_empty() {
        dirs.into_iter()
            .for_each(|d| eprintln!("RSHash: {}: Is a directory", d.display()));

        std::process::exit(exitcode::NOINPUT);
    }

    Ok(())
}
