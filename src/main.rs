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
use std::convert::{TryFrom, TryInto};
use std::fs;
use std::io::{self, Read};
use std::str;
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
use dialoguer::theme::ColorfulTheme;
use indicatif::{BinaryBytes, ParallelProgressIterator, ProgressBar, ProgressStyle};
use maplit::btreemap;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use structopt::StructOpt;
use strum::VariantNames;

use crate::cli::Opt;
use crate::value::{Checksum, HashAlgorithm, Style};
use crate::verify::{Verify, VERIFICATION_RESULT_WIDTH};

const PROGRESS_BAR_TEMPLATE: &str =
    "{spinner:.green} [{elapsed_precise}] {percent}% {wide_bar:.cyan/blue} {pos}/{len} ETA {eta}";

fn main() -> Result<()> {
    let opt = Opt::from_args().apply_config()?;

    rayon::ThreadPoolBuilder::new()
        .num_threads(opt.threads)
        .build_global()
        .expect("Failed to initialize the global thread pool");

    if let Some(shell) = opt.generate_completion {
        if let Some(out_dir) = opt.output {
            Opt::generate_completion_to_file(shell, out_dir)?;
        } else {
            Opt::generate_completion_to_stdout(shell);
        }

        return Ok(());
    }

    if opt.list_hash_algorithms {
        HashAlgorithm::VARIANTS
            .iter()
            .for_each(|h| println!("{}", h));

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

    let start = Instant::now();
    let mut total_length = u64::default();

    if opt.check {
        let mut results = BTreeMap::new();
        let mut is_improper = bool::default();

        for (i, (path, data)) in inputs.iter().enumerate() {
            let start = Instant::now();

            let str = str::from_utf8(data).context("Failed to convert from bytes to a string")?;

            let mut impropers = Vec::new();
            let checksums: Vec<_> = if let Ok(checksums) = serde_json::from_str(str) {
                checksums
            } else {
                for (i, line) in str.lines().enumerate() {
                    if let Err(error) = line.parse::<Checksum>() {
                        impropers.push((i, error));
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

            let pb = ProgressBar::new(
                checksums
                    .len()
                    .try_into()
                    .expect("Number of files exceeds the limit"),
            )
            .with_style(ProgressStyle::default_bar().template(PROGRESS_BAR_TEMPLATE));

            if opt.progress {
                eprintln!(
                    "Verifying {} checksums from {}",
                    checksums.len(),
                    path.display()
                );
            }
            let result = if opt.progress {
                checksums
                    .par_iter()
                    .progress_with(pb)
                    .map(|c| Verify::verify(c).context("Failed to verify a checksum"))
                    .collect::<Result<Vec<_>>>()?
            } else {
                checksums
                    .par_iter()
                    .map(|c| Verify::verify(c).context("Failed to verify a checksum"))
                    .collect::<Result<Vec<_>>>()?
            };

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

            if opt.status {
                if result.into_iter().all(|r| r.success.unwrap_or_default()) {
                    continue;
                } else {
                    std::process::exit(exitcode::SOFTWARE);
                }
            }

            if !opt.json {
                eprintln!("Result of {}", path.display());
                eprintln!("{}", "-".repeat(VERIFICATION_RESULT_WIDTH));
                result
                    .iter()
                    .map(|r| r.output())
                    .for_each(|o| println!("{}", o));
                eprintln!("{}", "-".repeat(VERIFICATION_RESULT_WIDTH));
                if total == success && !opt.quiet {
                    eprintln!("Everything is successful");
                } else if opt.ignore_missing {
                    eprintln!(
                        "{} validations failed (Success:{}; Failure:{})",
                        total - success,
                        success,
                        failure
                    );
                } else {
                    eprintln!(
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
            }

            if opt.speed {
                let duration: u64 = start
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .expect("Time interval is too long");
                let length: u64 = result
                    .into_iter()
                    .flat_map(|r| fs::metadata(r.file.as_path()))
                    .map(|f| f.len())
                    .sum();

                if let Some(speed) = length
                    .checked_div(duration)
                    .and_then(|s| s.checked_mul(1_000))
                {
                    eprintln!(
                        "Computed {} in {} ({}/s)",
                        BinaryBytes(length),
                        humantime::format_duration(Duration::from_millis(duration)),
                        BinaryBytes(speed)
                    );
                } else {
                    eprintln!(
                        "Computed {} in {}",
                        BinaryBytes(length),
                        humantime::format_duration(Duration::from_millis(duration))
                    );
                }

                total_length += length;
            }

            if !opt.json && i < inputs.len() - 1 {
                eprintln!();
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

        let pb = ProgressBar::new(
            inputs
                .len()
                .try_into()
                .expect("Number of files exceeds the limit"),
        )
        .with_style(ProgressStyle::default_bar().template(PROGRESS_BAR_TEMPLATE));

        if opt.progress {
            eprintln!("Computing {} files", inputs.len());
        }
        let checksums: Vec<_> = if opt.progress {
            inputs
                .par_iter()
                .progress_with(pb)
                .map(|i| Checksum::digest(algo, i))
                .collect()
        } else {
            inputs
                .par_iter()
                .map(|i| Checksum::digest(algo, i))
                .collect()
        };
        if opt.progress {
            eprintln!("Done.");
        }

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
            Some(ref file) => fs::write(file, format!("{}\n", output))
                .with_context(|| format!("Failed to write to {}", file.display()))?,
            None => println!("{}", output),
        }
    }
    let total_length = total_length;

    if !dirs.is_empty() {
        dirs.into_iter()
            .for_each(|d| eprintln!("RSHash: {}: Is a directory", d.display()));

        std::process::exit(exitcode::NOINPUT);
    }

    if opt.speed {
        let duration: u64 = start
            .elapsed()
            .as_millis()
            .try_into()
            .expect("Time interval is too long");

        if opt.check {
            if let Some(speed) = total_length
                .checked_div(duration)
                .and_then(|s| s.checked_mul(1_000))
            {
                eprintln!(
                    "Total {} in {} ({}/s)",
                    BinaryBytes(total_length),
                    humantime::format_duration(Duration::from_millis(duration)),
                    BinaryBytes(speed)
                );
            } else {
                eprintln!(
                    "Total {} in {}",
                    BinaryBytes(total_length),
                    humantime::format_duration(Duration::from_millis(duration))
                );
            }
        } else {
            let length: u64 = inputs
                .into_iter()
                .map(|i| i.1)
                .map(|d| u64::try_from(d.len()).expect("File size exceeds the limit"))
                .sum();

            if let Some(speed) = length
                .checked_div(duration)
                .and_then(|s| s.checked_mul(1_000))
            {
                eprintln!(
                    "Computed {} in {} ({}/s)",
                    BinaryBytes(length),
                    humantime::format_duration(Duration::from_millis(duration)),
                    BinaryBytes(speed)
                );
            } else {
                eprintln!(
                    "Computed {} in {}",
                    BinaryBytes(length),
                    humantime::format_duration(Duration::from_millis(duration))
                );
            }
        }
    }

    Ok(())
}
