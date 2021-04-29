//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

mod cli;
mod compute;
mod output;
mod value;

use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::str;

use anyhow::{bail, Result};
use indexmap::IndexMap;
use structopt::StructOpt;

use crate::cli::Opt;
use crate::value::{Checksum, HashAlgorithm};

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

        let inputs: IndexMap<_, _> = opt
            .input
            .iter()
            .zip(data.iter())
            .map(|(p, b)| (p.clone(), b.clone()))
            .collect();

        inputs
    };

    let opt = if opt.check {
        let first_line = str::from_utf8(&input[0])?;

        opt.guess_hash_algorithm(first_line)
    } else {
        opt
    };

    let algo = match opt.hash_algorithm {
        Some(v) => v,
        None => bail!("Unable to determine hash algorithm."),
    };

    let output = if opt.check {
        todo!();
    } else {
        let checksums: Vec<_> = input
            .iter()
            .map(|(p, c)| (p.as_path(), c.as_slice()))
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
