//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::path::PathBuf;

use const_format::formatcp;
use structopt::clap::crate_version;
use structopt::StructOpt;

use crate::value::{HashAlgorithm, Style};

const COPYRIGHT: &str = "Copyright (C) 2021 Shun Sakai";
const LICENSE: &str = "License: GNU General Public License v3.0 or later";
const REPORTING_BUGS: &str = "Reporting bugs: https://github.com/sorairolake/rshash/issues";
const LONG_VERSION: &str = formatcp!(
    "{}\n\n{}\n{}\n{}",
    crate_version!(),
    COPYRIGHT,
    LICENSE,
    REPORTING_BUGS
);

#[derive(Debug, StructOpt)]
#[structopt(name = "RSHash", long_version = LONG_VERSION, about)]
pub struct Opt {
    /// Specify hash algorithm.
    #[structopt(short = "H", long, value_name = "NAME", possible_values = &["BLAKE2b", "BLAKE2s", "SHA256", "SHA512", "SHA3-256", "SHA3-512"], case_insensitive = true)]
    pub hash_algorithm: Option<HashAlgorithm>,

    /// List supported hash algorithms.
    #[structopt(long)]
    pub list_hash_algorithms: bool,

    /// Read the checksums from the file and check them.
    #[structopt(short, long, requires = "input")]
    pub check: bool,

    /// Don't print OK for each successfully verified file.
    #[structopt(long, requires = "check", conflicts_with = "status")]
    pub quiet: bool,

    /// Don't output anything, return the verification result as the exit status.
    #[structopt(long, requires = "check", conflicts_with = "quiet")]
    pub status: bool,

    /// Output to <FILE> instead of stdout.
    #[structopt(short, long, value_name = "FILE", parse(from_os_str))]
    pub output: Option<PathBuf>,

    /// Specify style of the checksums.
    #[structopt(long, value_name = "STYLE", possible_values = &["SFV", "BSD"], case_insensitive = true, default_value)]
    pub style: Style,

    /// Input from <FILE>.
    #[structopt(value_name = "FILE", parse(from_os_str))]
    pub input: Vec<PathBuf>,
}

impl Opt {
    /// Guess the hash algorithm from BSD-style checksums.
    pub fn guess_hash_algorithm(mut self, checksums: &str) -> Self {
        if !self.check {
            return self;
        }
        if self.hash_algorithm.is_some() {
            return self;
        }

        let algo = checksums.split_whitespace().next();
        if let Some(v) = algo {
            self.hash_algorithm = match v {
                "BLAKE2b" => Some(HashAlgorithm::Blake2b),
                "BLAKE2s" => Some(HashAlgorithm::Blake2s),
                "SHA256" => Some(HashAlgorithm::Sha256),
                "SHA512" => Some(HashAlgorithm::Sha512),
                "SHA3-256" => Some(HashAlgorithm::Sha3_256),
                "SHA3-512" => Some(HashAlgorithm::Sha3_512),
                _ => self.hash_algorithm,
            };
        }

        self
    }
}
