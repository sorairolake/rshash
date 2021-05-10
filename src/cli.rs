//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::path::PathBuf;

use const_format::formatcp;
use structopt::clap::{crate_version, AppSettings};
use structopt::StructOpt;

use crate::value::{HashAlgorithm, Style};

const LONG_VERSION: &str = formatcp!(
    "{}\n\n{}\n{}\n{}",
    crate_version!(),
    "Copyright (C) 2021 Shun Sakai",
    "License: GNU General Public License v3.0 or later",
    "Reporting bugs: https://github.com/sorairolake/rshash/issues"
);
const HASH_ALGORITHMS: [&str; 15] = [
    "BLAKE2b",
    "BLAKE2s",
    "BLAKE3",
    "Groestl-224",
    "Groestl-256",
    "Groestl-384",
    "Groestl-512",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
];
const CHECKSUM_STYLES: [&str; 2] = ["SFV", "BSD"];

#[derive(Debug, StructOpt)]
#[structopt(
    name = "RSHash",
    long_version = LONG_VERSION,
    about,
    setting = AppSettings::ColoredHelp
)]
pub struct Opt {
    /// Specify hash algorithm.
    #[structopt(
        short = "H",
        long,
        value_name = "NAME",
        possible_values = &HASH_ALGORITHMS,
        case_insensitive = true
    )]
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
    #[structopt(
        long,
        value_name = "STYLE",
        possible_values = &CHECKSUM_STYLES,
        case_insensitive = true,
        default_value
    )]
    pub style: Style,

    /// Input from <FILE>.
    #[structopt(value_name = "FILE", parse(from_os_str))]
    pub input: Vec<PathBuf>,
}

impl Opt {
    /// Guess the hash algorithm from BSD-style checksums.
    pub fn guess_hash_algorithm(&self, checksums: &str) -> Option<HashAlgorithm> {
        if let Some(a) = self.hash_algorithm {
            return Some(a);
        }

        match checksums.split_whitespace().next() {
            Some("BLAKE2b") => Some(HashAlgorithm::Blake2b),
            Some("BLAKE2s") => Some(HashAlgorithm::Blake2s),
            Some("BLAKE3") => Some(HashAlgorithm::Blake3),
            Some("Groestl-224") => Some(HashAlgorithm::Groestl224),
            Some("Groestl-256") => Some(HashAlgorithm::Groestl256),
            Some("Groestl-384") => Some(HashAlgorithm::Groestl384),
            Some("Groestl-512") => Some(HashAlgorithm::Groestl512),
            Some("SHA224") => Some(HashAlgorithm::Sha224),
            Some("SHA256") => Some(HashAlgorithm::Sha256),
            Some("SHA384") => Some(HashAlgorithm::Sha384),
            Some("SHA512") => Some(HashAlgorithm::Sha512),
            Some("SHA3-224") => Some(HashAlgorithm::Sha3_224),
            Some("SHA3-256") => Some(HashAlgorithm::Sha3_256),
            Some("SHA3-384") => Some(HashAlgorithm::Sha3_384),
            Some("SHA3-512") => Some(HashAlgorithm::Sha3_512),
            _ => None,
        }
    }
}
