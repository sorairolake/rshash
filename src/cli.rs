//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::io;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use const_format::formatcp;
use structopt::clap::{crate_name, crate_version, AppSettings, Shell};
use structopt::StructOpt;

use crate::config::Config;
use crate::value::{HashAlgorithm, Style};

const LONG_VERSION: &str = formatcp!(
    "{}\n\n{}\n{}\n{}",
    crate_version!(),
    "Copyright (C) 2021 Shun Sakai",
    "License: GNU General Public License v3.0 or later",
    "Reporting bugs: https://github.com/sorairolake/rshash/issues"
);
const HASH_ALGORITHMS: [&str; 36] = [
    "blake2b",
    "blake2s",
    "blake3",
    "gost",
    "gost-cryptopro",
    "groestl-224",
    "groestl-256",
    "groestl-384",
    "groestl-512",
    "keccak-224",
    "keccak-256",
    "keccak-384",
    "keccak-512",
    "md2",
    "md4",
    "md5",
    "ripemd-160",
    "ripemd-320",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
    "shabal-192",
    "shabal-224",
    "shabal-256",
    "shabal-384",
    "shabal-512",
    "streebog-256",
    "streebog-512",
    "tiger",
    "whirlpool",
];

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
    #[structopt(short, long, requires = "input", conflicts_with = "output")]
    pub check: bool,

    /// Don't fail or report status for missing files.
    #[structopt(long, requires = "check", conflicts_with_all = &["quiet", "status"])]
    pub ignore_missing: bool,

    /// Don't print OK for each successfully verified file.
    #[structopt(long, requires = "check", conflicts_with = "status")]
    pub quiet: bool,

    /// Don't output anything, return the verification result as the exit status.
    #[structopt(long, requires = "check")]
    pub status: bool,

    /// Output to <FILE> instead of stdout.
    #[structopt(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Specify style of the checksums.
    #[structopt(
        long,
        value_name = "STYLE",
        possible_values = &["sfv", "bsd"],
        case_insensitive = true,
        default_value
    )]
    pub style: Style,

    /// Input from <FILE>.
    #[structopt(value_name = "FILE")]
    pub input: Vec<PathBuf>,

    /// Generate shell completion.
    #[structopt(long, value_name = "SHELL", possible_values = &Shell::variants(), hidden = true)]
    pub generate_completion: Option<Shell>,
}

impl Opt {
    /// Guess the hash algorithm from BSD-style checksums.
    pub fn guess_hash_algorithm(&self, checksums: impl AsRef<str>) -> Option<HashAlgorithm> {
        if let Some(a) = self.hash_algorithm {
            return Some(a);
        }

        match checksums
            .as_ref()
            .split_whitespace()
            .next()?
            .to_ascii_uppercase()
            .as_str()
        {
            "BLAKE2B" => Some(HashAlgorithm::Blake2b),
            "BLAKE2S" => Some(HashAlgorithm::Blake2s),
            "BLAKE3" => Some(HashAlgorithm::Blake3),
            "GOST" => Some(HashAlgorithm::Gost),
            "GOST-CRYPTOPRO" => Some(HashAlgorithm::GostCryptoPro),
            "GROESTL-224" => Some(HashAlgorithm::Groestl224),
            "GROESTL-256" => Some(HashAlgorithm::Groestl256),
            "GROESTL-384" => Some(HashAlgorithm::Groestl384),
            "GROESTL-512" => Some(HashAlgorithm::Groestl512),
            "KECCAK-224" => Some(HashAlgorithm::Keccak224),
            "KECCAK-256" => Some(HashAlgorithm::Keccak256),
            "KECCAK-384" => Some(HashAlgorithm::Keccak384),
            "KECCAK-512" => Some(HashAlgorithm::Keccak512),
            "MD2" => Some(HashAlgorithm::Md2),
            "MD4" => Some(HashAlgorithm::Md4),
            "MD5" => Some(HashAlgorithm::Md5),
            "RIPEMD-160" => Some(HashAlgorithm::Ripemd160),
            "RIPEMD-320" => Some(HashAlgorithm::Ripemd320),
            "SHA1" => Some(HashAlgorithm::Sha1),
            "SHA224" => Some(HashAlgorithm::Sha224),
            "SHA256" => Some(HashAlgorithm::Sha256),
            "SHA384" => Some(HashAlgorithm::Sha384),
            "SHA512" => Some(HashAlgorithm::Sha512),
            "SHA3-224" => Some(HashAlgorithm::Sha3_224),
            "SHA3-256" => Some(HashAlgorithm::Sha3_256),
            "SHA3-384" => Some(HashAlgorithm::Sha3_384),
            "SHA3-512" => Some(HashAlgorithm::Sha3_512),
            "SHABAL-192" => Some(HashAlgorithm::Shabal192),
            "SHABAL-224" => Some(HashAlgorithm::Shabal224),
            "SHABAL-256" => Some(HashAlgorithm::Shabal256),
            "SHABAL-384" => Some(HashAlgorithm::Shabal384),
            "SHABAL-512" => Some(HashAlgorithm::Shabal512),
            "STREEBOG-256" => Some(HashAlgorithm::Streebog256),
            "STREEBOG-512" => Some(HashAlgorithm::Streebog512),
            "TIGER" => Some(HashAlgorithm::Tiger),
            "WHIRLPOOL" => Some(HashAlgorithm::Whirlpool),
            _ => None,
        }
    }

    /// Apply the config from the config file.
    pub fn apply_config(mut self) -> Result<Self> {
        if let Some(p) = Config::path() {
            let config = Config::read(&p)?;
            let matches = Self::clap().get_matches();

            if let Some(s) = config.style {
                if matches.occurrences_of("style") == 0 {
                    self.style = s;
                }
            }
        }

        Ok(self)
    }

    /// Generate shell completion to a file.
    pub fn generate_completion_to_file(shell: Shell, outdir: impl AsRef<Path>) -> Result<()> {
        let outdir = outdir
            .as_ref()
            .canonicalize()
            .context("Failed to generate shell completion to a file")?;
        ensure!(outdir.is_dir(), "Output destination is not a directory");

        Self::clap().gen_completions(crate_name!(), shell, &outdir);
        eprintln!(
            "Generated a shell completion file of the {} in {}",
            shell,
            outdir.display()
        );

        Ok(())
    }

    /// Generate shell completion to stdout.
    pub fn generate_completion_to_stdout(shell: Shell) {
        Self::clap().gen_completions_to(crate_name!(), shell, &mut io::stdout())
    }
}
