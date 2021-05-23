//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use const_format::formatcp;
use structopt::clap::{crate_name, crate_version, AppSettings, Shell};
use structopt::StructOpt;

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
const CHECKSUM_STYLES: [&str; 2] = ["sfv", "bsd"];

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

    /// Allow insecure hash algorithm.
    #[structopt(long)]
    pub allow_insecure_hash_algorithm: bool,

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

    /// Generate completions.
    #[structopt(long, hidden = true)]
    pub generate_completions: bool,
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
            Some("GOST") => Some(HashAlgorithm::Gost),
            Some("GOST-CryptoPro") => Some(HashAlgorithm::GostCryptoPro),
            Some("Groestl-224") => Some(HashAlgorithm::Groestl224),
            Some("Groestl-256") => Some(HashAlgorithm::Groestl256),
            Some("Groestl-384") => Some(HashAlgorithm::Groestl384),
            Some("Groestl-512") => Some(HashAlgorithm::Groestl512),
            Some("Keccak-224") => Some(HashAlgorithm::Keccak224),
            Some("Keccak-256") => Some(HashAlgorithm::Keccak256),
            Some("Keccak-384") => Some(HashAlgorithm::Keccak384),
            Some("Keccak-512") => Some(HashAlgorithm::Keccak512),
            Some("MD2") => Some(HashAlgorithm::Md2),
            Some("MD4") => Some(HashAlgorithm::Md4),
            Some("MD5") => Some(HashAlgorithm::Md5),
            Some("RIPEMD-160") => Some(HashAlgorithm::Ripemd160),
            Some("RIPEMD-320") => Some(HashAlgorithm::Ripemd320),
            Some("SHA1") => Some(HashAlgorithm::Sha1),
            Some("SHA224") => Some(HashAlgorithm::Sha224),
            Some("SHA256") => Some(HashAlgorithm::Sha256),
            Some("SHA384") => Some(HashAlgorithm::Sha384),
            Some("SHA512") => Some(HashAlgorithm::Sha512),
            Some("SHA3-224") => Some(HashAlgorithm::Sha3_224),
            Some("SHA3-256") => Some(HashAlgorithm::Sha3_256),
            Some("SHA3-384") => Some(HashAlgorithm::Sha3_384),
            Some("SHA3-512") => Some(HashAlgorithm::Sha3_512),
            Some("Shabal-192") => Some(HashAlgorithm::Shabal192),
            Some("Shabal-224") => Some(HashAlgorithm::Shabal224),
            Some("Shabal-256") => Some(HashAlgorithm::Shabal256),
            Some("Shabal-384") => Some(HashAlgorithm::Shabal384),
            Some("Shabal-512") => Some(HashAlgorithm::Shabal512),
            Some("Streebog-256") => Some(HashAlgorithm::Streebog256),
            Some("Streebog-512") => Some(HashAlgorithm::Streebog512),
            Some("Tiger") => Some(HashAlgorithm::Tiger),
            Some("Whirlpool") => Some(HashAlgorithm::Whirlpool),
            _ => None,
        }
    }

    /// Generate completions.
    pub fn generate_completions() -> Result<()> {
        let outdir = Path::new("completion");
        if !outdir.exists() {
            fs::create_dir(outdir)?;
        }

        let shells: Vec<Shell> = Shell::variants().iter().flat_map(|s| s.parse()).collect();
        for s in shells {
            Self::clap().gen_completions(crate_name!(), s, outdir);
        }

        Ok(())
    }
}
