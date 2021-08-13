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
const APP_SETTINGS: [AppSettings; 2] = [AppSettings::ColoredHelp, AppSettings::DeriveDisplayOrder];
const HASH_ALGORITHMS: [&str; 38] = [
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
    "ripemd-256",
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
    "sm3",
    "streebog-256",
    "streebog-512",
    "tiger",
    "whirlpool",
];

#[derive(StructOpt)]
#[structopt(name = "RSHash", long_version = LONG_VERSION, about, settings = &APP_SETTINGS)]
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
    #[structopt(short, long, requires = "input", conflicts_with_all = &["output", "style"])]
    pub check: bool,

    /// Don't fail or report status for missing files.
    #[structopt(long, requires = "check")]
    pub ignore_missing: bool,

    /// Don't print OK for each successfully verified file.
    #[structopt(long, requires = "check")]
    pub quiet: bool,

    /// Don't output anything, return the verification result as the exit status.
    #[structopt(long, requires = "check")]
    pub status: bool,

    /// Exit non-zero for improperly formatted checksum lines.
    #[structopt(long, requires = "check")]
    pub strict: bool,

    /// Warn about improperly formatted checksum lines.
    #[structopt(short, long, requires = "check")]
    pub warn: bool,

    /// Output the verification result as JSON to stdout.
    #[structopt(short, long, requires = "check")]
    pub json: bool,

    /// Output as a pretty-printed JSON.
    #[structopt(short, long, requires = "json")]
    pub pretty: bool,

    /// Output to <FILE> instead of stdout.
    #[structopt(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Specify style of the checksums.
    #[structopt(
        short,
        long,
        value_name = "STYLE",
        possible_values = &["sfv", "bsd", "json"],
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
    /// Apply the config from the config file.
    pub fn apply_config(mut self) -> Result<Self> {
        if let Some(path) = Config::path() {
            let config = Config::read(&path)?;
            let matches = Self::clap().get_matches();

            if let Some(style) = config.style {
                if matches.occurrences_of("style") == 0 {
                    self.style = style;
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
