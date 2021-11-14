//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::io;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use structopt::clap::{crate_name, AppSettings, Shell};
use structopt::StructOpt;
use strum::VariantNames;

use crate::config::Config;
use crate::long_version;
use crate::value::{HashAlgorithm, Style};

#[derive(StructOpt)]
#[structopt(
    name = "RSHash",
    long_version = long_version!().as_str(),
    about,
    after_help = "See rshash(1) for more details.",
    settings = &[AppSettings::ColoredHelp, AppSettings::DeriveDisplayOrder]
)]
pub struct Opt {
    /// Specify hash algorithm.
    #[structopt(
        short = "H",
        long,
        value_name = "NAME",
        possible_values = &HashAlgorithm::VARIANTS,
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

    /// Don't output anything, return the verification result as the exit
    /// status.
    #[structopt(long, requires = "check")]
    pub status: bool,

    /// Exit non-zero for improperly formatted checksum lines.
    #[structopt(long, requires = "check")]
    pub strict: bool,

    /// Warn about improperly formatted checksum lines.
    #[structopt(short, long, requires = "check")]
    pub warn: bool,

    /// Output the verification result as JSON to stdout.
    ///
    /// If you want to pretty-printing, specify `--pretty` as well.
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
        possible_values = &Style::VARIANTS,
        case_insensitive = true,
        default_value
    )]
    pub style: Style,

    /// Specify the number of threads to use.
    ///
    /// If <NUM> is `0`, use as many threads as there are CPU cores.
    #[structopt(short = "T", long, value_name = "NUM", default_value)]
    pub threads: usize,

    /// Display a progress bar for reporting progress.
    #[structopt(long)]
    pub progress: bool,

    /// Print the processing speed.
    #[structopt(long)]
    pub speed: bool,

    /// Input from <FILE>.
    #[structopt(value_name = "FILE")]
    pub input: Vec<PathBuf>,

    /// Generate shell completion.
    ///
    /// The generated shell completion is output to stdout.
    /// To output as a shell completion file, specify the directory to store
    /// using `--output`=<OUT_DIR>.
    #[structopt(long, value_name = "SHELL", possible_values = &Shell::variants())]
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

    /// Generate shell completion to stdout.
    pub fn generate_completion(shell: Shell) {
        Self::clap().gen_completions_to(crate_name!(), shell, &mut io::stdout())
    }

    /// Generate shell completion to a file.
    pub fn generate_completion_to(shell: Shell, out_dir: impl AsRef<Path>) -> Result<()> {
        let out_dir = out_dir
            .as_ref()
            .canonicalize()
            .context("Failed to generate shell completion to a file")?;
        ensure!(out_dir.is_dir(), "Output destination is not a directory");

        Self::clap().gen_completions(crate_name!(), shell, &out_dir);
        eprintln!(
            "Generated a shell completion file of the {} in {}",
            shell,
            out_dir.display()
        );

        Ok(())
    }
}
