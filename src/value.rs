//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Error, Result};

#[derive(Debug)]
pub struct Checksum {
    pub path: PathBuf,
    pub digest: String,
}

impl Checksum {
    pub fn new(input: (&Path, &str)) -> Self {
        Checksum {
            path: input.0.to_path_buf(),
            digest: input.1.to_string(),
        }
    }
}

impl FromStr for Checksum {
    type Err = Error;

    fn from_str(checksum: &str) -> Result<Self> {
        if let Some(p) = checksum.splitn(2, "  ").nth(1) {
            // Parse as SFV-style checksum.
            let path: PathBuf = p.into();
            let digest = checksum
                .split_whitespace()
                .next()
                .context("Invalid format of checksum lines.")?;

            Ok(Self::new((path.as_path(), digest)))
        } else {
            // Parse as BSD-style checksum.
            let path = checksum
                .splitn(2, " (")
                .nth(1)
                .context("Invalid format of checksum lines.")?;
            let path = path
                .rsplitn(2, ") = ")
                .nth(1)
                .context("Invalid format of checksum lines.")?;
            let path: PathBuf = path.into();
            let digest = checksum
                .rsplit(' ')
                .next()
                .context("Invalid format of checksum lines.")?;

            Ok(Self::new((path.as_path(), digest)))
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum HashAlgorithm {
    Blake2b,
    Blake2s,
    Blake3,
    Groestl256,
    Groestl512,
    Sha256,
    Sha512,
    Sha3_256,
    Sha3_512,
}

impl FromStr for HashAlgorithm {
    type Err = Error;

    fn from_str(format: &str) -> Result<Self> {
        match format.to_ascii_lowercase().as_str() {
            "blake2b" => Ok(HashAlgorithm::Blake2b),
            "blake2s" => Ok(HashAlgorithm::Blake2s),
            "blake3" => Ok(HashAlgorithm::Blake3),
            "groestl-256" => Ok(HashAlgorithm::Groestl256),
            "groestl-512" => Ok(HashAlgorithm::Groestl512),
            "sha256" => Ok(HashAlgorithm::Sha256),
            "sha512" => Ok(HashAlgorithm::Sha512),
            "sha3-256" => Ok(HashAlgorithm::Sha3_256),
            "sha3-512" => Ok(HashAlgorithm::Sha3_512),
            _ => unreachable!(),
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashAlgorithm::Blake2b => write!(f, "BLAKE2b"),
            HashAlgorithm::Blake2s => write!(f, "BLAKE2s"),
            HashAlgorithm::Blake3 => write!(f, "BLAKE3"),
            HashAlgorithm::Groestl256 => write!(f, "Groestl-256"),
            HashAlgorithm::Groestl512 => write!(f, "Groestl-512"),
            HashAlgorithm::Sha256 => write!(f, "SHA256"),
            HashAlgorithm::Sha512 => write!(f, "SHA512"),
            HashAlgorithm::Sha3_256 => write!(f, "SHA3-256"),
            HashAlgorithm::Sha3_512 => write!(f, "SHA3-512"),
        }
    }
}

#[derive(Debug)]
pub enum Style {
    Sfv,
    Bsd,
}

impl Default for Style {
    fn default() -> Self {
        Style::Sfv
    }
}

impl fmt::Display for Style {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Style::Sfv => write!(f, "SFV"),
            Style::Bsd => write!(f, "BSD"),
        }
    }
}

impl FromStr for Style {
    type Err = Error;

    fn from_str(format: &str) -> Result<Self> {
        match format.to_ascii_lowercase().as_str() {
            "sfv" => Ok(Style::Sfv),
            "bsd" => Ok(Style::Bsd),
            _ => unreachable!(),
        }
    }
}
