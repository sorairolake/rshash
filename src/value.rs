//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Error, Result};

#[derive(Debug)]
pub struct Checksum {
    pub algorithm: HashAlgorithm,
    pub digest: String,
    pub path: PathBuf,
}

#[derive(Clone, Copy, Debug)]
pub enum HashAlgorithm {
    Blake2b,
    Blake2s,
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
