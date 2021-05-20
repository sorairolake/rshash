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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HashAlgorithm {
    Blake2b,
    Blake2s,
    Blake3,
    Groestl224,
    Groestl256,
    Groestl384,
    Groestl512,
    Md2,
    Md4,
    Md5,
    Ripemd160,
    Ripemd320,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Streebog256,
    Streebog512,
    Whirlpool,
}

impl FromStr for HashAlgorithm {
    type Err = Error;

    fn from_str(format: &str) -> Result<Self> {
        match format.to_ascii_lowercase().as_str() {
            "blake2b" => Ok(HashAlgorithm::Blake2b),
            "blake2s" => Ok(HashAlgorithm::Blake2s),
            "blake3" => Ok(HashAlgorithm::Blake3),
            "groestl-224" => Ok(HashAlgorithm::Groestl224),
            "groestl-256" => Ok(HashAlgorithm::Groestl256),
            "groestl-384" => Ok(HashAlgorithm::Groestl384),
            "groestl-512" => Ok(HashAlgorithm::Groestl512),
            "md2" => Ok(HashAlgorithm::Md2),
            "md4" => Ok(HashAlgorithm::Md4),
            "md5" => Ok(HashAlgorithm::Md5),
            "ripemd-160" => Ok(HashAlgorithm::Ripemd160),
            "ripemd-320" => Ok(HashAlgorithm::Ripemd320),
            "sha1" => Ok(HashAlgorithm::Sha1),
            "sha224" => Ok(HashAlgorithm::Sha224),
            "sha256" => Ok(HashAlgorithm::Sha256),
            "sha384" => Ok(HashAlgorithm::Sha384),
            "sha512" => Ok(HashAlgorithm::Sha512),
            "sha3-224" => Ok(HashAlgorithm::Sha3_224),
            "sha3-256" => Ok(HashAlgorithm::Sha3_256),
            "sha3-384" => Ok(HashAlgorithm::Sha3_384),
            "sha3-512" => Ok(HashAlgorithm::Sha3_512),
            "streebog-256" => Ok(HashAlgorithm::Streebog256),
            "streebog-512" => Ok(HashAlgorithm::Streebog512),
            "whirlpool" => Ok(HashAlgorithm::Whirlpool),
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
            HashAlgorithm::Groestl224 => write!(f, "Groestl-224"),
            HashAlgorithm::Groestl256 => write!(f, "Groestl-256"),
            HashAlgorithm::Groestl384 => write!(f, "Groestl-384"),
            HashAlgorithm::Groestl512 => write!(f, "Groestl-512"),
            HashAlgorithm::Md2 => write!(f, "MD2"),
            HashAlgorithm::Md4 => write!(f, "MD4"),
            HashAlgorithm::Md5 => write!(f, "MD5"),
            HashAlgorithm::Ripemd160 => write!(f, "RIPEMD-160"),
            HashAlgorithm::Ripemd320 => write!(f, "RIPEMD-320"),
            HashAlgorithm::Sha1 => write!(f, "SHA1"),
            HashAlgorithm::Sha224 => write!(f, "SHA224"),
            HashAlgorithm::Sha256 => write!(f, "SHA256"),
            HashAlgorithm::Sha384 => write!(f, "SHA384"),
            HashAlgorithm::Sha512 => write!(f, "SHA512"),
            HashAlgorithm::Sha3_224 => write!(f, "SHA3-224"),
            HashAlgorithm::Sha3_256 => write!(f, "SHA3-256"),
            HashAlgorithm::Sha3_384 => write!(f, "SHA3-384"),
            HashAlgorithm::Sha3_512 => write!(f, "SHA3-512"),
            HashAlgorithm::Streebog256 => write!(f, "Streebog-256"),
            HashAlgorithm::Streebog512 => write!(f, "Streebog-512"),
            HashAlgorithm::Whirlpool => write!(f, "Whirlpool"),
        }
    }
}

pub const INSECURE_HASH_ALGORITHMS: [HashAlgorithm; 4] = [
    HashAlgorithm::Md2,
    HashAlgorithm::Md4,
    HashAlgorithm::Md5,
    HashAlgorithm::Sha1,
];

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
