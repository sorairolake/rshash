//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, Error, Result};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::regex;

pub struct Checksum {
    pub algorithm: Option<HashAlgorithm>,
    pub file: PathBuf,
    pub digest: Vec<u8>,
}

impl FromStr for Checksum {
    type Err = Error;

    fn from_str(checksum: &str) -> Result<Self> {
        if let Some(captures) =
            regex!(r"^(?P<digest>[[:xdigit:]]{32,128})  (?P<file>\S.*\S)$").captures(checksum)
        {
            // Parse as SFV-style checksum.
            return Ok(Self {
                algorithm: None,
                file: captures["file"].into(),
                digest: hex::decode(captures["digest"].to_string())
                    .expect("Failed to decode a hex string into raw bytes"),
            });
        }
        if let Some(captures) =
            regex!(r"^(?P<algorithm>[[:alnum:]-]+) \((?P<file>\S.*\S)\) = (?P<digest>[[:xdigit:]]{32,128})$")
                .captures(checksum)
        {
            // Parse as BSD-style checksum.
            return Ok(Self {
                algorithm: captures["algorithm"].parse().ok(),
                file: captures["file"].into(),
                digest: hex::decode(captures["digest"].to_string()).expect("Failed to decode a hex string into raw bytes"),
            });
        }

        Err(anyhow!("Improperly formatted checksum line"))
    }
}

#[derive(Clone, Copy, SerializeDisplay)]
pub enum HashAlgorithm {
    Blake2b,
    Blake2s,
    Blake3,
    Gost,
    GostCryptoPro,
    Groestl224,
    Groestl256,
    Groestl384,
    Groestl512,
    Keccak224,
    Keccak256,
    Keccak384,
    Keccak512,
    Md2,
    Md4,
    Md5,
    Ripemd160,
    Ripemd256,
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
    Shabal192,
    Shabal224,
    Shabal256,
    Shabal384,
    Shabal512,
    Sm3,
    Streebog256,
    Streebog512,
    Tiger,
    Whirlpool,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashAlgorithm::Blake2b => write!(fmt, "BLAKE2b"),
            HashAlgorithm::Blake2s => write!(fmt, "BLAKE2s"),
            HashAlgorithm::Blake3 => write!(fmt, "BLAKE3"),
            HashAlgorithm::Gost => write!(fmt, "GOST"),
            HashAlgorithm::GostCryptoPro => write!(fmt, "GOST-CryptoPro"),
            HashAlgorithm::Groestl224 => write!(fmt, "Groestl-224"),
            HashAlgorithm::Groestl256 => write!(fmt, "Groestl-256"),
            HashAlgorithm::Groestl384 => write!(fmt, "Groestl-384"),
            HashAlgorithm::Groestl512 => write!(fmt, "Groestl-512"),
            HashAlgorithm::Keccak224 => write!(fmt, "Keccak-224"),
            HashAlgorithm::Keccak256 => write!(fmt, "Keccak-256"),
            HashAlgorithm::Keccak384 => write!(fmt, "Keccak-384"),
            HashAlgorithm::Keccak512 => write!(fmt, "Keccak-512"),
            HashAlgorithm::Md2 => write!(fmt, "MD2"),
            HashAlgorithm::Md4 => write!(fmt, "MD4"),
            HashAlgorithm::Md5 => write!(fmt, "MD5"),
            HashAlgorithm::Ripemd160 => write!(fmt, "RIPEMD-160"),
            HashAlgorithm::Ripemd256 => write!(fmt, "RIPEMD-256"),
            HashAlgorithm::Ripemd320 => write!(fmt, "RIPEMD-320"),
            HashAlgorithm::Sha1 => write!(fmt, "SHA1"),
            HashAlgorithm::Sha224 => write!(fmt, "SHA224"),
            HashAlgorithm::Sha256 => write!(fmt, "SHA256"),
            HashAlgorithm::Sha384 => write!(fmt, "SHA384"),
            HashAlgorithm::Sha512 => write!(fmt, "SHA512"),
            HashAlgorithm::Sha3_224 => write!(fmt, "SHA3-224"),
            HashAlgorithm::Sha3_256 => write!(fmt, "SHA3-256"),
            HashAlgorithm::Sha3_384 => write!(fmt, "SHA3-384"),
            HashAlgorithm::Sha3_512 => write!(fmt, "SHA3-512"),
            HashAlgorithm::Shabal192 => write!(fmt, "Shabal-192"),
            HashAlgorithm::Shabal224 => write!(fmt, "Shabal-224"),
            HashAlgorithm::Shabal256 => write!(fmt, "Shabal-256"),
            HashAlgorithm::Shabal384 => write!(fmt, "Shabal-384"),
            HashAlgorithm::Shabal512 => write!(fmt, "Shabal-512"),
            HashAlgorithm::Sm3 => write!(fmt, "SM3"),
            HashAlgorithm::Streebog256 => write!(fmt, "Streebog-256"),
            HashAlgorithm::Streebog512 => write!(fmt, "Streebog-512"),
            HashAlgorithm::Tiger => write!(fmt, "Tiger"),
            HashAlgorithm::Whirlpool => write!(fmt, "Whirlpool"),
        }
    }
}

impl FromStr for HashAlgorithm {
    type Err = Error;

    fn from_str(algorithm: &str) -> Result<Self> {
        match algorithm.to_ascii_lowercase().as_str() {
            "blake2b" => Ok(HashAlgorithm::Blake2b),
            "blake2s" => Ok(HashAlgorithm::Blake2s),
            "blake3" => Ok(HashAlgorithm::Blake3),
            "gost" => Ok(HashAlgorithm::Gost),
            "gost-cryptopro" => Ok(HashAlgorithm::GostCryptoPro),
            "groestl-224" => Ok(HashAlgorithm::Groestl224),
            "groestl-256" => Ok(HashAlgorithm::Groestl256),
            "groestl-384" => Ok(HashAlgorithm::Groestl384),
            "groestl-512" => Ok(HashAlgorithm::Groestl512),
            "keccak-224" => Ok(HashAlgorithm::Keccak224),
            "keccak-256" => Ok(HashAlgorithm::Keccak256),
            "keccak-384" => Ok(HashAlgorithm::Keccak384),
            "keccak-512" => Ok(HashAlgorithm::Keccak512),
            "md2" => Ok(HashAlgorithm::Md2),
            "md4" => Ok(HashAlgorithm::Md4),
            "md5" => Ok(HashAlgorithm::Md5),
            "ripemd-160" => Ok(HashAlgorithm::Ripemd160),
            "ripemd-256" => Ok(HashAlgorithm::Ripemd256),
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
            "shabal-192" => Ok(HashAlgorithm::Shabal192),
            "shabal-224" => Ok(HashAlgorithm::Shabal224),
            "shabal-256" => Ok(HashAlgorithm::Shabal256),
            "shabal-384" => Ok(HashAlgorithm::Shabal384),
            "shabal-512" => Ok(HashAlgorithm::Shabal512),
            "sm3" => Ok(HashAlgorithm::Sm3),
            "streebog-256" => Ok(HashAlgorithm::Streebog256),
            "streebog-512" => Ok(HashAlgorithm::Streebog512),
            "tiger" => Ok(HashAlgorithm::Tiger),
            "whirlpool" => Ok(HashAlgorithm::Whirlpool),
            _ => Err(anyhow!("Unknown hash algorithm: {}", algorithm)),
        }
    }
}

#[derive(Clone, Copy, DeserializeFromStr)]
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
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Style::Sfv => write!(fmt, "SFV"),
            Style::Bsd => write!(fmt, "BSD"),
        }
    }
}

impl FromStr for Style {
    type Err = Error;

    fn from_str(style: &str) -> Result<Self> {
        match style.to_ascii_lowercase().as_str() {
            "sfv" => Ok(Style::Sfv),
            "bsd" => Ok(Style::Bsd),
            _ => Err(anyhow!("Unknown style: {}", style)),
        }
    }
}
