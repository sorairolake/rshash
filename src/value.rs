//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, Error, Result};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DeserializeFromStr, SerializeDisplay};
use strum::{Display, EnumString, EnumVariantNames};

use crate::regex;

#[serde_as]
#[derive(Deserialize, Serialize)]
pub struct Checksum {
    pub algorithm: Option<HashAlgorithm>,
    pub file: PathBuf,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub digest: Vec<u8>,
}

impl FromStr for Checksum {
    type Err = Error;

    fn from_str(checksum: &str) -> Result<Self> {
        if let Some(captures) =
            regex!(r"^(?P<digest>[[:xdigit:]]{32,128})  (?P<file>.*)$").captures(checksum)
        {
            // Parse as SFV-style checksum.
            return Ok(Self {
                algorithm: None,
                file: captures["file"].trim().into(),
                digest: hex::decode(captures["digest"].to_string())
                    .expect("Failed to decode a hex string into raw bytes"),
            });
        }
        if let Some(captures) = regex!(
            r"^(?P<algorithm>[[:alnum:]-]+) \((?P<file>.*)\) = (?P<digest>[[:xdigit:]]{32,128})$"
        )
        .captures(checksum)
        {
            // Parse as BSD-style checksum.
            return Ok(Self {
                algorithm: captures["algorithm"].parse().ok(),
                file: captures["file"].trim().into(),
                digest: hex::decode(captures["digest"].to_string())
                    .expect("Failed to decode a hex string into raw bytes"),
            });
        }

        Err(anyhow!("Improperly formatted checksum line"))
    }
}

#[derive(
    Clone, Copy, DeserializeFromStr, Display, EnumString, EnumVariantNames, SerializeDisplay,
)]
#[strum(serialize_all = "SCREAMING-KEBAB-CASE", ascii_case_insensitive)]
pub enum HashAlgorithm {
    #[strum(to_string = "BLAKE2b")]
    Blake2b,
    #[strum(to_string = "BLAKE2s")]
    Blake2s,
    Blake3,
    #[strum(serialize = "FSB-160")]
    Fsb160,
    #[strum(serialize = "FSB-224")]
    Fsb224,
    #[strum(serialize = "FSB-256")]
    Fsb256,
    #[strum(serialize = "FSB-384")]
    Fsb384,
    #[strum(serialize = "FSB-512")]
    Fsb512,
    Gost,
    #[strum(serialize = "GOST-CryptoPro")]
    GostCryptoPro,
    #[strum(serialize = "Groestl-224")]
    Groestl224,
    #[strum(serialize = "Groestl-256")]
    Groestl256,
    #[strum(serialize = "Groestl-384")]
    Groestl384,
    #[strum(serialize = "Groestl-512")]
    Groestl512,
    #[strum(serialize = "Keccak-224")]
    Keccak224,
    #[strum(serialize = "Keccak-256")]
    Keccak256,
    #[strum(serialize = "Keccak-384")]
    Keccak384,
    #[strum(serialize = "Keccak-512")]
    Keccak512,
    Md2,
    Md4,
    Md5,
    #[strum(serialize = "RIPEMD-160")]
    Ripemd160,
    #[strum(serialize = "RIPEMD-256")]
    Ripemd256,
    #[strum(serialize = "RIPEMD-320")]
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
    #[strum(serialize = "Shabal-192")]
    Shabal192,
    #[strum(serialize = "Shabal-224")]
    Shabal224,
    #[strum(serialize = "Shabal-256")]
    Shabal256,
    #[strum(serialize = "Shabal-384")]
    Shabal384,
    #[strum(serialize = "Shabal-512")]
    Shabal512,
    Sm3,
    #[strum(serialize = "Streebog-256")]
    Streebog256,
    #[strum(serialize = "Streebog-512")]
    Streebog512,
    #[strum(to_string = "Tiger")]
    Tiger,
    #[strum(to_string = "Whirlpool")]
    Whirlpool,
}

#[derive(Clone, Copy, DeserializeFromStr, Display, EnumString, EnumVariantNames, PartialEq)]
#[strum(serialize_all = "UPPERCASE", ascii_case_insensitive)]
pub enum Style {
    Sfv,
    Bsd,
    Json,
}

impl Default for Style {
    fn default() -> Self {
        Style::Sfv
    }
}
