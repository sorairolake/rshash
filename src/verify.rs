//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::Result;

use crate::value::{Checksum, HashAlgorithm};

#[derive(Debug)]
pub struct Verify {
    pub path: PathBuf,
    pub is_path_exist: bool,
    pub result: Option<bool>,
}

impl Verify {
    /// Verify a checksum.
    pub fn verify(algo: &HashAlgorithm, checksum: &Checksum) -> Result<Self> {
        if !checksum.path.exists() && atty::is(atty::Stream::Stdin) {
            return Ok(Verify {
                path: checksum.path.clone(),
                is_path_exist: false,
                result: None,
            });
        }

        let data = if atty::isnt(atty::Stream::Stdin) {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            buf
        } else {
            fs::read(checksum.path.as_path())?
        };

        let compute_result = Checksum::compute(algo, (checksum.path.as_path(), data.as_slice()));

        if compute_result.digest == checksum.digest.to_ascii_lowercase() {
            Ok(Verify {
                path: checksum.path.clone(),
                is_path_exist: true,
                result: Some(true),
            })
        } else {
            Ok(Verify {
                path: checksum.path.clone(),
                is_path_exist: true,
                result: Some(false),
            })
        }
    }

    /// Output verification result.
    pub fn output(&self) -> String {
        if !self.is_path_exist {
            return format!("{}: No such file or directory", self.path.display());
        }

        if self.result.unwrap() {
            format!("{}: OK", self.path.display())
        } else {
            format!("{}: FAILED", self.path.display())
        }
    }
}
