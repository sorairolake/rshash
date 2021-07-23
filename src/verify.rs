//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::Result;
use serde::Serialize;

use crate::value::{Checksum, HashAlgorithm};

#[derive(Clone, Debug, Serialize)]
pub struct Verify {
    pub file: PathBuf,
    pub exist: bool,
    pub success: Option<bool>,
}

impl Verify {
    /// Verify a checksum.
    pub fn verify(algo: HashAlgorithm, checksum: &Checksum) -> Result<Self> {
        if !checksum.file.exists() && atty::is(atty::Stream::Stdin) {
            return Ok(Verify {
                file: checksum.file.clone(),
                exist: false,
                success: None,
            });
        }

        let data = if atty::isnt(atty::Stream::Stdin) {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            buf
        } else {
            fs::read(checksum.file.clone())?
        };

        let result = Checksum::digest(algo, (checksum.file.clone(), data));

        if result.digest == checksum.digest.to_ascii_lowercase() {
            Ok(Verify {
                file: checksum.file.clone(),
                exist: true,
                success: Some(true),
            })
        } else {
            Ok(Verify {
                file: checksum.file.clone(),
                exist: true,
                success: Some(false),
            })
        }
    }

    /// Output verification result.
    pub fn output(&self, padding: impl Into<usize>) -> String {
        if !self.exist {
            return format!(
                "{:01$} No such file or directory",
                self.file.display(),
                padding.into()
            );
        }

        if self.success.unwrap() {
            format!("{:01$} OK", self.file.display(), padding.into())
        } else {
            format!("{:01$} FAILED", self.file.display(), padding.into())
        }
    }
}
