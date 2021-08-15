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

pub const VERIFICATION_RESULT_WIDTH: usize = if cfg!(windows) { 79 } else { 80 };

#[derive(Clone, Serialize)]
pub struct Verify {
    pub algorithm: HashAlgorithm,
    pub file: PathBuf,
    pub success: Option<bool>,
}

impl Verify {
    /// Verify a checksum.
    pub fn verify(checksum: &Checksum) -> Result<Self> {
        let algorithm = checksum.algorithm.expect("Hash algorithm is unknown");

        if !checksum.file.exists() && atty::is(atty::Stream::Stdin) {
            return Ok(Verify {
                algorithm,
                file: checksum.file.clone(),
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

        let result = Checksum::digest(algorithm, (checksum.file.clone(), data));

        if result.digest == checksum.digest {
            Ok(Verify {
                algorithm,
                file: checksum.file.clone(),
                success: Some(true),
            })
        } else {
            Ok(Verify {
                algorithm,
                file: checksum.file.clone(),
                success: Some(false),
            })
        }
    }

    /// Output verification result.
    pub fn output(&self) -> String {
        if let Some(success) = self.success {
            if success {
                format!(
                    "{:01$} OK",
                    self.file.display(),
                    VERIFICATION_RESULT_WIDTH - 30
                )
            } else {
                format!(
                    "{:01$} FAILED",
                    self.file.display(),
                    VERIFICATION_RESULT_WIDTH - 30
                )
            }
        } else {
            format!(
                "{:01$} No such file or directory",
                self.file.display(),
                VERIFICATION_RESULT_WIDTH - 30
            )
        }
    }
}
