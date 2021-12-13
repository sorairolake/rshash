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
    pub fn check(checksum: &Checksum) -> Result<Self> {
        let algorithm = checksum.algorithm.expect("Hash algorithm is unknown");

        if !checksum.file.exists() && atty::is(atty::Stream::Stdin) {
            return Ok(Self {
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

        let result = Checksum::digest(algorithm, &(checksum.file.clone(), data));

        if result.digest == checksum.digest {
            Ok(Self {
                algorithm,
                file: checksum.file.clone(),
                success: Some(true),
            })
        } else {
            Ok(Self {
                algorithm,
                file: checksum.file.clone(),
                success: Some(false),
            })
        }
    }

    /// Output verification result.
    pub fn output(&self) -> String {
        self.success.map_or_else(
            || {
                format!(
                    "{:01$} No such file or directory",
                    self.file.display(),
                    VERIFICATION_RESULT_WIDTH - 30
                )
            },
            |s| {
                if s {
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
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    #[ignore]
    fn verification_success() {
        let mut file = NamedTempFile::new().unwrap();
        let data = "Hello, world!";
        write!(file, "{}", data).unwrap();
        let checksum = Checksum::digest(HashAlgorithm::Blake2b, &(file.path(), data));
        let result = Verify::check(&checksum).unwrap();

        assert!(result.success.unwrap());
        assert!(result.output().ends_with("OK"));
    }

    #[test]
    #[ignore]
    fn verification_failure() {
        let mut file = NamedTempFile::new().unwrap();
        let data = "Hello";
        write!(file, "{}", data).unwrap();
        let checksum = Checksum::digest(HashAlgorithm::Blake2b, &(file.path(), data));
        write!(file, ", world!").unwrap();
        let result = Verify::check(&checksum).unwrap();

        assert!(!result.success.unwrap());
        assert!(result.output().ends_with("FAILED"));
    }

    #[test]
    #[ignore]
    fn verification_missing() {
        let mut file = NamedTempFile::new().unwrap();
        let data = "Hello, world!";
        write!(file, "{}", data).unwrap();
        let checksum = Checksum::digest(HashAlgorithm::Blake2b, &(file.path(), data));
        file.close().unwrap();
        let result = Verify::check(&checksum).unwrap();

        assert!(result.success.is_none());
        assert!(result.output().ends_with("No such file or directory"));
    }
}
