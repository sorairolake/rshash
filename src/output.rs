//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use crate::value::{Checksum, Style};

impl Checksum {
    /// Output a checksum for the specified style.
    pub fn output(&self, style: Style) -> String {
        match style {
            Style::Sfv => format!(
                "{}  {}",
                hex::encode(self.digest.clone()),
                self.file.display()
            ),
            Style::Bsd => format!(
                "{} ({}) = {}",
                self.algorithm.expect("Hash algorithm is unknown"),
                self.file.display(),
                hex::encode(self.digest.clone())
            ),
            Style::Json => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sfv_style_checksum() {
        assert_eq!(
            Checksum::digest(
                crate::value::HashAlgorithm::Blake2b,
                &("-", b"Hello, world!")
            )
            .output(Style::Sfv),
            include_str!("../tests/resource/checksum/sfv.b2b")
                .lines()
                .next()
                .unwrap()
        );
    }

    #[test]
    fn bsd_style_checksum() {
        assert_eq!(
            Checksum::digest(
                crate::value::HashAlgorithm::Blake2b,
                &("-", b"Hello, world!")
            )
            .output(Style::Bsd),
            include_str!("../tests/resource/checksum/bsd.b2b")
                .lines()
                .next()
                .unwrap()
        );
    }
}
