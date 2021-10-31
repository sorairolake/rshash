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
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sfv_style_checksum() {
        assert_eq!(
            Checksum::digest(crate::value::HashAlgorithm::Md5, ("-", b"Hello, world!"))
                .output(Style::Sfv),
            "6cd3556deb0da54bca060b4c39479839  -"
        );
    }

    #[test]
    fn bsd_style_checksum() {
        assert_eq!(
            Checksum::digest(crate::value::HashAlgorithm::Md5, ("-", b"Hello, world!"))
                .output(Style::Bsd),
            "MD5 (-) = 6cd3556deb0da54bca060b4c39479839"
        );
    }
}
