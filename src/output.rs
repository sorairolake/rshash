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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sfv_style_checksum() {
        assert_eq!(
            Checksum::digest(crate::value::HashAlgorithm::Blake2b, ("-", b"Hello, world!")).output(Style::Sfv),
            "a2764d133a16816b5847a737a786f2ece4c148095c5faa73e24b4cc5d666c3e45ec271504e14dc6127ddfce4e144fb23b91a6f7b04b53d695502290722953b0f  -"
        );
    }

    #[test]
    fn bsd_style_checksum() {
        assert_eq!(
            Checksum::digest(crate::value::HashAlgorithm::Blake2b, ("-", b"Hello, world!")).output(Style::Bsd),
            "BLAKE2b (-) = a2764d133a16816b5847a737a786f2ece4c148095c5faa73e24b4cc5d666c3e45ec271504e14dc6127ddfce4e144fb23b91a6f7b04b53d695502290722953b0f"
        );
    }
}
