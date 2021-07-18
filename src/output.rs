//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use crate::value::{Checksum, HashAlgorithm, Style};

impl Checksum {
    /// Create a SFV-style checksum.
    fn sfv(&self) -> String {
        format!("{}  {}", self.digest, self.path.display())
    }

    /// Create a BSD-style checksum.
    fn bsd(&self, algo: &HashAlgorithm) -> String {
        format!("{} ({}) = {}", algo, self.path.display(), self.digest)
    }

    /// Create a checksum for the specified style.
    pub fn output(&self, algo: &HashAlgorithm, style: &Style) -> String {
        match style {
            Style::Sfv => self.sfv(),
            Style::Bsd => self.bsd(algo),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sfv_style_checksum() {
        assert_eq!(
            Checksum::compute(&HashAlgorithm::Blake2b, ("-", b"Hello, world!")).output(&HashAlgorithm::Blake2b, &Style::Sfv),
            "a2764d133a16816b5847a737a786f2ece4c148095c5faa73e24b4cc5d666c3e45ec271504e14dc6127ddfce4e144fb23b91a6f7b04b53d695502290722953b0f  -"
        );
    }

    #[test]
    fn bsd_style_checksum() {
        assert_eq!(
            Checksum::compute(&HashAlgorithm::Blake2b, ("-", b"Hello, world!")).output(&HashAlgorithm::Blake2b, &Style::Bsd),
            "BLAKE2b (-) = a2764d133a16816b5847a737a786f2ece4c148095c5faa73e24b4cc5d666c3e45ec271504e14dc6127ddfce4e144fb23b91a6f7b04b53d695502290722953b0f"
        );
    }
}
