//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use crate::value::{Checksum, Style};

impl Checksum {
    /// Create a SFV-style checksum.
    fn sfv(&self) -> String {
        let output = format!("{}  {}", self.digest, self.path.as_path().display());

        output
    }

    /// Create a BSD-style checksum.
    fn bsd(&self) -> String {
        let output = format!(
            "{} ({}) = {}",
            self.algorithm,
            self.path.as_path().display(),
            self.digest
        );

        output
    }

    /// Create a checksum for the specified style.
    pub fn output(&self, style: &Style) -> String {
        match style {
            Style::Sfv => self.sfv(),
            Style::Bsd => self.bsd(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::value::HashAlgorithm;

    use super::*;

    #[test]
    fn sfv_style_checksum() {
        let checksum =
            Checksum::compute(&HashAlgorithm::Blake2b, (Path::new("-"), b"Hello, world!"));

        assert_eq!(checksum.output(&Style::Sfv),"a2764d133a16816b5847a737a786f2ece4c148095c5faa73e24b4cc5d666c3e45ec271504e14dc6127ddfce4e144fb23b91a6f7b04b53d695502290722953b0f  -");
    }

    #[test]
    fn bsd_style_checksum() {
        let checksum =
            Checksum::compute(&HashAlgorithm::Blake2b, (Path::new("-"), b"Hello, world!"));

        assert_eq!(checksum.output(&Style::Bsd),"BLAKE2b (-) = a2764d133a16816b5847a737a786f2ece4c148095c5faa73e24b4cc5d666c3e45ec271504e14dc6127ddfce4e144fb23b91a6f7b04b53d695502290722953b0f");
    }
}
