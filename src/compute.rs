//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::path::Path;

use blake2::{Blake2b, Blake2s};
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

use crate::value::{Checksum, HashAlgorithm};

impl Checksum {
    /// Compute BLAKE2b message digest.
    fn blake2b(data: &[u8]) -> String {
        use blake2::Digest;

        hex::encode(Blake2b::digest(data))
    }

    /// Compute BLAKE2s message digest.
    fn blake2s(data: &[u8]) -> String {
        use blake2::Digest;

        hex::encode(Blake2s::digest(data))
    }

    /// Compute SHA-256 message digest.
    fn sha256(data: &[u8]) -> String {
        use sha2::Digest;

        hex::encode(Sha256::digest(data))
    }

    /// Compute SHA-512 message digest.
    fn sha512(data: &[u8]) -> String {
        use sha2::Digest;

        hex::encode(Sha512::digest(data))
    }

    /// Compute SHA3-256 message digest.
    fn sha3_256(data: &[u8]) -> String {
        use sha3::Digest;

        hex::encode(Sha3_256::digest(data))
    }

    /// Compute SHA3-512 message digest.
    fn sha3_512(data: &[u8]) -> String {
        use sha3::Digest;

        hex::encode(Sha3_512::digest(data))
    }

    /// Compute message digest for the specified hash algorithm.
    pub fn compute(algo: &HashAlgorithm, input: (&Path, &[u8])) -> Self {
        let digest = match algo {
            HashAlgorithm::Blake2b => Self::blake2b(input.1),
            HashAlgorithm::Blake2s => Self::blake2s(input.1),
            HashAlgorithm::Sha256 => Self::sha256(input.1),
            HashAlgorithm::Sha512 => Self::sha512(input.1),
            HashAlgorithm::Sha3_256 => Self::sha3_256(input.1),
            HashAlgorithm::Sha3_512 => Self::sha3_512(input.1),
        };

        Checksum {
            algorithm: *algo,
            path: input.0.to_path_buf(),
            digest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_blake2b() {
        let checksum =
            Checksum::compute(&HashAlgorithm::Blake2b, (Path::new("-"), b"Hello, world!"));

        assert_eq!(checksum.digest,"a2764d133a16816b5847a737a786f2ece4c148095c5faa73e24b4cc5d666c3e45ec271504e14dc6127ddfce4e144fb23b91a6f7b04b53d695502290722953b0f");
    }

    #[test]
    fn verify_blake2s() {
        let checksum =
            Checksum::compute(&HashAlgorithm::Blake2s, (Path::new("-"), b"Hello, world!"));

        assert_eq!(
            checksum.digest,
            "30d8777f0e178582ec8cd2fcdc18af57c828ee2f89e978df52c8e7af078bd5cf"
        );
    }

    #[test]
    fn verify_sha256() {
        let checksum =
            Checksum::compute(&HashAlgorithm::Sha256, (Path::new("-"), b"Hello, world!"));

        assert_eq!(
            checksum.digest,
            "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
        );
    }

    #[test]
    fn verify_sha512() {
        let checksum =
            Checksum::compute(&HashAlgorithm::Sha512, (Path::new("-"), b"Hello, world!"));

        assert_eq!(checksum.digest,"c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421");
    }

    #[test]
    fn verify_sha3_256() {
        let checksum =
            Checksum::compute(&HashAlgorithm::Sha3_256, (Path::new("-"), b"Hello, world!"));

        assert_eq!(
            checksum.digest,
            "f345a219da005ebe9c1a1eaad97bbf38a10c8473e41d0af7fb617caa0c6aa722"
        );
    }

    #[test]
    fn verify_sha3_512() {
        let checksum =
            Checksum::compute(&HashAlgorithm::Sha3_512, (Path::new("-"), b"Hello, world!"));

        assert_eq!(checksum.digest,"8e47f1185ffd014d238fabd02a1a32defe698cbf38c037a90e3c0a0a32370fb52cbd641250508502295fcabcbf676c09470b27443868c8e5f70e26dc337288af");
    }
}
