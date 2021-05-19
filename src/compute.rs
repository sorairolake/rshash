//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::path::Path;

use blake2::{Blake2b, Blake2s};
use groestl::{Groestl224, Groestl256, Groestl384, Groestl512};
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use whirlpool::Whirlpool;

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

    /// Compute BLAKE3 message digest.
    fn blake3(data: &[u8]) -> String {
        hex::encode(blake3::hash(data).as_bytes())
    }

    /// Compute Groestl-224 message digest.
    fn groestl224(data: &[u8]) -> String {
        use groestl::Digest;

        hex::encode(Groestl224::digest(data))
    }

    /// Compute Groestl-256 message digest.
    fn groestl256(data: &[u8]) -> String {
        use groestl::Digest;

        hex::encode(Groestl256::digest(data))
    }

    /// Compute Groestl-384 message digest.
    fn groestl384(data: &[u8]) -> String {
        use groestl::Digest;

        hex::encode(Groestl384::digest(data))
    }

    /// Compute Groestl-512 message digest.
    fn groestl512(data: &[u8]) -> String {
        use groestl::Digest;

        hex::encode(Groestl512::digest(data))
    }

    /// Compute SHA-224 message digest.
    fn sha224(data: &[u8]) -> String {
        use sha2::Digest;

        hex::encode(Sha224::digest(data))
    }

    /// Compute SHA-256 message digest.
    fn sha256(data: &[u8]) -> String {
        use sha2::Digest;

        hex::encode(Sha256::digest(data))
    }

    /// Compute SHA-384 message digest.
    fn sha384(data: &[u8]) -> String {
        use sha2::Digest;

        hex::encode(Sha384::digest(data))
    }

    /// Compute SHA-512 message digest.
    fn sha512(data: &[u8]) -> String {
        use sha2::Digest;

        hex::encode(Sha512::digest(data))
    }

    /// Compute SHA3-224 message digest.
    fn sha3_224(data: &[u8]) -> String {
        use sha3::Digest;

        hex::encode(Sha3_224::digest(data))
    }

    /// Compute SHA3-256 message digest.
    fn sha3_256(data: &[u8]) -> String {
        use sha3::Digest;

        hex::encode(Sha3_256::digest(data))
    }

    /// Compute SHA3-384 message digest.
    fn sha3_384(data: &[u8]) -> String {
        use sha3::Digest;

        hex::encode(Sha3_384::digest(data))
    }

    /// Compute SHA3-512 message digest.
    fn sha3_512(data: &[u8]) -> String {
        use sha3::Digest;

        hex::encode(Sha3_512::digest(data))
    }

    /// Compute Whirlpool message digest.
    fn whirlpool(data: &[u8]) -> String {
        use whirlpool::Digest;

        hex::encode(Whirlpool::digest(data))
    }

    /// Compute message digest for the specified hash algorithm.
    pub fn compute(algo: &HashAlgorithm, input: (&Path, &[u8])) -> Self {
        let digest = match algo {
            HashAlgorithm::Blake2b => Self::blake2b(input.1),
            HashAlgorithm::Blake2s => Self::blake2s(input.1),
            HashAlgorithm::Blake3 => Self::blake3(input.1),
            HashAlgorithm::Groestl224 => Self::groestl224(input.1),
            HashAlgorithm::Groestl256 => Self::groestl256(input.1),
            HashAlgorithm::Groestl384 => Self::groestl384(input.1),
            HashAlgorithm::Groestl512 => Self::groestl512(input.1),
            HashAlgorithm::Sha224 => Self::sha224(input.1),
            HashAlgorithm::Sha256 => Self::sha256(input.1),
            HashAlgorithm::Sha384 => Self::sha384(input.1),
            HashAlgorithm::Sha512 => Self::sha512(input.1),
            HashAlgorithm::Sha3_224 => Self::sha3_224(input.1),
            HashAlgorithm::Sha3_256 => Self::sha3_256(input.1),
            HashAlgorithm::Sha3_384 => Self::sha3_384(input.1),
            HashAlgorithm::Sha3_512 => Self::sha3_512(input.1),
            HashAlgorithm::Whirlpool => Self::whirlpool(input.1),
        };

        Checksum {
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

        assert_eq!(
            checksum.digest,
            "a2764d133a16816b5847a737a786f2ece4c148095c5faa73e24b4cc5d666c3e45ec271504e14dc6127ddfce4e144fb23b91a6f7b04b53d695502290722953b0f"
        );
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
    fn verify_blake3() {
        let checksum =
            Checksum::compute(&HashAlgorithm::Blake3, (Path::new("-"), b"Hello, world!"));

        assert_eq!(
            checksum.digest,
            "ede5c0b10f2ec4979c69b52f61e42ff5b413519ce09be0f14d098dcfe5f6f98d"
        );
    }

    #[test]
    fn verify_groestl224() {
        let checksum = Checksum::compute(
            &HashAlgorithm::Groestl224,
            (Path::new("-"), b"Hello, world!"),
        );

        assert_eq!(
            checksum.digest,
            "c6f16583ebfb2544969f673d1fb43d73a3a51cd6927cdc1b7ff5e20a"
        );
    }

    #[test]
    fn verify_groestl256() {
        let checksum = Checksum::compute(
            &HashAlgorithm::Groestl256,
            (Path::new("-"), b"Hello, world!"),
        );

        assert_eq!(
            checksum.digest,
            "63e4ab2044e38c1fb1725313f2229e038926af839c86eaf96553027d2c851e18"
        );
    }

    #[test]
    fn verify_groestl384() {
        let checksum = Checksum::compute(
            &HashAlgorithm::Groestl384,
            (Path::new("-"), b"Hello, world!"),
        );

        assert_eq!(
            checksum.digest,
            "fc49edd6b61c5630c6111e51b7b721ff18454e451f829498cc0d76018c11f9f13836545f5d61ac3209a2a9fb2b5cdcfd"
        );
    }

    #[test]
    fn verify_groestl512() {
        let checksum = Checksum::compute(
            &HashAlgorithm::Groestl512,
            (Path::new("-"), b"Hello, world!"),
        );

        assert_eq!(
            checksum.digest,
            "b60658e723a8eb1743823a8002175486bc24223ba3dc6d8cb435a948f6d2b9744ac9e307e1d38021ea18c4d536d28fc23491d7771a5a5b0d02ffad9a073dcc28"
        );
    }

    #[test]
    fn verify_sha224() {
        let checksum =
            Checksum::compute(&HashAlgorithm::Sha224, (Path::new("-"), b"Hello, world!"));

        assert_eq!(
            checksum.digest,
            "8552d8b7a7dc5476cb9e25dee69a8091290764b7f2a64fe6e78e9568"
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
    fn verify_sha384() {
        let checksum =
            Checksum::compute(&HashAlgorithm::Sha384, (Path::new("-"), b"Hello, world!"));

        assert_eq!(
            checksum.digest,
            "55bc556b0d2fe0fce582ba5fe07baafff035653638c7ac0d5494c2a64c0bea1cc57331c7c12a45cdbca7f4c34a089eeb"
        );
    }

    #[test]
    fn verify_sha512() {
        let checksum =
            Checksum::compute(&HashAlgorithm::Sha512, (Path::new("-"), b"Hello, world!"));

        assert_eq!(
            checksum.digest,
            "c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421"
        );
    }

    #[test]
    fn verify_sha3_224() {
        let checksum =
            Checksum::compute(&HashAlgorithm::Sha3_224, (Path::new("-"), b"Hello, world!"));

        assert_eq!(
            checksum.digest,
            "6a33e22f20f16642697e8bd549ff7b759252ad56c05a1b0acc31dc69"
        );
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
    fn verify_sha3_384() {
        let checksum =
            Checksum::compute(&HashAlgorithm::Sha3_384, (Path::new("-"), b"Hello, world!"));

        assert_eq!(
            checksum.digest,
            "6ba9ea268965916f5937228dde678c202f9fe756a87d8b1b7362869583a45901fd1a27289d72fc0e3ff48b1b78827d3a"
        );
    }

    #[test]
    fn verify_sha3_512() {
        let checksum =
            Checksum::compute(&HashAlgorithm::Sha3_512, (Path::new("-"), b"Hello, world!"));

        assert_eq!(
            checksum.digest,
            "8e47f1185ffd014d238fabd02a1a32defe698cbf38c037a90e3c0a0a32370fb52cbd641250508502295fcabcbf676c09470b27443868c8e5f70e26dc337288af"
        );
    }

    #[test]
    fn verify_whirlpool() {
        let checksum = Checksum::compute(
            &HashAlgorithm::Whirlpool,
            (Path::new("-"), b"Hello, world!"),
        );

        assert_eq!(
            checksum.digest,
            "a1a8703be5312b139b42eb331aa800ccaca0c34d58c6988e44f45489cfb16beb4b6bf0ce20be1db22a10b0e4bb680480a3d2429e6c483085453c098b65852495"
        );
    }
}
