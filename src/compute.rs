//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::path::Path;

use blake2::{Blake2b, Blake2s};
use gost94::{Gost94CryptoPro, Gost94Test};
use groestl::{Groestl224, Groestl256, Groestl384, Groestl512};
use md2::Md2;
use md4::Md4;
use md5::Md5;
use ripemd160::Ripemd160;
use ripemd320::Ripemd320;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Keccak224, Keccak256, Keccak384, Keccak512, Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use shabal::{Shabal192, Shabal224, Shabal256, Shabal384, Shabal512};
use streebog::{Streebog256, Streebog512};
use tiger::Tiger;
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

    /// Compute GOST message digest.
    fn gost(data: &[u8]) -> String {
        use gost94::Digest;

        hex::encode(Gost94Test::digest(data))
    }

    /// Compute GOST-CryptoPro message digest.
    fn gost_cryptopro(data: &[u8]) -> String {
        use gost94::Digest;

        hex::encode(Gost94CryptoPro::digest(data))
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

    /// Compute Keccak-224 message digest.
    fn keccak224(data: &[u8]) -> String {
        use sha3::Digest;

        hex::encode(Keccak224::digest(data))
    }

    /// Compute Keccak-256 message digest.
    fn keccak256(data: &[u8]) -> String {
        use sha3::Digest;

        hex::encode(Keccak256::digest(data))
    }

    /// Compute Keccak-384 message digest.
    fn keccak384(data: &[u8]) -> String {
        use sha3::Digest;

        hex::encode(Keccak384::digest(data))
    }

    /// Compute Keccak-512 message digest.
    fn keccak512(data: &[u8]) -> String {
        use sha3::Digest;

        hex::encode(Keccak512::digest(data))
    }

    /// Compute MD2 message digest.
    fn md2(data: &[u8]) -> String {
        use md2::Digest;

        hex::encode(Md2::digest(data))
    }

    /// Compute MD4 message digest.
    fn md4(data: &[u8]) -> String {
        use md4::Digest;

        hex::encode(Md4::digest(data))
    }

    /// Compute MD5 message digest.
    fn md5(data: &[u8]) -> String {
        use md5::Digest;

        hex::encode(Md5::digest(data))
    }

    /// Compute RIPEMD-160 message digest.
    fn ripemd160(data: &[u8]) -> String {
        use ripemd160::Digest;

        hex::encode(Ripemd160::digest(data))
    }

    /// Compute RIPEMD-320 message digest.
    fn ripemd320(data: &[u8]) -> String {
        use ripemd320::Digest;

        hex::encode(Ripemd320::digest(data))
    }

    /// Compute SHA-1 message digest.
    fn sha1(data: &[u8]) -> String {
        use sha1::Digest;

        hex::encode(Sha1::digest(data))
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

    /// Compute Shabal-192 message digest.
    fn shabal192(data: &[u8]) -> String {
        use shabal::Digest;

        hex::encode(Shabal192::digest(data))
    }

    /// Compute Shabal-224 message digest.
    fn shabal224(data: &[u8]) -> String {
        use shabal::Digest;

        hex::encode(Shabal224::digest(data))
    }

    /// Compute Shabal-256 message digest.
    fn shabal256(data: &[u8]) -> String {
        use shabal::Digest;

        hex::encode(Shabal256::digest(data))
    }

    /// Compute Shabal-384 message digest.
    fn shabal384(data: &[u8]) -> String {
        use shabal::Digest;

        hex::encode(Shabal384::digest(data))
    }

    /// Compute Shabal-512 message digest.
    fn shabal512(data: &[u8]) -> String {
        use shabal::Digest;

        hex::encode(Shabal512::digest(data))
    }

    /// Compute Streebog-256 message digest.
    fn streebog256(data: &[u8]) -> String {
        use streebog::Digest;

        hex::encode(Streebog256::digest(data))
    }

    /// Compute Streebog-512 message digest.
    fn streebog512(data: &[u8]) -> String {
        use streebog::Digest;

        hex::encode(Streebog512::digest(data))
    }

    /// Compute Tiger message digest.
    fn tiger(data: &[u8]) -> String {
        use tiger::digest::Digest;

        hex::encode(Tiger::digest(data))
    }

    /// Compute Whirlpool message digest.
    fn whirlpool(data: &[u8]) -> String {
        use whirlpool::Digest;

        hex::encode(Whirlpool::digest(data))
    }

    /// Compute message digest for the specified hash algorithm.
    pub fn compute<P: AsRef<Path>, S: AsRef<[u8]>>(algo: HashAlgorithm, input: (P, S)) -> Self {
        let digest = match algo {
            HashAlgorithm::Blake2b => Self::blake2b(input.1.as_ref()),
            HashAlgorithm::Blake2s => Self::blake2s(input.1.as_ref()),
            HashAlgorithm::Blake3 => Self::blake3(input.1.as_ref()),
            HashAlgorithm::Gost => Self::gost(input.1.as_ref()),
            HashAlgorithm::GostCryptoPro => Self::gost_cryptopro(input.1.as_ref()),
            HashAlgorithm::Groestl224 => Self::groestl224(input.1.as_ref()),
            HashAlgorithm::Groestl256 => Self::groestl256(input.1.as_ref()),
            HashAlgorithm::Groestl384 => Self::groestl384(input.1.as_ref()),
            HashAlgorithm::Groestl512 => Self::groestl512(input.1.as_ref()),
            HashAlgorithm::Keccak224 => Self::keccak224(input.1.as_ref()),
            HashAlgorithm::Keccak256 => Self::keccak256(input.1.as_ref()),
            HashAlgorithm::Keccak384 => Self::keccak384(input.1.as_ref()),
            HashAlgorithm::Keccak512 => Self::keccak512(input.1.as_ref()),
            HashAlgorithm::Md2 => Self::md2(input.1.as_ref()),
            HashAlgorithm::Md4 => Self::md4(input.1.as_ref()),
            HashAlgorithm::Md5 => Self::md5(input.1.as_ref()),
            HashAlgorithm::Ripemd160 => Self::ripemd160(input.1.as_ref()),
            HashAlgorithm::Ripemd320 => Self::ripemd320(input.1.as_ref()),
            HashAlgorithm::Sha1 => Self::sha1(input.1.as_ref()),
            HashAlgorithm::Sha224 => Self::sha224(input.1.as_ref()),
            HashAlgorithm::Sha256 => Self::sha256(input.1.as_ref()),
            HashAlgorithm::Sha384 => Self::sha384(input.1.as_ref()),
            HashAlgorithm::Sha512 => Self::sha512(input.1.as_ref()),
            HashAlgorithm::Sha3_224 => Self::sha3_224(input.1.as_ref()),
            HashAlgorithm::Sha3_256 => Self::sha3_256(input.1.as_ref()),
            HashAlgorithm::Sha3_384 => Self::sha3_384(input.1.as_ref()),
            HashAlgorithm::Sha3_512 => Self::sha3_512(input.1.as_ref()),
            HashAlgorithm::Shabal192 => Self::shabal192(input.1.as_ref()),
            HashAlgorithm::Shabal224 => Self::shabal224(input.1.as_ref()),
            HashAlgorithm::Shabal256 => Self::shabal256(input.1.as_ref()),
            HashAlgorithm::Shabal384 => Self::shabal384(input.1.as_ref()),
            HashAlgorithm::Shabal512 => Self::shabal512(input.1.as_ref()),
            HashAlgorithm::Streebog256 => Self::streebog256(input.1.as_ref()),
            HashAlgorithm::Streebog512 => Self::streebog512(input.1.as_ref()),
            HashAlgorithm::Tiger => Self::tiger(input.1.as_ref()),
            HashAlgorithm::Whirlpool => Self::whirlpool(input.1.as_ref()),
        };

        Checksum {
            file: input.0.as_ref().to_path_buf(),
            digest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_blake2() {
        assert_eq!(
            Checksum::compute(HashAlgorithm::Blake2b, ("-", b"Hello, world!")).digest,
            "a2764d133a16816b5847a737a786f2ece4c148095c5faa73e24b4cc5d666c3e45ec271504e14dc6127ddfce4e144fb23b91a6f7b04b53d695502290722953b0f"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Blake2s, ("-", b"Hello, world!")).digest,
            "30d8777f0e178582ec8cd2fcdc18af57c828ee2f89e978df52c8e7af078bd5cf"
        );
    }

    #[test]
    fn verify_blake3() {
        assert_eq!(
            Checksum::compute(HashAlgorithm::Blake3, ("-", b"Hello, world!")).digest,
            "ede5c0b10f2ec4979c69b52f61e42ff5b413519ce09be0f14d098dcfe5f6f98d"
        );
    }

    #[test]
    fn verify_gost() {
        assert_eq!(
            Checksum::compute(HashAlgorithm::Gost, ("-", b"Hello, world!")).digest,
            "711e00e034a9254765f6270bd02b6badf9dfe380a16593eff6e1ef1eec7ca023"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::GostCryptoPro, ("-", b"Hello, world!")).digest,
            "c003abf7ee48c42fe23cad86d56d2c982461f94d46b109a9f6b2e960f583cf52"
        );
    }

    #[test]
    fn verify_groestl() {
        assert_eq!(
            Checksum::compute(HashAlgorithm::Groestl224, ("-", b"Hello, world!")).digest,
            "c6f16583ebfb2544969f673d1fb43d73a3a51cd6927cdc1b7ff5e20a"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Groestl256, ("-", b"Hello, world!")).digest,
            "63e4ab2044e38c1fb1725313f2229e038926af839c86eaf96553027d2c851e18"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Groestl384, ("-", b"Hello, world!")).digest,
            "fc49edd6b61c5630c6111e51b7b721ff18454e451f829498cc0d76018c11f9f13836545f5d61ac3209a2a9fb2b5cdcfd"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Groestl512, ("-", b"Hello, world!")).digest,
            "b60658e723a8eb1743823a8002175486bc24223ba3dc6d8cb435a948f6d2b9744ac9e307e1d38021ea18c4d536d28fc23491d7771a5a5b0d02ffad9a073dcc28"
        );
    }

    #[test]
    fn verify_keccak() {
        assert_eq!(
            Checksum::compute(HashAlgorithm::Keccak224, ("-", b"Hello, world!")).digest,
            "f89e15347fc711f25fc629f4ba60e3326643dc1daf5ae9c04e86961d"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Keccak256, ("-", b"Hello, world!")).digest,
            "b6e16d27ac5ab427a7f68900ac5559ce272dc6c37c82b3e052246c82244c50e4"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Keccak384, ("-", b"Hello, world!")).digest,
            "939e56d1f678b0b21f5c176ac1a5fed347a35c688cf64bd997bc57113b6ba6245149157665b7dd23358228dcda5803de"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Keccak512, ("-", b"Hello, world!")).digest,
            "101f353a4727cc94ef81613bb38a807ebc888e2061baa4f845c84cd3c317f3430fda3dbeb44010844b35bccc8e190061d05b4d002c709615275a44e18e494f0c"
        );
    }

    #[test]
    fn verify_md2() {
        assert_eq!(
            Checksum::compute(HashAlgorithm::Md2, ("-", b"Hello, world!")).digest,
            "8cca0e965edd0e223b744f9cedf8e141"
        );
    }

    #[test]
    fn verify_md4() {
        assert_eq!(
            Checksum::compute(HashAlgorithm::Md4, ("-", b"Hello, world!")).digest,
            "0abe9ee1f376caa1bcecad9042f16e73"
        );
    }

    #[test]
    fn verify_md5() {
        assert_eq!(
            Checksum::compute(HashAlgorithm::Md5, ("-", b"Hello, world!")).digest,
            "6cd3556deb0da54bca060b4c39479839"
        );
    }

    #[test]
    fn verify_ripemd() {
        assert_eq!(
            Checksum::compute(HashAlgorithm::Ripemd160, ("-", b"Hello, world!")).digest,
            "58262d1fbdbe4530d8865d3518c6d6e41002610f"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Ripemd320, ("-", b"Hello, world!")).digest,
            "38e0636b7efa3c6c3cce53a334f4ff12cfee2a9704cdf9c2e7d0fe0399cf6ee66a71babb49f5870d"
        );
    }

    #[test]
    fn verify_sha1() {
        assert_eq!(
            Checksum::compute(HashAlgorithm::Sha1, ("-", b"Hello, world!")).digest,
            "943a702d06f34599aee1f8da8ef9f7296031d699"
        );
    }

    #[test]
    fn verify_sha2() {
        assert_eq!(
            Checksum::compute(HashAlgorithm::Sha224, ("-", b"Hello, world!")).digest,
            "8552d8b7a7dc5476cb9e25dee69a8091290764b7f2a64fe6e78e9568"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Sha256, ("-", b"Hello, world!")).digest,
            "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Sha384, ("-", b"Hello, world!")).digest,
            "55bc556b0d2fe0fce582ba5fe07baafff035653638c7ac0d5494c2a64c0bea1cc57331c7c12a45cdbca7f4c34a089eeb"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Sha512, ("-", b"Hello, world!")).digest,
            "c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421"
        );
    }

    #[test]
    fn verify_sha3() {
        assert_eq!(
            Checksum::compute(HashAlgorithm::Sha3_224, ("-", b"Hello, world!")).digest,
            "6a33e22f20f16642697e8bd549ff7b759252ad56c05a1b0acc31dc69"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Sha3_256, ("-", b"Hello, world!")).digest,
            "f345a219da005ebe9c1a1eaad97bbf38a10c8473e41d0af7fb617caa0c6aa722"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Sha3_384, ("-", b"Hello, world!")).digest,
            "6ba9ea268965916f5937228dde678c202f9fe756a87d8b1b7362869583a45901fd1a27289d72fc0e3ff48b1b78827d3a"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Sha3_512, ("-", b"Hello, world!")).digest,
            "8e47f1185ffd014d238fabd02a1a32defe698cbf38c037a90e3c0a0a32370fb52cbd641250508502295fcabcbf676c09470b27443868c8e5f70e26dc337288af"
        );
    }

    #[test]
    fn verify_shabal() {
        assert_eq!(
            Checksum::compute(HashAlgorithm::Shabal192, ("-", b"Hello, world!")).digest,
            "5530ace9c4f72542da200b109f2f31acdfd0f5cb599917a6"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Shabal224, ("-", b"Hello, world!")).digest,
            "64e06cbe06f9822731bdd2a2cc8e01637202e2ecd3ef6b3360b873b5"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Shabal256, ("-", b"Hello, world!")).digest,
            "e58d8d764ad4db5e716df1840283681a4010a77dfe59b494fc7ac9fc8c64af76"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Shabal384, ("-", b"Hello, world!")).digest,
            "bfae21d6dcb252249f8df385dfa4382bb34748c81854a42c8ed947f57ee9102169f443560a72e553fb65d3f14fd54d35"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Shabal512, ("-", b"Hello, world!")).digest,
            "7048f0a589339d2d26890701ed3b2d1ed7c8dd1ac37fec517c7a8c39d5d51548e96ea8dfaceb5b99f9d1db3b18a7652e0412348ebfd61d32d755d6098bff8cb3"
        );
    }

    #[test]
    fn verify_streebog() {
        assert_eq!(
            Checksum::compute(HashAlgorithm::Streebog256, ("-", b"Hello, world!")).digest,
            "ccb6fae3553c101715da535328de718f6f6e412db8611a38025c510ac8f85aeb"
        );
        assert_eq!(
            Checksum::compute(HashAlgorithm::Streebog512, ("-", b"Hello, world!")).digest,
            "a83352d35dc8f07ca8048e6752415e5e991527e29415ade0eaad6e48d67bf37b60dfd7bb4475cbcbe297ed016128391c312dfe3a00e0a9bd0e497389c888eedc"
        );
    }

    #[test]
    fn verify_tiger() {
        assert_eq!(
            Checksum::compute(HashAlgorithm::Tiger, ("-", b"Hello, world!")).digest,
            "b5e5dd73a5894236937084131bb845189cdc5477579b9f36"
        );
    }

    #[test]
    fn verify_whirlpool() {
        assert_eq!(
            Checksum::compute(HashAlgorithm::Whirlpool, ("-", b"Hello, world!")).digest,
            "a1a8703be5312b139b42eb331aa800ccaca0c34d58c6988e44f45489cfb16beb4b6bf0ce20be1db22a10b0e4bb680480a3d2429e6c483085453c098b65852495"
        );
    }
}
