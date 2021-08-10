//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::path::Path;

use crate::value::{Checksum, HashAlgorithm};

impl Checksum {
    /// Compute message digest for the specified hash algorithm.
    pub fn digest<P: AsRef<Path>, T: AsRef<[u8]>>(algo: HashAlgorithm, input: (P, T)) -> Self {
        let digest = match algo {
            HashAlgorithm::Blake2b => {
                use blake2::{Blake2b, Digest};

                hex::encode(Blake2b::digest(input.1.as_ref()))
            }
            HashAlgorithm::Blake2s => {
                use blake2::{Blake2s, Digest};

                hex::encode(Blake2s::digest(input.1.as_ref()))
            }
            HashAlgorithm::Blake3 => hex::encode(blake3::hash(input.1.as_ref()).as_bytes()),
            HashAlgorithm::Gost => {
                use gost94::{Digest, Gost94Test};

                hex::encode(Gost94Test::digest(input.1.as_ref()))
            }
            HashAlgorithm::GostCryptoPro => {
                use gost94::{Digest, Gost94CryptoPro};

                hex::encode(Gost94CryptoPro::digest(input.1.as_ref()))
            }
            HashAlgorithm::Groestl224 => {
                use groestl::{Digest, Groestl224};

                hex::encode(Groestl224::digest(input.1.as_ref()))
            }
            HashAlgorithm::Groestl256 => {
                use groestl::{Digest, Groestl256};

                hex::encode(Groestl256::digest(input.1.as_ref()))
            }
            HashAlgorithm::Groestl384 => {
                use groestl::{Digest, Groestl384};

                hex::encode(Groestl384::digest(input.1.as_ref()))
            }
            HashAlgorithm::Groestl512 => {
                use groestl::{Digest, Groestl512};

                hex::encode(Groestl512::digest(input.1.as_ref()))
            }
            HashAlgorithm::Keccak224 => {
                use sha3::{Digest, Keccak224};

                hex::encode(Keccak224::digest(input.1.as_ref()))
            }
            HashAlgorithm::Keccak256 => {
                use sha3::{Digest, Keccak256};

                hex::encode(Keccak256::digest(input.1.as_ref()))
            }
            HashAlgorithm::Keccak384 => {
                use sha3::{Digest, Keccak384};

                hex::encode(Keccak384::digest(input.1.as_ref()))
            }
            HashAlgorithm::Keccak512 => {
                use sha3::{Digest, Keccak512};

                hex::encode(Keccak512::digest(input.1.as_ref()))
            }
            HashAlgorithm::Md2 => {
                use md2::{Digest, Md2};

                hex::encode(Md2::digest(input.1.as_ref()))
            }
            HashAlgorithm::Md4 => {
                use md4::{Digest, Md4};

                hex::encode(Md4::digest(input.1.as_ref()))
            }
            HashAlgorithm::Md5 => {
                use md5::{Digest, Md5};

                hex::encode(Md5::digest(input.1.as_ref()))
            }
            HashAlgorithm::Ripemd160 => {
                use ripemd160::{Digest, Ripemd160};

                hex::encode(Ripemd160::digest(input.1.as_ref()))
            }
            HashAlgorithm::Ripemd256 => {
                use ripemd256::{Digest, Ripemd256};

                hex::encode(Ripemd256::digest(input.1.as_ref()))
            }
            HashAlgorithm::Ripemd320 => {
                use ripemd320::{Digest, Ripemd320};

                hex::encode(Ripemd320::digest(input.1.as_ref()))
            }
            HashAlgorithm::Sha1 => {
                use sha1::{Digest, Sha1};

                hex::encode(Sha1::digest(input.1.as_ref()))
            }
            HashAlgorithm::Sha224 => {
                use sha2::{Digest, Sha224};

                hex::encode(Sha224::digest(input.1.as_ref()))
            }
            HashAlgorithm::Sha256 => {
                use sha2::{Digest, Sha256};

                hex::encode(Sha256::digest(input.1.as_ref()))
            }
            HashAlgorithm::Sha384 => {
                use sha2::{Digest, Sha384};

                hex::encode(Sha384::digest(input.1.as_ref()))
            }
            HashAlgorithm::Sha512 => {
                use sha2::{Digest, Sha512};

                hex::encode(Sha512::digest(input.1.as_ref()))
            }
            HashAlgorithm::Sha3_224 => {
                use sha3::{Digest, Sha3_224};

                hex::encode(Sha3_224::digest(input.1.as_ref()))
            }
            HashAlgorithm::Sha3_256 => {
                use sha3::{Digest, Sha3_256};

                hex::encode(Sha3_256::digest(input.1.as_ref()))
            }
            HashAlgorithm::Sha3_384 => {
                use sha3::{Digest, Sha3_384};

                hex::encode(Sha3_384::digest(input.1.as_ref()))
            }
            HashAlgorithm::Sha3_512 => {
                use sha3::{Digest, Sha3_512};

                hex::encode(Sha3_512::digest(input.1.as_ref()))
            }
            HashAlgorithm::Shabal192 => {
                use shabal::{Digest, Shabal192};

                hex::encode(Shabal192::digest(input.1.as_ref()))
            }
            HashAlgorithm::Shabal224 => {
                use shabal::{Digest, Shabal224};

                hex::encode(Shabal224::digest(input.1.as_ref()))
            }
            HashAlgorithm::Shabal256 => {
                use shabal::{Digest, Shabal256};

                hex::encode(Shabal256::digest(input.1.as_ref()))
            }
            HashAlgorithm::Shabal384 => {
                use shabal::{Digest, Shabal384};

                hex::encode(Shabal384::digest(input.1.as_ref()))
            }
            HashAlgorithm::Shabal512 => {
                use shabal::{Digest, Shabal512};

                hex::encode(Shabal512::digest(input.1.as_ref()))
            }
            HashAlgorithm::Sm3 => {
                use sm3::{Digest, Sm3};

                hex::encode(Sm3::digest(input.1.as_ref()))
            }
            HashAlgorithm::Streebog256 => {
                use streebog::{Digest, Streebog256};

                hex::encode(Streebog256::digest(input.1.as_ref()))
            }
            HashAlgorithm::Streebog512 => {
                use streebog::{Digest, Streebog512};

                hex::encode(Streebog512::digest(input.1.as_ref()))
            }
            HashAlgorithm::Tiger => {
                use tiger::{digest::Digest, Tiger};

                hex::encode(Tiger::digest(input.1.as_ref()))
            }
            HashAlgorithm::Whirlpool => {
                use whirlpool::{Digest, Whirlpool};

                hex::encode(Whirlpool::digest(input.1.as_ref()))
            }
        };

        Checksum {
            algorithm: Some(algo),
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
            Checksum::digest(HashAlgorithm::Blake2b, ("-", b"Hello, world!")).digest,
            "a2764d133a16816b5847a737a786f2ece4c148095c5faa73e24b4cc5d666c3e45ec271504e14dc6127ddfce4e144fb23b91a6f7b04b53d695502290722953b0f"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Blake2s, ("-", b"Hello, world!")).digest,
            "30d8777f0e178582ec8cd2fcdc18af57c828ee2f89e978df52c8e7af078bd5cf"
        );
    }

    #[test]
    fn verify_blake3() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Blake3, ("-", b"Hello, world!")).digest,
            "ede5c0b10f2ec4979c69b52f61e42ff5b413519ce09be0f14d098dcfe5f6f98d"
        );
    }

    #[test]
    fn verify_gost() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Gost, ("-", b"Hello, world!")).digest,
            "711e00e034a9254765f6270bd02b6badf9dfe380a16593eff6e1ef1eec7ca023"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::GostCryptoPro, ("-", b"Hello, world!")).digest,
            "c003abf7ee48c42fe23cad86d56d2c982461f94d46b109a9f6b2e960f583cf52"
        );
    }

    #[test]
    fn verify_groestl() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Groestl224, ("-", b"Hello, world!")).digest,
            "c6f16583ebfb2544969f673d1fb43d73a3a51cd6927cdc1b7ff5e20a"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Groestl256, ("-", b"Hello, world!")).digest,
            "63e4ab2044e38c1fb1725313f2229e038926af839c86eaf96553027d2c851e18"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Groestl384, ("-", b"Hello, world!")).digest,
            "fc49edd6b61c5630c6111e51b7b721ff18454e451f829498cc0d76018c11f9f13836545f5d61ac3209a2a9fb2b5cdcfd"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Groestl512, ("-", b"Hello, world!")).digest,
            "b60658e723a8eb1743823a8002175486bc24223ba3dc6d8cb435a948f6d2b9744ac9e307e1d38021ea18c4d536d28fc23491d7771a5a5b0d02ffad9a073dcc28"
        );
    }

    #[test]
    fn verify_keccak() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Keccak224, ("-", b"Hello, world!")).digest,
            "f89e15347fc711f25fc629f4ba60e3326643dc1daf5ae9c04e86961d"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Keccak256, ("-", b"Hello, world!")).digest,
            "b6e16d27ac5ab427a7f68900ac5559ce272dc6c37c82b3e052246c82244c50e4"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Keccak384, ("-", b"Hello, world!")).digest,
            "939e56d1f678b0b21f5c176ac1a5fed347a35c688cf64bd997bc57113b6ba6245149157665b7dd23358228dcda5803de"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Keccak512, ("-", b"Hello, world!")).digest,
            "101f353a4727cc94ef81613bb38a807ebc888e2061baa4f845c84cd3c317f3430fda3dbeb44010844b35bccc8e190061d05b4d002c709615275a44e18e494f0c"
        );
    }

    #[test]
    fn verify_md2() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Md2, ("-", b"Hello, world!")).digest,
            "8cca0e965edd0e223b744f9cedf8e141"
        );
    }

    #[test]
    fn verify_md4() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Md4, ("-", b"Hello, world!")).digest,
            "0abe9ee1f376caa1bcecad9042f16e73"
        );
    }

    #[test]
    fn verify_md5() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Md5, ("-", b"Hello, world!")).digest,
            "6cd3556deb0da54bca060b4c39479839"
        );
    }

    #[test]
    fn verify_ripemd() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Ripemd160, ("-", b"Hello, world!")).digest,
            "58262d1fbdbe4530d8865d3518c6d6e41002610f"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Ripemd256, ("-", b"Hello, world!")).digest,
            "4121b1d1e68be2c62719efbdc4321957074a9fd3f597cda5c90235a6a85061e5"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Ripemd320, ("-", b"Hello, world!")).digest,
            "38e0636b7efa3c6c3cce53a334f4ff12cfee2a9704cdf9c2e7d0fe0399cf6ee66a71babb49f5870d"
        );
    }

    #[test]
    fn verify_sha1() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha1, ("-", b"Hello, world!")).digest,
            "943a702d06f34599aee1f8da8ef9f7296031d699"
        );
    }

    #[test]
    fn verify_sha2() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha224, ("-", b"Hello, world!")).digest,
            "8552d8b7a7dc5476cb9e25dee69a8091290764b7f2a64fe6e78e9568"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha256, ("-", b"Hello, world!")).digest,
            "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha384, ("-", b"Hello, world!")).digest,
            "55bc556b0d2fe0fce582ba5fe07baafff035653638c7ac0d5494c2a64c0bea1cc57331c7c12a45cdbca7f4c34a089eeb"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha512, ("-", b"Hello, world!")).digest,
            "c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421"
        );
    }

    #[test]
    fn verify_sha3() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha3_224, ("-", b"Hello, world!")).digest,
            "6a33e22f20f16642697e8bd549ff7b759252ad56c05a1b0acc31dc69"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha3_256, ("-", b"Hello, world!")).digest,
            "f345a219da005ebe9c1a1eaad97bbf38a10c8473e41d0af7fb617caa0c6aa722"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha3_384, ("-", b"Hello, world!")).digest,
            "6ba9ea268965916f5937228dde678c202f9fe756a87d8b1b7362869583a45901fd1a27289d72fc0e3ff48b1b78827d3a"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha3_512, ("-", b"Hello, world!")).digest,
            "8e47f1185ffd014d238fabd02a1a32defe698cbf38c037a90e3c0a0a32370fb52cbd641250508502295fcabcbf676c09470b27443868c8e5f70e26dc337288af"
        );
    }

    #[test]
    fn verify_shabal() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Shabal192, ("-", b"Hello, world!")).digest,
            "5530ace9c4f72542da200b109f2f31acdfd0f5cb599917a6"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Shabal224, ("-", b"Hello, world!")).digest,
            "64e06cbe06f9822731bdd2a2cc8e01637202e2ecd3ef6b3360b873b5"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Shabal256, ("-", b"Hello, world!")).digest,
            "e58d8d764ad4db5e716df1840283681a4010a77dfe59b494fc7ac9fc8c64af76"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Shabal384, ("-", b"Hello, world!")).digest,
            "bfae21d6dcb252249f8df385dfa4382bb34748c81854a42c8ed947f57ee9102169f443560a72e553fb65d3f14fd54d35"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Shabal512, ("-", b"Hello, world!")).digest,
            "7048f0a589339d2d26890701ed3b2d1ed7c8dd1ac37fec517c7a8c39d5d51548e96ea8dfaceb5b99f9d1db3b18a7652e0412348ebfd61d32d755d6098bff8cb3"
        );
    }

    #[test]
    fn verify_sm3() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sm3, ("-", b"Hello, world!")).digest,
            "e3bca101b496880c3653dad85861d0e784b00a8c18f7574472d156060e9096bf"
        );
    }

    #[test]
    fn verify_streebog() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Streebog256, ("-", b"Hello, world!")).digest,
            "ccb6fae3553c101715da535328de718f6f6e412db8611a38025c510ac8f85aeb"
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Streebog512, ("-", b"Hello, world!")).digest,
            "a83352d35dc8f07ca8048e6752415e5e991527e29415ade0eaad6e48d67bf37b60dfd7bb4475cbcbe297ed016128391c312dfe3a00e0a9bd0e497389c888eedc"
        );
    }

    #[test]
    fn verify_tiger() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Tiger, ("-", b"Hello, world!")).digest,
            "b5e5dd73a5894236937084131bb845189cdc5477579b9f36"
        );
    }

    #[test]
    fn verify_whirlpool() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Whirlpool, ("-", b"Hello, world!")).digest,
            "a1a8703be5312b139b42eb331aa800ccaca0c34d58c6988e44f45489cfb16beb4b6bf0ce20be1db22a10b0e4bb680480a3d2429e6c483085453c098b65852495"
        );
    }
}
