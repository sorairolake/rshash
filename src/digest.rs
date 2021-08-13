//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::path::Path;

use crate::value::{Checksum, HashAlgorithm};

impl Checksum {
    /// Compute message digest for the specified hash algorithm.
    pub fn digest<P: AsRef<Path>, T: AsRef<[u8]>>(algorithm: HashAlgorithm, input: (P, T)) -> Self {
        let digest = match algorithm {
            HashAlgorithm::Blake2b => {
                use blake2::{Blake2b, Digest};

                Blake2b::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Blake2s => {
                use blake2::{Blake2s, Digest};

                Blake2s::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Blake3 => blake3::hash(input.1.as_ref()).as_bytes().to_vec(),
            HashAlgorithm::Gost => {
                use gost94::{Digest, Gost94Test};

                Gost94Test::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::GostCryptoPro => {
                use gost94::{Digest, Gost94CryptoPro};

                Gost94CryptoPro::digest(input.1.as_ref())
                    .as_slice()
                    .to_vec()
            }
            HashAlgorithm::Groestl224 => {
                use groestl::{Digest, Groestl224};

                Groestl224::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Groestl256 => {
                use groestl::{Digest, Groestl256};

                Groestl256::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Groestl384 => {
                use groestl::{Digest, Groestl384};

                Groestl384::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Groestl512 => {
                use groestl::{Digest, Groestl512};

                Groestl512::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Keccak224 => {
                use sha3::{Digest, Keccak224};

                Keccak224::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Keccak256 => {
                use sha3::{Digest, Keccak256};

                Keccak256::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Keccak384 => {
                use sha3::{Digest, Keccak384};

                Keccak384::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Keccak512 => {
                use sha3::{Digest, Keccak512};

                Keccak512::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Md2 => {
                use md2::{Digest, Md2};

                Md2::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Md4 => {
                use md4::{Digest, Md4};

                Md4::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Md5 => {
                use md5::{Digest, Md5};

                Md5::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Ripemd160 => {
                use ripemd160::{Digest, Ripemd160};

                Ripemd160::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Ripemd256 => {
                use ripemd256::{Digest, Ripemd256};

                Ripemd256::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Ripemd320 => {
                use ripemd320::{Digest, Ripemd320};

                Ripemd320::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Sha1 => {
                use sha1::{Digest, Sha1};

                Sha1::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Sha224 => {
                use sha2::{Digest, Sha224};

                Sha224::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Sha256 => {
                use sha2::{Digest, Sha256};

                Sha256::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Sha384 => {
                use sha2::{Digest, Sha384};

                Sha384::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Sha512 => {
                use sha2::{Digest, Sha512};

                Sha512::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Sha3_224 => {
                use sha3::{Digest, Sha3_224};

                Sha3_224::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Sha3_256 => {
                use sha3::{Digest, Sha3_256};

                Sha3_256::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Sha3_384 => {
                use sha3::{Digest, Sha3_384};

                Sha3_384::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Sha3_512 => {
                use sha3::{Digest, Sha3_512};

                Sha3_512::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Shabal192 => {
                use shabal::{Digest, Shabal192};

                Shabal192::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Shabal224 => {
                use shabal::{Digest, Shabal224};

                Shabal224::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Shabal256 => {
                use shabal::{Digest, Shabal256};

                Shabal256::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Shabal384 => {
                use shabal::{Digest, Shabal384};

                Shabal384::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Shabal512 => {
                use shabal::{Digest, Shabal512};

                Shabal512::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Sm3 => {
                use sm3::{Digest, Sm3};

                Sm3::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Streebog256 => {
                use streebog::{Digest, Streebog256};

                Streebog256::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Streebog512 => {
                use streebog::{Digest, Streebog512};

                Streebog512::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Tiger => {
                use tiger::{digest::Digest, Tiger};

                Tiger::digest(input.1.as_ref()).as_slice().to_vec()
            }
            HashAlgorithm::Whirlpool => {
                use whirlpool::{Digest, Whirlpool};

                Whirlpool::digest(input.1.as_ref()).as_slice().to_vec()
            }
        };

        Checksum {
            algorithm: Some(algorithm),
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
            [
                162, 118, 77, 19, 58, 22, 129, 107, 88, 71, 167, 55, 167, 134, 242, 236, 228, 193,
                72, 9, 92, 95, 170, 115, 226, 75, 76, 197, 214, 102, 195, 228, 94, 194, 113, 80,
                78, 20, 220, 97, 39, 221, 252, 228, 225, 68, 251, 35, 185, 26, 111, 123, 4, 181,
                61, 105, 85, 2, 41, 7, 34, 149, 59, 15
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Blake2s, ("-", b"Hello, world!")).digest,
            [
                48, 216, 119, 127, 14, 23, 133, 130, 236, 140, 210, 252, 220, 24, 175, 87, 200, 40,
                238, 47, 137, 233, 120, 223, 82, 200, 231, 175, 7, 139, 213, 207
            ]
        );
    }

    #[test]
    fn verify_blake3() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Blake3, ("-", b"Hello, world!")).digest,
            [
                237, 229, 192, 177, 15, 46, 196, 151, 156, 105, 181, 47, 97, 228, 47, 245, 180, 19,
                81, 156, 224, 155, 224, 241, 77, 9, 141, 207, 229, 246, 249, 141
            ]
        );
    }

    #[test]
    fn verify_gost() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Gost, ("-", b"Hello, world!")).digest,
            [
                113, 30, 0, 224, 52, 169, 37, 71, 101, 246, 39, 11, 208, 43, 107, 173, 249, 223,
                227, 128, 161, 101, 147, 239, 246, 225, 239, 30, 236, 124, 160, 35
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::GostCryptoPro, ("-", b"Hello, world!")).digest,
            [
                192, 3, 171, 247, 238, 72, 196, 47, 226, 60, 173, 134, 213, 109, 44, 152, 36, 97,
                249, 77, 70, 177, 9, 169, 246, 178, 233, 96, 245, 131, 207, 82
            ]
        );
    }

    #[test]
    fn verify_groestl() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Groestl224, ("-", b"Hello, world!")).digest,
            [
                198, 241, 101, 131, 235, 251, 37, 68, 150, 159, 103, 61, 31, 180, 61, 115, 163,
                165, 28, 214, 146, 124, 220, 27, 127, 245, 226, 10
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Groestl256, ("-", b"Hello, world!")).digest,
            [
                99, 228, 171, 32, 68, 227, 140, 31, 177, 114, 83, 19, 242, 34, 158, 3, 137, 38,
                175, 131, 156, 134, 234, 249, 101, 83, 2, 125, 44, 133, 30, 24
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Groestl384, ("-", b"Hello, world!")).digest,
            [
                252, 73, 237, 214, 182, 28, 86, 48, 198, 17, 30, 81, 183, 183, 33, 255, 24, 69, 78,
                69, 31, 130, 148, 152, 204, 13, 118, 1, 140, 17, 249, 241, 56, 54, 84, 95, 93, 97,
                172, 50, 9, 162, 169, 251, 43, 92, 220, 253
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Groestl512, ("-", b"Hello, world!")).digest,
            [
                182, 6, 88, 231, 35, 168, 235, 23, 67, 130, 58, 128, 2, 23, 84, 134, 188, 36, 34,
                59, 163, 220, 109, 140, 180, 53, 169, 72, 246, 210, 185, 116, 74, 201, 227, 7, 225,
                211, 128, 33, 234, 24, 196, 213, 54, 210, 143, 194, 52, 145, 215, 119, 26, 90, 91,
                13, 2, 255, 173, 154, 7, 61, 204, 40
            ]
        );
    }

    #[test]
    fn verify_keccak() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Keccak224, ("-", b"Hello, world!")).digest,
            [
                248, 158, 21, 52, 127, 199, 17, 242, 95, 198, 41, 244, 186, 96, 227, 50, 102, 67,
                220, 29, 175, 90, 233, 192, 78, 134, 150, 29
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Keccak256, ("-", b"Hello, world!")).digest,
            [
                182, 225, 109, 39, 172, 90, 180, 39, 167, 246, 137, 0, 172, 85, 89, 206, 39, 45,
                198, 195, 124, 130, 179, 224, 82, 36, 108, 130, 36, 76, 80, 228
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Keccak384, ("-", b"Hello, world!")).digest,
            [
                147, 158, 86, 209, 246, 120, 176, 178, 31, 92, 23, 106, 193, 165, 254, 211, 71,
                163, 92, 104, 140, 246, 75, 217, 151, 188, 87, 17, 59, 107, 166, 36, 81, 73, 21,
                118, 101, 183, 221, 35, 53, 130, 40, 220, 218, 88, 3, 222
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Keccak512, ("-", b"Hello, world!")).digest,
            [
                16, 31, 53, 58, 71, 39, 204, 148, 239, 129, 97, 59, 179, 138, 128, 126, 188, 136,
                142, 32, 97, 186, 164, 248, 69, 200, 76, 211, 195, 23, 243, 67, 15, 218, 61, 190,
                180, 64, 16, 132, 75, 53, 188, 204, 142, 25, 0, 97, 208, 91, 77, 0, 44, 112, 150,
                21, 39, 90, 68, 225, 142, 73, 79, 12
            ]
        );
    }

    #[test]
    fn verify_md2() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Md2, ("-", b"Hello, world!")).digest,
            [140, 202, 14, 150, 94, 221, 14, 34, 59, 116, 79, 156, 237, 248, 225, 65]
        );
    }

    #[test]
    fn verify_md4() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Md4, ("-", b"Hello, world!")).digest,
            [10, 190, 158, 225, 243, 118, 202, 161, 188, 236, 173, 144, 66, 241, 110, 115]
        );
    }

    #[test]
    fn verify_md5() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Md5, ("-", b"Hello, world!")).digest,
            [108, 211, 85, 109, 235, 13, 165, 75, 202, 6, 11, 76, 57, 71, 152, 57]
        );
    }

    #[test]
    fn verify_ripemd() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Ripemd160, ("-", b"Hello, world!")).digest,
            [
                88, 38, 45, 31, 189, 190, 69, 48, 216, 134, 93, 53, 24, 198, 214, 228, 16, 2, 97,
                15
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Ripemd256, ("-", b"Hello, world!")).digest,
            [
                65, 33, 177, 209, 230, 139, 226, 198, 39, 25, 239, 189, 196, 50, 25, 87, 7, 74,
                159, 211, 245, 151, 205, 165, 201, 2, 53, 166, 168, 80, 97, 229
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Ripemd320, ("-", b"Hello, world!")).digest,
            [
                56, 224, 99, 107, 126, 250, 60, 108, 60, 206, 83, 163, 52, 244, 255, 18, 207, 238,
                42, 151, 4, 205, 249, 194, 231, 208, 254, 3, 153, 207, 110, 230, 106, 113, 186,
                187, 73, 245, 135, 13
            ]
        );
    }

    #[test]
    fn verify_sha1() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha1, ("-", b"Hello, world!")).digest,
            [
                148, 58, 112, 45, 6, 243, 69, 153, 174, 225, 248, 218, 142, 249, 247, 41, 96, 49,
                214, 153
            ]
        );
    }

    #[test]
    fn verify_sha2() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha224, ("-", b"Hello, world!")).digest,
            [
                133, 82, 216, 183, 167, 220, 84, 118, 203, 158, 37, 222, 230, 154, 128, 145, 41, 7,
                100, 183, 242, 166, 79, 230, 231, 142, 149, 104
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha256, ("-", b"Hello, world!")).digest,
            [
                49, 95, 91, 219, 118, 208, 120, 196, 59, 138, 192, 6, 78, 74, 1, 100, 97, 43, 31,
                206, 119, 200, 105, 52, 91, 252, 148, 199, 88, 148, 237, 211
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha384, ("-", b"Hello, world!")).digest,
            [
                85, 188, 85, 107, 13, 47, 224, 252, 229, 130, 186, 95, 224, 123, 170, 255, 240, 53,
                101, 54, 56, 199, 172, 13, 84, 148, 194, 166, 76, 11, 234, 28, 197, 115, 49, 199,
                193, 42, 69, 205, 188, 167, 244, 195, 74, 8, 158, 235
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha512, ("-", b"Hello, world!")).digest,
            [
                193, 82, 124, 216, 147, 193, 36, 119, 61, 129, 25, 17, 151, 12, 143, 230, 232, 87,
                214, 223, 93, 201, 34, 107, 216, 161, 96, 97, 76, 12, 217, 99, 164, 221, 234, 43,
                148, 187, 125, 54, 2, 30, 249, 216, 101, 213, 206, 162, 148, 168, 45, 212, 154, 11,
                178, 105, 245, 31, 110, 122, 87, 247, 148, 33
            ]
        );
    }

    #[test]
    fn verify_sha3() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha3_224, ("-", b"Hello, world!")).digest,
            [
                106, 51, 226, 47, 32, 241, 102, 66, 105, 126, 139, 213, 73, 255, 123, 117, 146, 82,
                173, 86, 192, 90, 27, 10, 204, 49, 220, 105
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha3_256, ("-", b"Hello, world!")).digest,
            [
                243, 69, 162, 25, 218, 0, 94, 190, 156, 26, 30, 170, 217, 123, 191, 56, 161, 12,
                132, 115, 228, 29, 10, 247, 251, 97, 124, 170, 12, 106, 167, 34
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha3_384, ("-", b"Hello, world!")).digest,
            [
                107, 169, 234, 38, 137, 101, 145, 111, 89, 55, 34, 141, 222, 103, 140, 32, 47, 159,
                231, 86, 168, 125, 139, 27, 115, 98, 134, 149, 131, 164, 89, 1, 253, 26, 39, 40,
                157, 114, 252, 14, 63, 244, 139, 27, 120, 130, 125, 58
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sha3_512, ("-", b"Hello, world!")).digest,
            [
                142, 71, 241, 24, 95, 253, 1, 77, 35, 143, 171, 208, 42, 26, 50, 222, 254, 105,
                140, 191, 56, 192, 55, 169, 14, 60, 10, 10, 50, 55, 15, 181, 44, 189, 100, 18, 80,
                80, 133, 2, 41, 95, 202, 188, 191, 103, 108, 9, 71, 11, 39, 68, 56, 104, 200, 229,
                247, 14, 38, 220, 51, 114, 136, 175
            ]
        );
    }

    #[test]
    fn verify_shabal() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Shabal192, ("-", b"Hello, world!")).digest,
            [
                85, 48, 172, 233, 196, 247, 37, 66, 218, 32, 11, 16, 159, 47, 49, 172, 223, 208,
                245, 203, 89, 153, 23, 166
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Shabal224, ("-", b"Hello, world!")).digest,
            [
                100, 224, 108, 190, 6, 249, 130, 39, 49, 189, 210, 162, 204, 142, 1, 99, 114, 2,
                226, 236, 211, 239, 107, 51, 96, 184, 115, 181
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Shabal256, ("-", b"Hello, world!")).digest,
            [
                229, 141, 141, 118, 74, 212, 219, 94, 113, 109, 241, 132, 2, 131, 104, 26, 64, 16,
                167, 125, 254, 89, 180, 148, 252, 122, 201, 252, 140, 100, 175, 118
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Shabal384, ("-", b"Hello, world!")).digest,
            [
                191, 174, 33, 214, 220, 178, 82, 36, 159, 141, 243, 133, 223, 164, 56, 43, 179, 71,
                72, 200, 24, 84, 164, 44, 142, 217, 71, 245, 126, 233, 16, 33, 105, 244, 67, 86,
                10, 114, 229, 83, 251, 101, 211, 241, 79, 213, 77, 53
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Shabal512, ("-", b"Hello, world!")).digest,
            [
                112, 72, 240, 165, 137, 51, 157, 45, 38, 137, 7, 1, 237, 59, 45, 30, 215, 200, 221,
                26, 195, 127, 236, 81, 124, 122, 140, 57, 213, 213, 21, 72, 233, 110, 168, 223,
                172, 235, 91, 153, 249, 209, 219, 59, 24, 167, 101, 46, 4, 18, 52, 142, 191, 214,
                29, 50, 215, 85, 214, 9, 139, 255, 140, 179
            ]
        );
    }

    #[test]
    fn verify_sm3() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Sm3, ("-", b"Hello, world!")).digest,
            [
                227, 188, 161, 1, 180, 150, 136, 12, 54, 83, 218, 216, 88, 97, 208, 231, 132, 176,
                10, 140, 24, 247, 87, 68, 114, 209, 86, 6, 14, 144, 150, 191
            ]
        );
    }

    #[test]
    fn verify_streebog() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Streebog256, ("-", b"Hello, world!")).digest,
            [
                204, 182, 250, 227, 85, 60, 16, 23, 21, 218, 83, 83, 40, 222, 113, 143, 111, 110,
                65, 45, 184, 97, 26, 56, 2, 92, 81, 10, 200, 248, 90, 235
            ]
        );
        assert_eq!(
            Checksum::digest(HashAlgorithm::Streebog512, ("-", b"Hello, world!")).digest,
            [
                168, 51, 82, 211, 93, 200, 240, 124, 168, 4, 142, 103, 82, 65, 94, 94, 153, 21, 39,
                226, 148, 21, 173, 224, 234, 173, 110, 72, 214, 123, 243, 123, 96, 223, 215, 187,
                68, 117, 203, 203, 226, 151, 237, 1, 97, 40, 57, 28, 49, 45, 254, 58, 0, 224, 169,
                189, 14, 73, 115, 137, 200, 136, 238, 220
            ]
        );
    }

    #[test]
    fn verify_tiger() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Tiger, ("-", b"Hello, world!")).digest,
            [
                181, 229, 221, 115, 165, 137, 66, 54, 147, 112, 132, 19, 27, 184, 69, 24, 156, 220,
                84, 119, 87, 155, 159, 54
            ]
        );
    }

    #[test]
    fn verify_whirlpool() {
        assert_eq!(
            Checksum::digest(HashAlgorithm::Whirlpool, ("-", b"Hello, world!")).digest,
            [
                161, 168, 112, 59, 229, 49, 43, 19, 155, 66, 235, 51, 26, 168, 0, 204, 172, 160,
                195, 77, 88, 198, 152, 142, 68, 244, 84, 137, 207, 177, 107, 235, 75, 107, 240,
                206, 32, 190, 29, 178, 42, 16, 176, 228, 187, 104, 4, 128, 163, 210, 66, 158, 108,
                72, 48, 133, 69, 60, 9, 139, 101, 133, 36, 149
            ]
        );
    }
}
