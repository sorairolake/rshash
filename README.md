# RSHash

[![CI](https://github.com/sorairolake/rshash/workflows/CI/badge.svg)](https://github.com/sorairolake/rshash/actions?query=workflow%3ACI)
[![Version](https://img.shields.io/crates/v/rshash)](https://crates.io/crates/rshash)
[![License](https://img.shields.io/crates/l/rshash)](https://www.gnu.org/licenses/gpl-3.0.html)

**RSHash** is a command-line utility for computing and checking various message
digests.

## Installation

### Via a package manager

| OS  | Method | Package                                     | Command                |
| --- | ------ | ------------------------------------------- | ---------------------- |
| Any | Cargo  | [`rshash`](https://crates.io/crates/rshash) | `cargo install rshash` |

### Via pre-built binaries

Pre-built binaries for Linux, macOS and Windows are available on the
[release page](https://github.com/sorairolake/rshash/releases).

### How to build and install

Please see [BUILD.adoc](BUILD.adoc).

## Usage

```text
RSHash 0.3.0
A utility for computing various message digests

USAGE:
    rshash [OPTIONS] [FILE]...

ARGS:
    <FILE>...    Input from <FILE>

OPTIONS:
    -H, --hash-algorithm <NAME>
            Specify hash algorithm [possible values: blake2b, blake2s, blake3, fsb160, fsb224,
            fsb256, fsb384, fsb512, gost, gost-crypto-pro, groestl224, groestl256, groestl384,
            groestl512, keccak224, keccak256, keccak384, keccak512, md2, md4, md5, ripemd160,
            ripemd256, ripemd320, sha1, sha224, sha256, sha384, sha512, sha3-224, sha3-256, sha3-
            384, sha3-512, shabal192, shabal224, shabal256, shabal384, shabal512, sm3, streebog256,
            streebog512, tiger, whirlpool]

        --list-hash-algorithms
            List supported hash algorithms

    -c, --check
            Read the checksums from the file and check them

        --ignore-missing
            Don't fail or report status for missing files

        --quiet
            Don't print OK for each successfully verified file

        --status
            Don't output anything, return the verification result as the exit status

        --strict
            Exit non-zero for improperly formatted checksum lines

    -w, --warn
            Warn about improperly formatted checksum lines

    -j, --json
            Output the verification result as JSON to stdout

    -p, --pretty
            Output as a pretty-printed JSON

    -o, --output <FILE>
            Output to <FILE> instead of stdout

    -s, --style <STYLE>
            Specify style of the checksums [default: sfv] [possible values: sfv, bsd, json]

    -T, --threads <NUM>
            Specify the number of threads to use [default: 0]

        --progress
            Display a progress bar for reporting progress

        --speed
            Print the processing speed

        --generate-completion <SHELL>
            Generate shell completion [possible values: bash, elvish, fish, powershell, zsh]

    -h, --help
            Print help information

    -V, --version
            Print version information

See rshash(1) for more details.
```

See [`rshash(1)`](doc/man/man1/rshash.1.adoc) for more details.

## Changelog

Please see [CHANGELOG.adoc](CHANGELOG.adoc).

## Configuration

If you want to change the default behavior, you can use the configuration file.

See [`rshash-config.toml(5)`](doc/man/man5/rshash-config.toml.5.adoc) for more
details.

## Contributing

Please see [CONTRIBUTING.adoc](CONTRIBUTING.adoc).

## License

Copyright (C) 2021 Shun Sakai (see [AUTHORS.adoc](AUTHORS.adoc))

This program is distributed under the terms of the _GNU General Public License
v3.0 or later_.

See [COPYING](COPYING) for more details.
