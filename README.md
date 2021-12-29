# RSHash

[![CI](https://github.com/sorairolake/rshash/workflows/CI/badge.svg)](https://github.com/sorairolake/rshash/actions?query=workflow%3ACI)
[![Version](https://img.shields.io/crates/v/rshash)](https://crates.io/crates/rshash)
[![License](https://img.shields.io/crates/l/rshash)](https://www.gnu.org/licenses/gpl-3.0.html)

**RSHash** is a command-line utility for computing and checking various message digests.

## Installation

### Via a package manager

| OS  | Method | Package                                     | Command                |
| --- | ------ | ------------------------------------------- | ---------------------- |
| Any | Cargo  | [`rshash`](https://crates.io/crates/rshash) | `cargo install rshash` |

### Via pre-built binaries

Pre-built binaries for Linux, macOS and Windows are available on the [release page](https://github.com/sorairolake/rshash/releases).

### How to build and install

Please see [BUILD.adoc](BUILD.adoc).

## Usage

```text
RSHash 0.3.0
A utility for computing various message digests

USAGE:
    rshash [FLAGS] [OPTIONS] [FILE]...

FLAGS:
        --list-hash-algorithms    List supported hash algorithms
    -c, --check                   Read the checksums from the file and check them
        --ignore-missing          Don't fail or report status for missing files
        --quiet                   Don't print OK for each successfully verified file
        --status                  Don't output anything, return the verification result as the exit status
        --strict                  Exit non-zero for improperly formatted checksum lines
    -w, --warn                    Warn about improperly formatted checksum lines
    -j, --json                    Output the verification result as JSON to stdout
    -p, --pretty                  Output as a pretty-printed JSON
        --progress                Display a progress bar for reporting progress
        --speed                   Print the processing speed
    -h, --help                    Prints help information
    -V, --version                 Prints version information

OPTIONS:
    -H, --hash-algorithm <NAME>          Specify hash algorithm [possible values: BLAKE2b, BLAKE2s, BLAKE3, FSB-160,
                                         FSB-224, FSB-256, FSB-384, FSB-512, GOST, GOST-CryptoPro, Groestl-224, Groestl-
                                         256, Groestl-384, Groestl-512, Keccak-224, Keccak-256, Keccak-384,
                                         Keccak-512, MD2, MD4, MD5, RIPEMD-160, RIPEMD-256, RIPEMD-320, SHA1, SHA224,
                                         SHA256, SHA384, SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, Shabal-192,
                                         Shabal-224, Shabal-256, Shabal-384, Shabal-512, SM3, Streebog-256, Streebog-
                                         512, Tiger, Whirlpool]
    -o, --output <FILE>                  Output to <FILE> instead of stdout
    -s, --style <STYLE>                  Specify style of the checksums [default: SFV]  [possible values: SFV, BSD,
                                         JSON]
    -T, --threads <NUM>                  Specify the number of threads to use [default: 0]
        --generate-completion <SHELL>    Generate shell completion [possible values: zsh, bash, fish, powershell,
                                         elvish]

ARGS:
    <FILE>...    Input from <FILE>

See rshash(1) for more details.
```

See [`rshash(1)`](doc/man/man1/rshash.1.adoc) for more details.

## Changelog

Please see [CHANGELOG.adoc](CHANGELOG.adoc).

## Configuration

If you want to change the default behavior, you can use the configuration file.

See [`rshash-config.toml(5)`](doc/man/man5/rshash-config.toml.5.adoc) for more details.

## Contributing

Please see [CONTRIBUTING.adoc](CONTRIBUTING.adoc).

## License

Copyright (C) 2021 Shun Sakai (see [AUTHORS.adoc](AUTHORS.adoc))

This program is distributed under the terms of the _GNU General Public License v3.0 or later_.

See [COPYING](COPYING) for more details.
