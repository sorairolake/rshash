//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::env;
use std::io;
use std::path::Path;
use std::process::{Command, ExitStatus};

fn generate_man_page(
    source: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
) -> io::Result<ExitStatus> {
    let mut command = Command::new("asciidoctor");

    #[cfg(feature = "gost94")]
    command.args(["-a", "gost94"]);
    #[cfg(feature = "md2")]
    command.args(["-a", "md2"]);
    #[cfg(feature = "md4")]
    command.args(["-a", "md4"]);
    #[cfg(feature = "md-5")]
    command.args(["-a", "md-5"]);
    #[cfg(feature = "sha-1")]
    command.args(["-a", "sha-1"]);
    #[cfg(feature = "streebog")]
    command.args(["-a", "streebog"]);

    command
        .args(["-a", concat!("revnumber=", env!("CARGO_PKG_VERSION"))])
        .args(["-b", "manpage"])
        .args(["-D".as_ref(), out_dir.as_ref()])
        .arg(source.as_ref())
        .status()
}

fn main() {
    let out_dir =
        env::var_os("OUT_DIR").expect("OUT_DIR is not defined as an environment variable");

    let current_dir = env::current_dir().expect("Failed to get the current working directory");
    let man_dir = current_dir.join("doc/man");
    let man_page_sources = [
        man_dir.join("man1/rshash.1.adoc"),
        man_dir.join("man5/rshash-config.toml.5.adoc"),
    ];

    for man_page_source in &man_page_sources {
        println!("cargo:rerun-if-changed={}", man_page_source.display());

        match generate_man_page(man_page_source, &out_dir) {
            Ok(status) => {
                if !status.success() {
                    println!(
                        "cargo:warning={:?} was not generated (Asciidoctor failed: {})",
                        man_page_source
                            .file_stem()
                            .expect("Failed to extract the stem"),
                        status
                    );
                }
            }
            Err(error) => {
                println!(
                    "cargo:warning={:?} was not generated (failed to execute Asciidoctor: {})",
                    man_page_source
                        .file_stem()
                        .expect("Failed to extract the stem"),
                    error
                );
            }
        }
    }
}
