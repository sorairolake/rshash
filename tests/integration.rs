//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use assert_cmd::Command;
use predicates::prelude::*;

fn command() -> Command {
    let mut command = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    command.current_dir("tests/");

    command
}

#[test]
#[cfg(unix)]
fn sfv_style_output() {
    command()
        .arg("-H")
        .arg("blake2b")
        .arg("-s")
        .arg("sfv")
        .write_stdin("Hello, world!")
        .assert()
        .stdout(predicate::eq(include_str!("resource/checksum/sfv.b2b")));
}

#[test]
#[cfg(unix)]
fn bsd_style_output() {
    command()
        .arg("-H")
        .arg("blake2b")
        .arg("-s")
        .arg("bsd")
        .write_stdin("Hello, world!")
        .assert()
        .stdout(predicate::eq(include_str!("resource/checksum/bsd.b2b")));
}

#[test]
#[cfg(unix)]
fn json_style_output() {
    command()
        .arg("-H")
        .arg("blake2b")
        .arg("-s")
        .arg("json")
        .write_stdin("Hello, world!")
        .assert()
        .stdout(predicate::eq(include_str!("resource/checksum/json.b2b")));
}

#[test]
fn verification_success() {
    command()
        .arg("-c")
        .arg("-H")
        .arg("blake2b")
        .arg("resource/checksum/sfv.b2b")
        .write_stdin("Hello, world!")
        .assert()
        .success()
        .stderr(predicate::str::contains("Everything is successful"));
}

#[test]
fn verification_failure() {
    command()
        .arg("-c")
        .arg("-H")
        .arg("blake2b")
        .arg("resource/checksum/sfv.b2b")
        .write_stdin("hELLO, WORLD!")
        .assert()
        .failure()
        .stdout(predicate::str::contains("FAILED"));
}
