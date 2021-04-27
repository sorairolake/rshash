//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

mod cli;
mod value;

use std::fs;
use std::io::{self, Read};

use anyhow::{bail, Result};
use structopt::StructOpt;

use crate::cli::Opt;

fn main() -> Result<()> {
    let opt = Opt::from_args();

    let input = if opt.input.is_empty() {
        if atty::is(atty::Stream::Stdin) {
            bail!("Input from tty is invalid.")
        }
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        vec![buf]
    } else {
        let inputs: Result<Vec<_>, _> = opt.input.iter().map(fs::read_to_string).collect();
        inputs?
    };

    let opt = opt.process(&input[0]);

    match opt.output {
        Some(f) => fs::write(f, &input[0])?,
        None => print!("{}", input[0]),
    }

    Ok(())
}
