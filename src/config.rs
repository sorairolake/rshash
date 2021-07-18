//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::Deserialize;
use structopt::clap::crate_name;

use crate::value::Style;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub style: Option<Style>,
}

impl Config {
    /// Get the path of the config file.
    pub fn path() -> Option<PathBuf> {
        ProjectDirs::from("", "", crate_name!())
            .map(|p| p.config_dir().join("config.toml"))
            .filter(|p| p.exists())
    }

    /// Read the config from the config file.
    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        let string = fs::read_to_string(path.as_ref()).with_context(|| {
            format!("Failed to read the config from {}", path.as_ref().display())
        })?;

        toml::from_str(&string).with_context(|| {
            format!(
                "Failed to parse the config from {}",
                path.as_ref().display()
            )
        })
    }
}
