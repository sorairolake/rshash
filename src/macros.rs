//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2021 Shun Sakai
//

#[macro_export]
macro_rules! regex {
    ($regex:literal $(,)?) => {{
        static REGEX: once_cell::sync::OnceCell<regex::Regex> = once_cell::sync::OnceCell::new();

        REGEX.get_or_init(|| {
            regex::Regex::new($regex).expect("Failed to compile a regular expression")
        })
    }};
}

#[macro_export]
macro_rules! long_version {
    () => {{
        static LONG_VERSION: once_cell::sync::OnceCell<String> = once_cell::sync::OnceCell::new();

        LONG_VERSION.get_or_init(|| {
            let head = if let (Some(sha_short), Some(commit_date)) = (
                option_env!("VERGEN_GIT_SHA_SHORT"),
                option_env!("VERGEN_GIT_COMMIT_DATE"),
            ) {
                format!(
                    "{} ({} {})",
                    env!("CARGO_PKG_VERSION"),
                    sha_short,
                    commit_date
                )
            } else {
                env!("CARGO_PKG_VERSION").to_string()
            };
            format!(
                "{}\n\n{}\n{}\n\n{}",
                head,
                "Copyright (C) 2021 Shun Sakai",
                "License: GNU General Public License v3.0 or later",
                "Report bugs to https://github.com/sorairolake/rshash/issues"
            )
        })
    }};
}
