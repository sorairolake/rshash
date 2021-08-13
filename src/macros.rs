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
