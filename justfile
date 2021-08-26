#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2021 Shun Sakai
#

alias all := default

# Run default recipe
default: build

# Build a package
@build:
    cargo build

# Check a package
@check:
    cargo check

# Run tests
@test:
    cargo test

# Run the code formatter
@fmt:
    cargo fmt

# Run the linter
@clippy:
    cargo clippy -- -D warnings

# Update README
@update-readme:
    csplit -s README.adoc '/^....$/' '{*}'
    sed -i -n 1p xx01
    cargo -q run -- -h >> xx01
    cat xx00 xx01 xx02 > README.adoc
    rm xx00 xx01 xx02
