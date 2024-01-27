// Copyright 2019-2024 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[clap(
    name = "openpgp-ca-restd",
    author = "Heiko Schäfer <heiko@schaefer.name>",
    version,
    about = "OpenPGP CA REST daemon."
)]
pub struct RestdCli {
    #[clap(name = "filename", short = 'd', long = "database")]
    pub database: Option<String>,

    #[clap(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run restd
    Run,
}
