// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(
    name = "openpgp-ca-restd",
    author = "Heiko Schäfer <heiko@schaefer.name>",
    about = "OpenPGP CA REST daemon."
)]
pub struct RestdCli {
    #[structopt(name = "filename", short = "d", long = "database")]
    pub database: Option<String>,

    #[structopt(subcommand)]
    pub cmd: Command,
}

#[derive(StructOpt, Debug)]
pub enum Command {
    /// Run restd
    Run,
}
