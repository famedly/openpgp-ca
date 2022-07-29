// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use anyhow::Result;
use clap::{CommandFactory, FromArgMatches};

use openpgp_ca_lib::ca::OpenpgpCa;

mod cli;

fn main() -> Result<()> {
    let version = format!(
        "{} (openpgp-ca-lib {})",
        env!("CARGO_PKG_VERSION"),
        openpgp_ca_lib::VERSION,
    );

    let cli = cli::Cli::command().version(&*version);

    let c = cli::Cli::from_arg_matches(&cli.get_matches())?;

    let ca = OpenpgpCa::new(c.database.as_deref())?;

    match c.cmd {
        cli::Commands::User { cmd } => match cmd {
            cli::UserCommand::Add {
                email,
                name,
                minimal,
            } => {
                // TODO: key-profile?

                let emails: Vec<_> = email.iter().map(String::as_str).collect();

                ca.user_new(name.as_deref(), &emails[..], None, true, minimal)?;
            }
            cli::UserCommand::AddRevocation { revocation_file } => {
                ca.revocation_add_from_file(&revocation_file)?
            }

            cli::UserCommand::Check { cmd } => match cmd {
                cli::UserCheckSubcommand::Expiry { days } => {
                    OpenpgpCa::print_expiry_status(&ca, days)?;
                }
                cli::UserCheckSubcommand::Certifications => {
                    OpenpgpCa::print_certifications_status(&ca)?;
                }
            },
            cli::UserCommand::Import {
                cert_file,
                name,
                email,
                revocation_file,
            } => {
                let cert = std::fs::read(cert_file)?;

                let mut revoc_certs = Vec::new();
                for path in revocation_file {
                    let rev = std::fs::read(path)?;
                    revoc_certs.push(rev);
                }

                let emails: Vec<_> = email.iter().map(String::as_str).collect();

                ca.cert_import_new(
                    &cert,
                    revoc_certs
                        .iter()
                        .map(|v| v.as_slice())
                        .collect::<Vec<_>>()
                        .as_ref(),
                    name.as_deref(),
                    &emails,
                    None,
                )?;
            }
            cli::UserCommand::Update { cert_file } => {
                let cert = std::fs::read(cert_file)?;
                ca.cert_import_update(&cert)?;
            }
            cli::UserCommand::Export { email, path } => {
                if let Some(path) = path {
                    ca.export_certs_as_files(email, &path)?;
                } else {
                    ca.print_certring(email)?;
                }
            }
            cli::UserCommand::List => OpenpgpCa::print_users(&ca)?,
            cli::UserCommand::ShowRevocations { email } => {
                OpenpgpCa::print_revocations(&ca, &email)?
            }
            cli::UserCommand::ApplyRevocation { hash } => {
                let rev = ca.revocation_get_by_hash(&hash)?;
                ca.revocation_apply(rev)?;
            }
        },
        cli::Commands::Ca { cmd } => match cmd {
            cli::CaCommand::Init { domain, name } => {
                ca.ca_init(&domain, name.as_deref())?;
            }
            cli::CaCommand::Export => {
                println!("{}", ca.ca_get_pubkey_armored()?);
            }
            cli::CaCommand::Revocations { output } => {
                ca.ca_generate_revocations(output)?;
                println!("Wrote a set of revocations to the output file");
            }
            cli::CaCommand::ImportTsig { cert_file } => {
                let cert = std::fs::read(cert_file)?;
                ca.ca_import_tsig(&cert)?;
            }
            cli::CaCommand::Show => ca.ca_show()?,
            cli::CaCommand::Private => ca.ca_print_private()?,

            cli::CaCommand::ReCertify {
                pubkey_file_old: cert_file_old,
                validity_days,
            } => {
                let cert_old = std::fs::read(cert_file_old)?;
                ca.ca_re_certify(&cert_old, validity_days)?;
            }
        },
        cli::Commands::Bridge { cmd } => match cmd {
            cli::BridgeCommand::New {
                email,
                scope,
                remote_key_file,
                commit,
            } => ca.add_bridge(email.as_deref(), &remote_key_file, scope.as_deref(), commit)?,
            cli::BridgeCommand::Revoke { email } => ca.bridge_revoke(&email)?,
            cli::BridgeCommand::List => ca.list_bridges()?,
            cli::BridgeCommand::Export { email } => ca.print_bridges(email)?,
        },
        cli::Commands::Wkd { cmd } => match cmd {
            cli::WkdCommand::Export { path } => {
                ca.export_wkd(&ca.get_ca_domain()?, &path)?;
            }
        },

        cli::Commands::Keylist { cmd } => match cmd {
            cli::KeyListCommand::Export {
                path,
                signature_uri,
                force,
            } => {
                ca.export_keylist(path, signature_uri, force)?;
            }
        },
        cli::Commands::Update { cmd } => match cmd {
            cli::UpdateCommand::Keyserver {} => ca.update_from_keyserver()?,
            cli::UpdateCommand::Wkd {} => ca.update_from_wkd()?,
        },
    }

    Ok(())
}
