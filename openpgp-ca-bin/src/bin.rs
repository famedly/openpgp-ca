// SPDX-FileCopyrightText: 2019-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use anyhow::Result;
use clap::{CommandFactory, FromArgMatches};
use openpgp_ca_lib::{pgp, Oca, Uninit};

mod cli;

fn find_one_empty_card(ident: &Option<String>) -> Result<String> {
    if let Some(ident) = ident {
        Ok(ident.clone())
    } else {
        // find suitable card
        let cards = openpgp_ca_lib::blank_cards()?;
        match cards.len() {
            0 => Err(anyhow::anyhow!("No blank OpenPGP card found")),
            1 => Ok(cards[0].clone()),
            _ => Err(anyhow::anyhow!(
                "Multiple blank OpenPGP cards found: {}",
                cards.join(" ")
            )),
        }
    }
}

fn find_one_matching_card(ident: &Option<String>, cert: &[u8]) -> Result<String> {
    if let Some(ident) = ident {
        Ok(ident.clone())
    } else {
        // find suitable card
        let cards = openpgp_ca_lib::matching_cards(cert)?;
        match cards.len() {
            0 => Err(anyhow::anyhow!("No matching OpenPGP card found")),
            1 => Ok(cards[0].clone()),
            _ => Err(anyhow::anyhow!(
                "Multiple matching OpenPGP cards found: {}",
                cards.join(" ")
            )),
        }
    }
}

fn main() -> Result<()> {
    let version = format!(
        "{} (openpgp-ca-lib {})",
        env!("CARGO_PKG_VERSION"),
        openpgp_ca_lib::VERSION,
    );

    let cli = cli::Cli::command().version(&*version);

    let c = cli::Cli::from_arg_matches(&cli.get_matches())?;
    let db = c.database.as_deref();

    // Handle init calls separately, here.
    // Setting up an OpenpgpCa instance differs from most other workflows.
    if let cli::Commands::Ca {
        cmd:
            cli::CaCommand::Init {
                domain,
                name,
                backend,
            },
    } = &c.cmd
    {
        let cau = Uninit::new(db)?;

        let ca = match backend {
            cli::Backend::Softkey => cau.init_softkey(domain, name.as_deref()),
            cli::Backend::Card {
                ident,
                pinpad,
                from_card,
                import,
                generate_on_card,
                public_key,
            } => {
                if *pinpad {
                    // FIXME:
                    // - extend syntax in database backend field: don't store PIN in pinpad mode
                    // - use pinpad for changing user PIN to its new value
                    // - use pinpad for signing operations

                    unimplemented!("pinpad mode is not implemented yet");
                }

                match (from_card, import, generate_on_card) {
                    (false, None, false) => {
                        // Generate key in CA, import to card, print private key
                        let ident = find_one_empty_card(ident)?;

                        println!("Initializing OpenPGP CA on card {ident}.");
                        println!();

                        let (ca, key) =
                            cau.init_card_generate_on_host(&ident, domain, name.as_deref())?;

                        println!("Generated new CA key:\n\n{key}");

                        Ok(ca)
                    }

                    (true, None, false) => {
                        // Initialize CA from existing card and pubkey file
                        // NOTE: unwrap is ok because clap requires "public_key" if "from_card"

                        let ca_cert = std::fs::read(public_key.as_ref().unwrap())?;
                        let ident = find_one_matching_card(ident, &ca_cert)?;

                        println!(
                            "Initializing OpenPGP CA from pre-configured OpenPGP card {ident}."
                        );
                        println!();

                        // This card is already initialized, ask for User PIN
                        let pin = rpassword::prompt_password(format!(
                            "Enter User PIN for OpenPGP card {ident}: "
                        ))?;
                        println!();

                        cau.init_card_import_card(&ident, &pin, domain, &ca_cert)
                    }
                    (false, Some(import), false) => {
                        // Initialize CA onto a blank card, from private CA key file
                        let ident = find_one_empty_card(ident)?;

                        println!("Initializing OpenPGP CA from existing key, on card {ident}.");
                        println!();

                        let ca_cert = std::fs::read(import)?;
                        cau.init_card_import_key(&ident, domain, &ca_cert)
                    }
                    (false, None, true) => {
                        // Generate key on card, make public key (and store it in DB)
                        let ident = find_one_empty_card(ident)?;

                        println!("Generate new OpenPGP CA key on card {ident}.");
                        println!();
                        println!("Note:");
                        println!("1) The private CA key will only exist on the card (you can't make a backup)");
                        println!("2) The randomness your OpenPGP card generates could be worse than your host computer's");
                        println!();

                        let mut line = String::new();
                        println!("Are you sure? (type 'yes' to continue)");
                        std::io::stdin().read_line(&mut line)?;
                        println!();

                        if line.trim().to_ascii_lowercase() == "yes" {
                            cau.init_card_generate_on_card(&ident, domain, name.as_deref(), None)
                        } else {
                            Err(anyhow::anyhow!("Aborted CA initialization."))
                        }
                    }
                    _ => {
                        // Clap should enforce that this is unreachable (with the group "mode")
                        unreachable!()
                    }
                }
            }
        }?;

        println!("Initialized OpenPGP CA instance:\n");
        ca.ca_show()?;

        return Ok(());
    }

    // Handle migrate calls separately, here.
    // Migrating an OpenpgpCa instance differs from most other workflows.
    if let cli::Commands::Ca {
        cmd: cli::CaCommand::Migrate { backend },
    } = &c.cmd
    {
        match backend {
            cli::MigrateCommand::Card { ident, pinpad: _ } => {
                let ident = find_one_empty_card(ident)?;

                println!("Migrating OpenPGP CA instance to card {ident}.");
                println!();
                println!(
                    "Caution: After migration is performed, the CA private key material will not"
                );
                println!("be available in the CA database anymore!");
                println!();
                println!("Make sure you have a backup of your CA key before continuing!");
                println!();

                let mut line = String::new();
                println!("Are you sure? (type 'yes' to continue)");
                std::io::stdin().read_line(&mut line)?;
                println!();

                if line.trim().to_ascii_lowercase() == "yes" {
                    let cau = Uninit::new(db)?;
                    let ca = cau.migrate_card_import_key(&ident)?;

                    println!("Migrated OpenPGP CA instance:\n");
                    ca.ca_show()?;
                } else {
                    return Err(anyhow::anyhow!("Aborted CA migration."));
                }

                return Ok(());
            }
        }
    }

    // The CLI command was not `ca init` or `ca migrate`, so we should be able to directly open
    // the database as an Oca object
    let ca = Oca::open(db)?;

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
                    Oca::print_expiry_status(&ca, days)?;
                }
                cli::UserCheckSubcommand::Certifications => {
                    Oca::print_certifications_status(&ca)?;
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
            cli::UserCommand::List => Oca::print_users(&ca)?,
            cli::UserCommand::ShowRevocations { email } => Oca::print_revocations(&ca, &email)?,
            cli::UserCommand::ApplyRevocation { hash } => {
                let rev = ca.revocation_get_by_hash(&hash)?;
                ca.revocation_apply(rev)?;
            }
        },
        cli::Commands::Ca { cmd } => match cmd {
            cli::CaCommand::Init { .. } | cli::CaCommand::Migrate { .. } => {
                // handled separately, above
                unreachable!()
            }
            cli::CaCommand::SetBackend { backend } => match backend {
                cli::SetBackendCommand::Card { ident, pinpad: _ } => {
                    let ca_cert = ca.ca_get_pubkey_armored()?;

                    let ident = find_one_matching_card(&ident, ca_cert.as_bytes())?;

                    // This card is already initialized, ask for User PIN
                    let user_pin = rpassword::prompt_password(format!(
                        "Enter User PIN for OpenPGP card {ident}: "
                    ))?;
                    println!();

                    ca.set_card_backend(&ident, &user_pin)?;
                    println!("CA backend configuration is changed.");
                }
            },
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

            cli::CaCommand::Split { cmd } => match cmd {
                cli::SplitCommand::Into { front, back } => ca.ca_split_into(&front, &back)?,
                cli::SplitCommand::Merge { back } => ca.ca_merge_split(&back)?,

                cli::SplitCommand::Export { file } => ca.ca_split_export(file)?,

                cli::SplitCommand::Certify { import, export } => {
                    ca.ca_split_certify(import, export)?
                }

                cli::SplitCommand::Import { import: file } => ca.ca_split_import(file)?,

                cli::SplitCommand::ShowQueue {} => ca.ca_split_show_queue()?,
            },
        },
        cli::Commands::Bridge { cmd } => match cmd {
            cli::BridgeCommand::New {
                email,
                scope,
                remote_key_file,
                commit,
            } => {
                if commit {
                    let (email, fp) =
                        ca.add_bridge(email.as_deref(), &remote_key_file, scope.as_deref(), false)?;

                    println!("Added OpenPGP key for {} as bridge.\n", email);
                    println!("The fingerprint of the remote CA key is");
                    println!("{fp}\n");
                } else {
                    println!("Bridge creation DRY RUN.");
                    println!();

                    println!(
                        "Please verify that this is the correct fingerprint for the \
            remote CA admin before continuing:"
                    );
                    println!();

                    let key = std::fs::read(remote_key_file)?;
                    pgp::print_cert_info(&key)?;

                    println!();
                    println!(
                        "When you've confirmed that the remote key is correct, repeat \
            this command with the additional parameter '--commit' \
            to commit the OpenPGP CA bridge to the database."
                    );
                }
            }
            cli::BridgeCommand::Revoke { email } => ca.bridge_revoke(&email)?,
            cli::BridgeCommand::List => ca.list_bridges()?,
            cli::BridgeCommand::Export { email } => ca.print_bridges(email)?,
        },
        cli::Commands::Wkd { cmd } => match cmd {
            cli::WkdCommand::Export { path } => {
                ca.export_wkd(ca.domainname(), &path)?;
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
