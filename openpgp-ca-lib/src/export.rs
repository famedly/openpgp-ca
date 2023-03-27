// Copyright 2019-2022 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result};
use openpgp_keylist::{Key, Keylist, Metadata};

use crate::pgp;
use crate::Oca;

// export filename of keylist
const KEYLIST_FILE: &str = "keylist.json";

/// Write all Certs to stdout as one armored certring (or a subset of certs,
/// filtered by User ID via email)
pub fn print_certring(oca: &Oca, email_filter: Option<String>) -> Result<()> {
    // Load all user-certs (optionally filtered by email)
    let certs = match &email_filter {
        Some(email) => oca.certs_by_email(email)?,
        None => oca.user_certs_get_all()?,
    };

    let mut c = Vec::new();

    // add CA cert if no filter has been set
    if email_filter.is_none() {
        c.push(oca.ca_get_cert_pub()?);
    }

    for cert in certs {
        c.push(pgp::to_cert(cert.pub_cert.as_bytes())?);
    }

    println!("{}", pgp::certs_to_armored(&c)?);

    Ok(())
}

/// Export Certs to filesystem, as individual files split and named by email.
/// (Optionally: filter by User ID via list of emails)
pub fn export_certs_as_files(oca: &Oca, email_filter: Option<String>, path: &str) -> Result<()> {
    // export CA cert
    if email_filter.is_none() {
        // add CA cert to output
        let ca_cert = oca.ca_get_cert_pub()?;

        std::fs::write(
            path_append(path, &format!("{}.asc", &oca.get_ca_email()?))?,
            pgp::certs_to_armored(&[ca_cert])?,
        )?;
    }

    let emails = if let Some(email) = email_filter {
        vec![email]
    } else {
        oca.get_emails_all()?
            .iter()
            .map(|ce| ce.addr.clone())
            .collect()
    };

    for email in &emails {
        let certs = oca
            .certs_by_email(email)
            .context(format!("Failed to load certs for email '{email}'"))?;

        if !certs.is_empty() {
            let mut c: Vec<_> = vec![];
            for cert in certs {
                c.push(pgp::to_cert(cert.pub_cert.as_bytes())?);
            }

            std::fs::write(
                path_append(path, &format!("{email}.asc"))?,
                pgp::certs_to_armored(&c)?,
            )?;
        }
    }

    Ok(())
}

/// Open a file for writing. If 'overwrite' is false and the file already
/// exists, an Error is returned. When 'overwrite' is false, an existing
/// file will get truncated.
fn open_file(name: PathBuf, overwrite: bool) -> std::io::Result<File> {
    if overwrite {
        File::create(name)
    } else {
        OpenOptions::new().write(true).create_new(true).open(name)
    }
}

/// Append a (potentially adversarial) `filename` to a (presumed trustworthy)
/// `path`.
///
/// If `filename` contains suspicious chars, this fn returns an Err.
fn path_append(path: &str, filename: &str) -> Result<PathBuf> {
    // colon is a special char on windows (and illegal in emails)
    if filename.chars().any(std::path::is_separator) || filename.chars().any(|c| c == ':') {
        Err(anyhow::anyhow!(
            "Filename contains special character. May be a path traversal \
            attack? {}",
            filename
        ))
    } else {
        let mut pb = PathBuf::from_str(path)?;
        pb.push(filename);
        Ok(pb)
    }
}

// --------- wkd

pub fn wkd_export(oca: &Oca, domain: &str, path: &Path) -> Result<()> {
    use sequoia_net::wkd;

    let ca_cert = oca.ca_get_cert_pub()?;
    wkd::insert(path, domain, None, &ca_cert)?;

    for cert in oca.user_certs_get_all()? {
        // Don't export to WKD if the cert is marked "delisted"
        if !cert.delisted {
            let c = pgp::to_cert(cert.pub_cert.as_bytes())?;

            if pgp::cert_has_uid_in_domain(&c, domain)? {
                if let Err(err) = wkd::insert(path, domain, None, &c) {
                    // FIXME 1: wkd::import should accept a policy
                    // FIXME 2: if there are still errors, don't print them here.
                    // Any warning information should be returned to the caller.
                    println!("WARN: skipped cert {} ({})", c.fingerprint(), err);
                }
            }
        }
    }

    Ok(())
}

// --------- keylist

pub fn export_keylist(
    oca: &Oca,
    path: PathBuf,
    signature_uri: String,
    overwrite: bool,
) -> Result<()> {
    // Use last part of signature_uri as filename for sigfile
    let sigfile_name = match signature_uri.split('/').last() {
        Some(file) => file,
        None => {
            return Err(anyhow::anyhow!("Unexpected signature_uri format"));
        }
    };

    // Start populating new Keylist with metadata
    let mut ukl = Keylist {
        metadata: Metadata {
            signature_uri: signature_uri.clone(),
            keyserver: None,
            comment: Some("Exported from OpenPGP CA".to_string()),
        },
        keys: vec![],
    };

    // .. add CA cert to Keylist ..
    let fingerprint = oca.ca_get_cert_pub()?.fingerprint().to_hex();

    ukl.keys.push(Key {
        fingerprint,
        name: Some(format!("OpenPGP CA at {}", oca.domainname())),
        email: Some(oca.get_ca_email()?),
        comment: None,
        keyserver: None,
    });

    // .. and add all user certs that were certified by this CA.
    for user in &oca.users_get_all()? {
        for cert in oca.get_certs_by_user(user)? {
            // Create Keylist entry for each User ID that the CA has certified
            for uid in oca.cert_check_ca_sig(&cert)?.certified {
                if let Ok(Some(email)) = uid.email() {
                    ukl.keys.push(Key {
                        fingerprint: cert.fingerprint.clone(),
                        name: user.name.clone(),
                        email: Some(email),
                        comment: None,
                        keyserver: None,
                    });
                }
            }
        }
    }

    let signer = Box::new(|text: &str| oca.secret().sign_detached(text.as_bytes()));

    // Make a signed list object
    let skl = ukl.sign(signer)?;

    // Write keylist and signature to the filesystem
    let mut keylist = path.clone();
    keylist.push(KEYLIST_FILE);
    open_file(keylist, overwrite)?.write_all(skl.keylist.as_bytes())?;

    let mut sigfile = path;
    sigfile.push(sigfile_name);
    open_file(sigfile, overwrite)?.write_all(skl.sig.as_bytes())?;

    Ok(())
}
