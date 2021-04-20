// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::ca::OpenpgpCa;
use crate::pgp::Pgp;

use openpgp_keylist::{Key, Keylist, Metadata};

use anyhow::Result;

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

// export filename of keylist
const KEYLIST_FILE: &str = "keylist.json";

/// Write all Certs to stdout as one armored certring (or a subset of certs,
/// filtered by User ID via email)
pub fn print_certring(
    oca: &OpenpgpCa,
    email_filter: Option<String>,
) -> Result<()> {
    // Load all user-certs (optionally filtered by email)
    let certs = match &email_filter {
        Some(email) => oca.certs_get(email)?,
        None => oca.user_certs_get_all()?,
    };

    let mut c = Vec::new();

    // add CA cert if no filter has been set
    if email_filter.is_none() {
        c.push(oca.ca_get_cert_pub()?);
    }

    for cert in certs {
        c.push(Pgp::armored_to_cert(&cert.pub_cert)?);
    }

    println!("{}", Pgp::certs_to_armored(&c)?);

    Ok(())
}

/// Export Certs to filesystem, as individual files split and named by email.
/// (Optionally: filter by User ID via list of emails)
pub fn export_certs_as_files(
    oca: &OpenpgpCa,
    email_filter: Option<String>,
    path: &str,
) -> Result<()> {
    // export CA cert
    if email_filter.is_none() {
        // add CA cert to output
        let ca_cert = oca.ca_get_cert_pub()?;

        std::fs::write(
            path_append(path, &format!("{}.asc", &oca.get_ca_email()?))?,
            Pgp::certs_to_armored(&[ca_cert])?,
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
        if let Ok(certs) = oca.certs_get(email) {
            if !certs.is_empty() {
                let mut c: Vec<_> = vec![];
                for cert in certs {
                    c.push(Pgp::armored_to_cert(&cert.pub_cert)?);
                }

                std::fs::write(
                    path_append(path, &format!("{}.asc", email))?,
                    Pgp::certs_to_armored(&c)?,
                )?;
            }
        } else {
            println!("ERROR loading certs for email '{}'", email)
        };
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
    if filename.chars().any(std::path::is_separator)
        || filename.chars().any(|c| c == ':')
    {
        Err(anyhow::anyhow!(
            "filename contains special character - maybe a path traversal \
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

pub fn wkd_export(oca: &OpenpgpCa, domain: &str, path: &Path) -> Result<()> {
    use sequoia_net::wkd;

    let ca_cert = oca.ca_get_cert_pub()?;
    wkd::insert(&path, domain, None, &ca_cert)?;

    for cert in oca.user_certs_get_all()? {
        // don't export to WKD if the cert is marked "delisted"
        if !cert.delisted {
            let c = Pgp::armored_to_cert(&cert.pub_cert)?;

            if Pgp::cert_has_uid_in_domain(&c, domain)? {
                wkd::insert(&path, domain, None, &c)?;
            }
        }
    }

    Ok(())
}

// --------- keylist

pub fn export_keylist(
    oca: &OpenpgpCa,
    path: PathBuf,
    signature_uri: String,
    force: bool,
) -> Result<()> {
    // filename of sigfile: last part of signature_uri
    let pos = &signature_uri.rfind('/').unwrap() + 1; //FIXME
    let sigfile_name = &signature_uri[pos..];

    // Start populating new Keylist
    let mut ukl = Keylist {
        metadata: Metadata {
            signature_uri: signature_uri.clone(),
            keyserver: None,
            comment: Some("Exported from OpenPGP CA".to_string()),
        },
        keys: vec![],
    };

    // .. add ca cert to Keylist ..
    let fingerprint = oca.ca_get_cert_pub()?.fingerprint().to_hex();

    ukl.keys.push(Key {
        fingerprint,
        name: Some(format!("OpenPGP CA at {}", oca.get_ca_domain()?)),
        email: Some(oca.get_ca_email()?),
        comment: None,
        keyserver: None,
    });

    // .. add all "signed-by-ca" certs to the list.
    for user in &oca.users_get_all()? {
        for user_cert in oca.get_certs_by_user(&user)? {
            // check if any user id of the cert has been certified by this ca (else skip)
            let (sig_from_ca, _) =
                oca.cert_check_certifications(&user_cert)?;
            if sig_from_ca.is_empty() {
                continue;
            }

            // Create entries for each user id that the CA has certified
            for u in sig_from_ca {
                if let Ok(Some(email)) = u.email() {
                    ukl.keys.push(Key {
                        fingerprint: user_cert.fingerprint.clone(),
                        name: user.name.clone(),
                        email: Some(email),
                        comment: None,
                        keyserver: None,
                    });
                }
            }
        }
    }

    let signer = Box::new(|text: &str| oca.secret().sign_detached(text));

    // make a signed list object
    let skl = ukl.sign(signer)?;

    // Write keylist and signature to the filesystem
    let mut keylist = path.clone();
    keylist.push(KEYLIST_FILE);
    open_file(keylist, force)?.write_all(&skl.keylist.as_bytes().to_vec())?;

    let mut sigfile = path;
    sigfile.push(sigfile_name);
    open_file(sigfile, force)?.write_all(&skl.sig.as_bytes().to_vec())?;

    Ok(())
}
