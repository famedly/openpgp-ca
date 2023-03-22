// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use sequoia_openpgp::cert::amalgamation::ValidateAmalgamation;
use sequoia_openpgp::packet::{Signature, UserID};
use sequoia_openpgp::Cert;

use crate::db::models;
use crate::pgp;
use crate::types::CertificationStatus;
use crate::Oca;

pub fn user_new(
    oca: &Oca,
    name: Option<&str>,
    emails: &[&str],
    duration_days: Option<u64>,
    password: bool,
    output_format_minimal: bool,
) -> Result<()> {
    // Generate new user key
    let (user_key, user_revoc, pass) =
        pgp::make_user_cert(emails, name, password).context("make_user_cert failed")?;

    // CA certifies user cert
    let user_certified = sign_cert_emails(oca, &user_key, Some(emails), duration_days)
        .context("sign_user_emails failed")?;

    // User tsigns CA cert
    let ca_cert = oca.ca_get_cert_pub()?;
    let tsigned_ca =
        pgp::tsign(ca_cert, &user_key, pass.as_deref()).context("tsign for CA cert failed")?;

    let tsigned_ca = pgp::cert_to_armored_private_key(&tsigned_ca)?;

    // Store new user cert in DB
    let user_cert = pgp::cert_to_armored(&user_certified)?;
    let user_revoc = pgp::revoc_to_armored(&user_revoc, None)?;

    {
        // FIXME: move DB actions into storage layer, bind together as a transaction

        // Store tsig for the CA cert
        oca.storage.ca_import_tsig(tsigned_ca.as_bytes())?;

        oca.storage
            .user_add(
                name,
                (&user_cert, &user_key.fingerprint().to_hex()),
                emails,
                &[user_revoc],
            )
            .context("Failed to insert new user into DB")?;
    }

    // the private key needs to be handed over to the user -> print it
    let private = pgp::cert_to_armored_private_key(&user_certified)?;

    if output_format_minimal {
        // short format (convenient for use with the 'pass' tool)
        if let Some(pass) = pass {
            println!("{pass}");
        }
        println!("{private}");
    } else {
        if let Some(name) = name {
            eprintln!("Created new user key for {name}.\n");
        } else {
            eprintln!("Created new user key.\n");
        }

        println!("{private}");

        if let Some(pass) = pass {
            eprintln!("Password for this key: '{pass}'.\n");
        } else {
            eprintln!("No password set for this key.\n");
        }
    }

    Ok(())
}

pub fn cert_import_new(
    oca: &Oca,
    user_cert: &[u8],
    revoc_certs: &[&[u8]],
    name: Option<&str>,
    emails: &[&str],
    duration_days: Option<u64>,
) -> Result<()> {
    // FIXME

    let user_cert =
        pgp::to_cert(user_cert).context("cert_import_new: Couldn't process user cert.")?;

    let fp = user_cert.fingerprint().to_hex();

    if let Some(_exists) = oca
        .storage
        .cert_by_fp(&fp)
        .context("cert_import_new(): get_cert() check by fingerprint failed")?
    {
        // import_new is not intended for certs we already have a version of
        return Err(anyhow::anyhow!(
            "A key with this fingerprint already exists in the DB.\nTo update it, use the 'user update' command."
        ));
    }

    // Sign user cert with CA key (only the User IDs that have been specified)
    let certified = sign_cert_emails(oca, &user_cert, Some(emails), duration_days)
        .context("sign_cert_emails() failed")?;

    // Determine "name" for this user in the CA database
    let name = if let Some(name) = name {
        // Use explicitly specified name
        Some(name.to_string())
    } else {
        // If no user name was specified explicitly, we try deriving one from User IDs:

        // Collect all names that are used in User IDs
        let names: HashSet<_> = user_cert
            .userids()
            .filter_map(|u| u.userid().name().ok().flatten())
            .collect();

        // If there is exactly one name variant between all UserIDs -> use as CA database name
        if names.len() == 1 {
            names.into_iter().next()
        } else {
            None
        }
    };

    // Insert new user cert into DB
    let pub_cert =
        pgp::cert_to_armored(&certified).context("cert_import_new: Couldn't re-armor key")?;

    // (filter revocations through Sequoia, to get (re-)armored representations)
    let rev_sig: Result<Vec<_>> = revoc_certs.iter().map(|r| pgp::to_signature(r)).collect();
    let rev_armored: Result<Vec<_>> = rev_sig?
        .iter()
        .map(|s| pgp::revoc_to_armored(s, None))
        .collect();

    oca.storage
        .user_add(name.as_deref(), (&pub_cert, &fp), emails, &rev_armored?)
        .context("Couldn't insert user")?;

    Ok(())
}

pub fn cert_import_update(oca: &Oca, cert: &[u8]) -> Result<()> {
    // FIXME: move DB actions into storage layer, bind together as a transaction

    let cert_new = pgp::to_cert(cert).context("cert_import_update: couldn't process cert")?;

    let fp = cert_new.fingerprint().to_hex();

    if let Some(mut db_cert) = oca
        .storage
        .cert_by_fp(&fp)
        .context("cert_import_update(): get_cert() check by fingerprint failed")?
    {
        // merge existing and new public key
        let cert_old = pgp::to_cert(db_cert.pub_cert.as_bytes())?;

        let updated = cert_old.merge_public(cert_new)?;
        let armored = pgp::cert_to_armored(&updated)?;

        db_cert.pub_cert = armored;
        oca.storage.cert_update(&db_cert)
    } else {
        Err(anyhow::anyhow!(
            "No cert with this fingerprint found in DB, cannot update"
        ))
    }
}

/// Certify the User IDs in `certify` in the Cert `c` (with validity of `validity_days`).
/// Then update `db_cert` in the database to contain the resulting armored cert.
fn add_certifications(
    oca: &Oca,
    certify: Vec<&UserID>,
    c: &Cert,
    db_cert: models::Cert,
    validity_days: u64,
) -> Result<()> {
    if !certify.is_empty() {
        // Make new certifications for the User IDs identified above
        let sigs = oca
            .secret()
            .sign_user_ids(c, &certify[..], Some(validity_days))?;

        let certified = c.clone().insert_packets(sigs)?;

        // update cert in db
        let mut cert_update = db_cert;
        cert_update.pub_cert = pgp::cert_to_armored(&certified)?;
        oca.storage.cert_update(&cert_update)?;
    }

    Ok(())
}

pub fn certs_refresh_ca_certifications(
    oca: &Oca,
    threshold_days: u64,
    validity_days: u64,
) -> Result<()> {
    // FIXME: move DB actions into storage layer, bind together as a transaction

    // FIXME: fail/report individual certification problems?

    let threshold_time =
        SystemTime::now() + Duration::from_secs(threshold_days * pgp::SECONDS_IN_DAY);

    let ca = oca.ca_get_cert_pub()?;

    for db_cert in oca
        .storage
        .certs()?
        .into_iter()
        // ignore "inactive" Certs
        .filter(|c| !c.inactive)
    {
        let c = pgp::to_cert(db_cert.pub_cert.as_bytes())?;

        let mut re_certify = Vec::new();

        for uid in c.userids() {
            // find valid certifications by the CA on this uid
            let ca_certifications = pgp::valid_certifications_by(&uid, &c, ca.clone());

            let sig_valid_past_threshold = |sig: &Signature| {
                if let Some(expiration) = sig.signature_expiration_time() {
                    expiration > threshold_time
                } else {
                    true // signature has no expiration time
                }
            };

            // A new certification is created if
            // a) a valid certification by the CA exists, but
            // b) no existing certification is valid for longer than
            // `threshold_days`
            if !ca_certifications.is_empty()
                && !ca_certifications.iter().any(sig_valid_past_threshold)
            {
                // A new certification for this uid should be created
                re_certify.push(uid.userid());
            }
        }

        add_certifications(oca, re_certify, &c, db_cert, validity_days)?;
    }

    Ok(())
}

pub fn certs_re_certify(oca: &Oca, cert_old: Cert, validity_days: u64) -> Result<()> {
    // FIXME: de-deduplicate code with certs_refresh_ca_certifications()?

    // FIXME: move DB actions into storage layer, bind together as a transaction

    // FIXME: fail/report individual certification problems?

    for db_cert in oca
        .storage
        .certs()?
        .into_iter()
        // ignore "inactive" Certs
        .filter(|c| !c.inactive)
    {
        let ca_new = oca.ca_get_cert_pub()?;

        let c = pgp::to_cert(db_cert.pub_cert.as_bytes())?;

        let mut re_certify = Vec::new();

        for uid in c.userids() {
            // find valid certifications by the old CA on this uid
            let ca_certifications = pgp::valid_certifications_by(&uid, &c, cert_old.clone());

            // A new certification is created if any certification by old_cert exists
            if !ca_certifications.is_empty() {
                // Only certify if there is not yet any certification by the current CA key
                if pgp::valid_certifications_by(&uid, &c, ca_new.clone()).is_empty() {
                    // A new certification for this uid should be created
                    re_certify.push(uid.userid());
                }
            }
        }

        add_certifications(oca, re_certify, &c, db_cert, validity_days)?;
    }

    Ok(())
}

/// Return a list of Certs that are alive now, but will not be alive
/// anymore a number of 'days' in the future.
///
/// The purpose is to have a list of Certs whose users can be notified that
/// their Certs will expire soon, in case they want to extend the
/// expiration date.
pub fn certs_expired(oca: &Oca, days: u64) -> Result<HashMap<models::Cert, Option<SystemTime>>> {
    let mut res = HashMap::new();

    let days = Duration::new(60 * 60 * 24 * days, 0);
    let expiry_test = SystemTime::now().checked_add(days).unwrap();

    let certs = oca.user_certs_get_all().context("couldn't load certs")?;

    for db_cert in certs {
        let c = pgp::to_cert(db_cert.pub_cert.as_bytes())?;

        // Notify only certs that are alive now, but not alive at
        // 'expiry_test'.
        if c.with_policy(pgp::SP, None)?.alive().is_ok()
            && c.with_policy(pgp::SP, expiry_test)?.alive().is_err()
        {
            res.insert(db_cert, pgp::get_expiry(&c)?);
        }
    }

    Ok(res)
}

pub fn cert_check_ca_sig(oca: &Oca, cert: &models::Cert) -> Result<CertificationStatus> {
    let c = pgp::to_cert(cert.pub_cert.as_bytes())?;
    let ca = oca.ca_get_cert_pub()?;

    let mut certified = vec![];
    let mut uncertified = vec![];

    for uid in c.userids() {
        if pgp::valid_certifications_by(&uid, &c, ca.clone()).is_empty() {
            uncertified.push(uid.userid().clone());
        } else {
            certified.push(uid.userid().clone());
        }
    }

    Ok(CertificationStatus {
        certified,
        uncertified,
    })
}

pub fn cert_check_tsig_on_ca(oca: &Oca, cert: &models::Cert) -> Result<bool> {
    let ca = oca.ca_get_cert_pub()?;
    let tsigs = pgp::get_trust_sigs(&ca)?;

    let user_cert = pgp::to_cert(cert.pub_cert.as_bytes())?;

    Ok(tsigs.iter().any(|t| {
        t.issuer_fingerprints()
            .any(|fp| fp == &user_cert.fingerprint())
    }))
}

/// CA certifies either all or a subset of User IDs of cert.
///
/// 'emails_filter' (if not None) specifies the subset of User IDs to
/// certify.
fn sign_cert_emails(
    oca: &Oca,
    cert: &Cert,
    emails_filter: Option<&[&str]>,
    duration_days: Option<u64>,
) -> Result<Cert> {
    let fp_ca = oca.ca_get_cert_pub()?.fingerprint();

    let mut uids = Vec::new();

    // make sure we find suitable user ids to certify for each passed email
    let mut unused_email: HashSet<&str> = if let Some(emails) = emails_filter {
        emails.iter().copied().collect()
    } else {
        HashSet::new()
    };

    for uid in cert.userids() {
        // check if this uid already has a valid signature by ca_cert.
        // if yes, don't add another one.
        if !uid
            .clone()
            .with_policy(pgp::SP, None)?
            .certifications()
            .any(|s| s.issuer_fingerprints().any(|fp| fp == &fp_ca))
        {
            let userid = uid.userid();

            // Some, if this user id contains a valid email part, None otherwise.
            let uid_email: Option<String> = match userid.email_normalized() {
                Ok(email) => email.clone(),
                Err(_) => None,
            };

            // Certify this User ID if we
            // a) have no filter-list, or
            // b) if the User ID contains an email that is specified in the filter-list.
            if emails_filter.is_none()
                || (uid_email.is_some()
                    && emails_filter
                        .unwrap()
                        .contains(&uid_email.clone().unwrap().as_str()))
            {
                if let Some(uid_email) = uid_email {
                    unused_email.remove(uid_email.as_str());
                }

                uids.push(userid);
            }
        }
    }

    // Print a message when specified email addresses couldn't be found and certified on a User ID.
    //
    // FIXME: this information should not be printed here, but returned to the user of the library
    // as a list
    if !unused_email.is_empty() {
        let mut unused: Vec<_> = unused_email.into_iter().collect();
        unused.sort_unstable();

        println!(
            "Warning: Couldn't find a User ID to certify for '{}' in {}",
            unused.join(", "),
            cert.fingerprint()
        );
    }

    let sigs = oca.secret().sign_user_ids(cert, &uids, duration_days)?;
    cert.clone().insert_packets(sigs)
}
