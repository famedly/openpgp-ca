// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use std::path::Path;

use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::{Cert, Fingerprint};

use crate::ca::OpenpgpCa;
use crate::db::models;
use crate::pgp::Pgp;

/// Create a new Bridge (between this OpenPGP CA and a remote OpenPGP
/// CA instance)
///
/// The result of this operation is a signed public key for the remote
/// CA. Once this signature is published and available to OpenPGP
/// CA users, the bridge is in effect.
///
/// When `remote_email` or `remote_scope` are not set, they are derived
/// from the User ID in the key_file
pub fn bridge_new(
    oca: &OpenpgpCa,
    remote_cert_file: &Path,
    remote_email: Option<&str>,
    remote_scope: Option<&str>,
) -> Result<(models::Bridge, Fingerprint)> {
    let remote_ca_cert =
        Cert::from_file(remote_cert_file).context("Failed to read key")?;

    let remote_uids: Vec<_> = remote_ca_cert.userids().collect();

    // expect exactly one User ID in remote CA key (otherwise fail)
    if remote_uids.len() != 1 {
        return Err(anyhow::anyhow!(
            "Expected exactly one User ID in remote CA Cert",
        ));
    }

    let remote_uid = remote_uids[0].userid();

    // derive an email and domain from the User ID in the remote cert
    let (remote_cert_email, remote_cert_domain) = {
        if let Some(remote_email) = remote_uid.email()? {
            let split: Vec<_> = remote_email.split('@').collect();

            // expect remote email address with localpart "openpgp-ca"
            if split.len() != 2 || split[0] != "openpgp-ca" {
                return Err(anyhow::anyhow!(format!(
                    "Unexpected remote email {}",
                    remote_email
                )));
            }

            let domain = split[1];
            (remote_email.to_owned(), domain.to_owned())
        } else {
            return Err(anyhow::anyhow!(
                "Couldn't get email from remote CA Cert"
            ));
        }
    };

    // Email to store in the oca-database for this bridge
    let email = match remote_email {
        None => remote_cert_email,
        Some(email) => email.to_owned(),
    };

    // Scope for the bridge (limit which user ids the trust signature is
    // valid for, by domainname)
    let scope = match remote_scope {
        Some(scope) => {
            // if scope and domain don't match, warn/error?
            // (FIXME: error, unless --force parameter has been given?!)
            if scope != remote_cert_domain {
                return Err(anyhow::anyhow!(
                    "Scope and domain don't match, currently unsupported"
                ));
            }

            scope
        }
        None => &remote_cert_domain,
    };

    let regex = domain_to_regex(scope)?;

    // Make trust signature on the remote CA cert, to set up the bridge
    let bridged = oca
        .secret()
        .bridge_to_remote_ca(remote_ca_cert, vec![regex])?;

    // store new bridge in DB
    let db_cert = oca.db().add_cert(
        &Pgp::cert_to_armored(&bridged)?,
        &bridged.fingerprint().to_hex(),
        None,
    )?;

    let (ca_db, _) = oca.db().get_ca()?;
    let new_bridge = models::NewBridge {
        email: &email,
        scope,
        cert_id: db_cert.id,
        cas_id: ca_db.id,
    };

    Ok((oca.db().insert_bridge(new_bridge)?, bridged.fingerprint()))
}

pub fn bridge_revoke(oca: &OpenpgpCa, email: &str) -> Result<()> {
    if let Some(bridge) = oca.db().search_bridge(email)? {
        if let Some(mut db_cert) = oca.db().get_cert_by_id(bridge.cert_id)? {
            let bridge_cert = Pgp::armored_to_cert(&db_cert.pub_cert)?;

            // Generate revocation for the bridge
            let (revocation, revoked) =
                oca.secret().bridge_revoke(&bridge_cert)?;

            // Print the revocation in case the user wants to publish it
            // using external mechanisms.
            println!(
                "Revocation for the bridge to {}:\n{}",
                email,
                Pgp::revoc_to_armored(&revocation, None)?
            );

            // Save updated cert (including the revocation) to DB
            db_cert.pub_cert = Pgp::cert_to_armored(&revoked)?;
            oca.db().update_cert(&db_cert)
        } else {
            Err(anyhow::anyhow!("No cert found for bridge"))
        }
    } else {
        Err(anyhow::anyhow!("Bridge not found"))
    }
}

/// Make regex for trust signature from domain name.
///
/// ("other.org" => "<[^>]+[@.]other\\.org>$")
fn domain_to_regex(domain: &str) -> Result<String> {
    if publicsuffix::Domain::has_valid_syntax(domain) {
        // if valid syntax: transform domain to regex
        let escaped_domain =
            &domain.split('.').collect::<Vec<_>>().join("\\.");

        Ok(format!("<[^>]+[@.]{}>$", escaped_domain))
    } else {
        Err(anyhow::anyhow!("Parameter is not a valid domain name"))
    }
}
