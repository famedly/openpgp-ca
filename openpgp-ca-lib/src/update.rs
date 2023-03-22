// Copyright 2019-2022 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use sequoia_net::wkd;
use sequoia_net::Policy;
use sequoia_openpgp::{Fingerprint, KeyID};
use tokio::runtime::Runtime;

use crate::db::models;
use crate::pgp;
use crate::Oca;

/// Update a cert in the OpenPGP CA database via wkd.
///
/// All emails found in User IDs of the cert are looked up via WKD. For
/// all certs retrieved in that way, if they have a  matching fingerprint,
/// the cert data from wkd is merged into the existing cert (failed merges are
/// ignored silently).
pub fn update_from_wkd(oca: &Oca, cert: &models::Cert) -> Result<bool> {
    let rt = Runtime::new()?;

    let emails = oca.emails_get(cert)?;

    // Collect all updates for 'cert' in 'merge'
    let orig = pgp::to_cert(cert.pub_cert.as_bytes())?;
    let mut merged = orig.clone();

    for email in emails {
        let res = rt.block_on(async move { wkd::get(&email.addr).await });

        // silently ignore errors on wkd lookup
        if let Ok(certs) = res {
            for c in certs {
                if c.fingerprint() == Fingerprint::from_hex(&cert.fingerprint)? {
                    // If 'c' can't be merged, silently ignore the error that
                    // sequoia returns
                    if let Ok(m) = merged.clone().merge_public(c) {
                        merged = m;
                    }
                }
            }
        }
    }

    // FIXME: use "update/merge" storage primitive?

    if merged != orig {
        let mut db_update = cert.clone();
        db_update.pub_cert = pgp::cert_to_armored(&merged)?;

        oca.storage.cert_update(&db_update)?;

        Ok(true)
    } else {
        Ok(false)
    }
}

/// Update a cert in the OpenPGP CA database from the "Hagrid" keyserver at
/// `keys.openpgp.org`
///
/// Returns "true" if updated data was received, false if not.
pub fn update_from_hagrid(oca: &Oca, cert: &models::Cert) -> Result<bool> {
    let fp = (cert.fingerprint).parse::<Fingerprint>()?;

    let c = pgp::to_cert(cert.pub_cert.as_bytes())?;

    // get key from hagrid
    let mut hagrid = sequoia_net::KeyServer::keys_openpgp_org(Policy::Encrypted)?;

    let rt = Runtime::new()?;
    let update = rt.block_on(async move { hagrid.get(&KeyID::from(fp)).await })?;

    // FIXME: use "update/merge" storage primitive?

    // Merge new certificate information into existing cert.
    // (Silently ignore potential errors from merge_public())
    if let Ok(merged) = c.clone().merge_public(update) {
        if merged != c {
            // Store merged cert in DB
            let mut db_update = cert.clone();
            db_update.pub_cert = pgp::cert_to_armored(&merged)?;

            oca.storage.cert_update(&db_update)?;

            // An update for this cert was received
            return Ok(true);
        }
    }

    // No update was received
    Ok(false)
}
