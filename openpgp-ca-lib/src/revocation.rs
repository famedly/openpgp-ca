// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::ca::OpenpgpCa;
use crate::db::models;
use crate::pgp::Pgp;

use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::KeyHandle;
use sequoia_openpgp::{Cert, Packet};

use anyhow::{Context, Result};

/// Check if the CA database has a variant of the revocation
/// certificate 'revocation' (according to Signature::normalized_eq()).
fn check_for_equivalent_revocation(
    oca: &OpenpgpCa,
    revocation: &Signature,
    cert: &models::Cert,
) -> Result<bool> {
    for db_rev in oca.db().revocations_by_cert(cert)? {
        let r = Pgp::armored_to_signature(&db_rev.revocation)
            .context("Couldn't re-armor revocation cert from CA db")?;

        if revocation.normalized_eq(&r) {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Store a new revocation in the database.
///
/// This implicitly searches for a cert that the revocation can be applied to.
/// If no suitable cert is found, an error is returned.
pub fn revocation_add(oca: &OpenpgpCa, revocation: &str) -> Result<()> {
    // Check if this revocation already exists in db
    if oca.db().revocation_exists(revocation)? {
        return Ok(()); // this revocation is already stored -> do nothing
    }

    let mut revocation = Pgp::armored_to_signature(revocation)
        .context("revocation_add: Couldn't process revocation")?;

    // Find the matching cert for this revocation certificate
    let mut cert = None;
    // 1) Search by fingerprint, if possible
    if let Some(issuer_fp) = Pgp::get_revoc_issuer_fp(&revocation)? {
        cert = oca.db().cert_by_fp(&issuer_fp.to_hex())?;
    }
    // 2) If match by fingerprint failed: test revocation for each cert
    if cert.is_none() {
        cert = search_revocable_cert_by_keyid(&oca, &mut revocation)?;
    }

    if let Some(cert) = cert {
        let c = Pgp::armored_to_cert(&cert.pub_cert)?;

        // verify that revocation certificate validates with cert
        if validate_revocation(&c, &mut revocation)? {
            if !check_for_equivalent_revocation(&oca, &revocation, &cert)? {
                // update sig in DB
                let armored = Pgp::revoc_to_armored(&revocation, None)
                    .context("couldn't armor revocation cert")?;

                oca.db().revocation_add(&armored, &cert)?;
            }

            Ok(())
        } else {
            Err(anyhow::anyhow!(format!(
                "Revocation couldn't be matched to a cert:\n{:?}",
                revocation
            )))
        }
    } else {
        Err(anyhow::anyhow!("Couldn't find cert for this fingerprint"))
    }
}

/// Verify that `revoc_cert` can be used to revoke the primary key of `cert`.
fn validate_revocation(
    cert: &Cert,
    revocation: &mut Signature,
) -> Result<bool> {
    let before = cert.primary_key().self_revocations().count();

    let revoked = cert.to_owned().insert_packets(revocation.to_owned())?;

    let after = revoked.primary_key().self_revocations().count();

    // expecting an additional self_revocation after merging revoc_cert
    if before + 1 != after {
        return Ok(false);
    }

    // Does the revocation verify?
    let key = revoked.primary_key().key();
    Ok(revocation.verify_primary_key_revocation(key, key).is_ok())
}

/// Search a matching cert for `revoc` based on KeyID equality.
///
/// (This is used when the revocation has no issuer fingerprint)
fn search_revocable_cert_by_keyid(
    oca: &OpenpgpCa,
    mut revoc: &mut Signature,
) -> Result<Option<models::Cert>> {
    let revoc_keyhandles = revoc.get_issuers();
    if revoc_keyhandles.is_empty() {
        return Err(anyhow::anyhow!("Signature has no issuer KeyID"));
    }

    for db_cert in oca.user_certs_get_all()? {
        let c = Pgp::armored_to_cert(&db_cert.pub_cert)?;

        // require that keyid of cert and Signature issuer match
        let c_keyid = c.keyid();

        if !revoc_keyhandles.contains(&KeyHandle::KeyID(c_keyid)) {
            // ignore certs with non-matching KeyID
            continue;
        }

        // if KeyID matches, check if revocation validates
        if validate_revocation(&c, &mut revoc)? {
            return Ok(Some(db_cert));
        }
    }
    Ok(None)
}

/// Merge a revocation into the cert that it applies to, thus revoking that
/// cert in the OpenPGP CA database.
pub fn revocation_apply(
    oca: &OpenpgpCa,
    mut db_revoc: models::Revocation,
) -> Result<()> {
    if let Some(mut db_cert) = oca.db().cert_by_id(db_revoc.cert_id)? {
        let sig = Pgp::armored_to_signature(&db_revoc.revocation)?;
        let c = Pgp::armored_to_cert(&db_cert.pub_cert)?;

        let revocation: Packet = sig.into();
        let revoked = c.insert_packets(vec![revocation])?;

        db_cert.pub_cert = Pgp::cert_to_armored(&revoked)?;

        db_revoc.published = true;

        oca.db()
            .cert_update(&db_cert)
            .context("Couldn't update Cert")?;

        oca.db()
            .revocation_update(&db_revoc)
            .context("Couldn't update Revocation")?;

        Ok(())
    } else {
        Err(anyhow::anyhow!("Couldn't find cert for apply_revocation"))
    }
}