// Copyright 2019-2022 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use core::time::Duration;
use std::collections::HashSet;
use std::convert::TryInto;
use std::error::Error;
use std::ops::Deref;
use std::str::FromStr;
use std::time::SystemTime;

use openpgp_ca_lib::pgp;
use openpgp_ca_lib::Oca;
use sequoia_openpgp::cert::ValidCert;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::types::{HashAlgorithm, PublicKeyAlgorithm, RevocationStatus};
use sequoia_openpgp::{Cert, Message, Packet};

use crate::cert_info::CertInfo;
use crate::json::*;
use crate::restd;
use crate::util::{is_email_in_domain, split_emails, user_id_filter};

const STANDARD_POLICY: &StandardPolicy = &StandardPolicy::new();

/// Warnings for this cert.
///
/// Warnings are currently generated for:
/// - Standard Policy gives an error for 'now + 2 years'
/// - Cert is not alive() in 'now + 3 months'
///
/// Assumption: the cert has been checked and found good by the
/// StandardPolicy for `now`.
pub fn get_warnings(cert: &Cert) -> Result<Option<Vec<Warning>>, CertError> {
    let mut warns = Vec::new();
    let now = SystemTime::now();

    // Check if StandardPolicy is bad in 'now + 2 years', but good when
    // allowing for SHA1.
    let now2y = now
        .clone()
        .checked_add(Duration::from_secs(60 * 60 * 24 * 365 * 2))
        .ok_or_else(|| {
            CertError::new(
                CertStatus::InternalError,
                "cert_to_warn: duration checked_add failed",
            )
        })?;

    let policy_plus2y = StandardPolicy::at(now2y);

    let valid2y = cert.with_policy(&policy_plus2y, Some(now2y));

    let mut sp_plus_sha1 = StandardPolicy::at(now2y);
    sp_plus_sha1.accept_hash(HashAlgorithm::SHA1);
    let valid2y_sha1 = cert.with_policy(&sp_plus_sha1, now2y);

    if valid2y.is_err() && valid2y_sha1.is_ok() {
        warns.push(Warning::new(
            WarnStatus::WeakCryptoSHA1,
            "This certificate relies on SHA1 hashes, which are deprecated. It should be updated!",
        ));
    }

    // Check if cert is alive() now, but will not be in 'now + 3 months'.
    // If so: warn about imminent expiry.

    let now3m = now
        .clone()
        .checked_add(Duration::from_secs(60 * 60 * 24 * 30 * 3))
        .ok_or_else(|| {
            CertError::new(
                CertStatus::InternalError,
                "cert_to_warn: duration checked_add failed",
            )
        })?;

    let policy_plus3m = StandardPolicy::at(now3m);

    let valid_cert_now = cert.with_policy(STANDARD_POLICY, None);

    let valid_cert_3m = cert.with_policy(&policy_plus3m, Some(now3m));

    if valid_cert_now.is_ok()
        && valid_cert_now.unwrap().alive().is_ok()
        && valid_cert_3m.is_ok()
        && valid_cert_3m.unwrap().alive().is_err()
    {
        warns.push(Warning::new(
            WarnStatus::ExpiresSoon,
            "Will expire in the next 90 days",
        ));
    }

    if warns.is_empty() {
        Ok(None)
    } else {
        Ok(Some(warns))
    }
}

pub fn get_cert_info(cert: &Cert) -> Result<CertInfo, ReturnError> {
    cert.try_into().map_err(|e| {
        ReturnError::new(
            ReturnStatus::InternalError,
            format!("Error getting CertInfo from Cert '{e:?}'"),
        )
    })
}

fn cert_policy_check(cert: &Cert) -> Result<ValidCert, CertError> {
    // check if cert is valid according to sequoia standard policy
    cert.with_policy(STANDARD_POLICY, None).map_err(|e| {
        CertError::new_with_url(
            CertStatus::BadCert,
            // restd::POLICY_BAD_URL.to_string(),
            None,
            format!("Cert invalid according to standard policy: '{e:?}'"),
        )
    })
}

// 'my_domain' is the domain that this CA is used over (like 'example.org').
//
// 'user_emails' is a list of email addresses that the client considers to
// be correctly used by this user (typically this will be local emails, such
// as ('alice@example.org').
//
// remove all user_ids with emails in "my_domain" that aren't contained in
// 'user_emails'
fn validate_and_strip_user_ids(
    cert: &Cert,
    my_domain: &str,
    user_emails: &[String],
) -> Result<Cert, CertError> {
    // validate user_emails vs. the user ids in cert

    // emails from the cert's user_ids
    let cert_uid_emails: HashSet<_> = cert
        .userids()
        .flat_map(|uid| uid.email().ok())
        .flatten()
        .collect();

    // the intersection between "user_emails" and "cert_uid_emails" must
    // be non-empty
    if cert_uid_emails
        .intersection(&user_emails.iter().cloned().collect::<HashSet<_>>())
        .next()
        .is_none()
    {
        return Err(CertError::new(
            CertStatus::CertMissingLocalUserId,
            format!("Cert does not contain user_ids matching '{user_emails:?}'"),
        ));
    }

    // split up user_ids between "external" and "internal" emails, then:
    match split_emails(my_domain, user_emails) {
        Ok((int_provided, _)) => {
            let mut filter_uid = Vec::new();

            for user_id in cert.userids() {
                if let Ok(Some(email)) = user_id.email() {
                    let in_domain = is_email_in_domain(&email, my_domain);

                    if in_domain.is_ok() && in_domain.unwrap() {
                        // this is a User ID with an email in the domain
                        // "my_domain"

                        if !int_provided.contains(&email) {
                            // flag unexpected "internal" emails for removal
                            filter_uid.push(user_id.userid());
                        }
                    }
                }
            }

            // strip unexpected "internal" user_ids from the Cert
            let mut stripped = cert.clone();
            for filter in filter_uid {
                stripped = user_id_filter(stripped, filter)
            }

            Ok(stripped)
        }
        Err(e) => Err(CertError::new(
            CertStatus::BadEmail,
            format!("Error with provided email addresses {e:?}"),
        )),
    }
}

#[allow(clippy::result_large_err)]
fn check_cert(cert: &Cert) -> Result<CertInfo, ReturnBadJson> {
    let ci = cert.try_into().map_err(|e| {
        ReturnBadJson::new(
            CertError::new(
                CertStatus::InternalError,
                format!["check_cert: CertInfo::from_cert() failed {e:?}"],
            ),
            None,
        )
    })?;

    // private keys are illegal
    if cert.is_tsk() {
        return Err(ReturnBadJson::new(
            CertError::new(
                CertStatus::PrivateKey,
                String::from("check_cert: The user provided private key material"),
            ),
            Some(ci),
        ));
    }

    // reject unreasonably big certificates
    if let Ok(armored) = pgp::cert_to_armored(cert) {
        let len = armored.len();
        if len > restd::CERT_SIZE_LIMIT {
            return Err(ReturnBadJson::new(
                CertError::new(
                    CertStatus::CertSizeLimit,
                    format!("check_cert: User cert is too big ({len} bytes)"),
                ),
                Some(ci),
            ));
        }
    } else {
        return Err(ReturnBadJson::new(
            CertError::new(
                CertStatus::InternalError,
                "check_cert: Failed to re-armor cert",
            ),
            Some(ci),
        ));
    }

    Ok(ci)
}

// `signed_by` is true, if the provided keyring has been signed
// by this cert. If so, upload will be recommended to the UI.
#[allow(clippy::result_large_err)]
fn process_cert(
    cert: &Cert,
    signed_by: bool,
    my_domain: &str,
    certificate: &Certificate,
    ca: &Oca,
    persist: bool,
) -> Result<ReturnGoodJson, ReturnBadJson> {
    let cert_info = check_cert(cert)?;

    // check if a cert with this fingerprint exists already in db
    // (new vs update)
    let fp = &cert_info.primary.fingerprint;

    let cert_in_ca_db = ca.cert_get_by_fingerprint(fp).map_err(|e| {
        let ce = CertError::new(
            CertStatus::InternalError,
            format!("process_cert: Error during db lookup by fingerprint: {e:?}"),
        );
        ReturnBadJson::new(ce, Some(cert_info.clone()))
    })?;

    // will this cert be processed as an update to an existing version of it?
    let is_update = cert_in_ca_db.is_some();

    if is_update {
        // input sanity check: delisted/inactive may not be changed by
        // input parameter, for now

        if (certificate.delisted.is_some()
            && certificate.delisted != Some(cert_in_ca_db.as_ref().unwrap().delisted))
            || (certificate.inactive.is_some()
                && certificate.inactive != Some(cert_in_ca_db.as_ref().unwrap().inactive))
        {
            let ce = CertError::new(
                CertStatus::InternalError,
                format!(
                    "process_cert: changing delisted and inactive is \
                    not currently allowed via this call {certificate:?}"
                ),
            );
            return Err(ReturnBadJson::new(ce, Some(cert_info.clone())));
        }
    }

    // merge new cert with existing cert, if any
    let merged = match cert_in_ca_db {
        None => cert.clone(),
        Some(ref c) => {
            let db_cert = pgp::to_cert(c.pub_cert.as_bytes()).map_err(|e| {
                let error = CertError::new(
                    CertStatus::InternalError,
                    format!("process_cert: Error un-armoring cert from CA DB: {e:?}"),
                );

                ReturnBadJson::new(error, Some(cert_info.clone()))
            })?;

            db_cert.merge_public(cert.clone()).map_err(|e| {
                let error = CertError::new(
                    CertStatus::InternalError,
                    format!(
                        "process_cert: Error merging new cert with DB \
                        cert: {e:?}"
                    ),
                );

                ReturnBadJson::new(error, Some(cert_info.clone()))
            })?
        }
    };
    let _ = cert; // drop previous version of the cert

    // Detect weak algorithms, to give a more specific error status:
    // RSA, DSA, Elgamal under 2048 bits return BadCertKeyTooWeak.
    let pk_algo = cert.primary_key().pk_algo();
    #[allow(deprecated)]
    if pk_algo == PublicKeyAlgorithm::RSAEncryptSign
        || pk_algo == PublicKeyAlgorithm::RSAEncrypt
        || pk_algo == PublicKeyAlgorithm::RSASign
        || pk_algo == PublicKeyAlgorithm::ElGamalEncryptSign
        || pk_algo == PublicKeyAlgorithm::ElGamalEncrypt
        || pk_algo == PublicKeyAlgorithm::DSA
    {
        // Note: Some implementations end up generating 2047 bits when a
        // 2048 bit key is requested
        if cert_info.primary.bits <= 2046 {
            let ce = CertError::new(
                CertStatus::BadCertKeyTooWeak,
                "Cert uses a public key algorithm with a key of \
                insufficient length",
            );
            return Err(ReturnBadJson::new(ce, Some(cert_info.clone())));
        }
    }

    // perform sequoia policy check
    let valid_cert =
        cert_policy_check(&merged).map_err(|ce| ReturnBadJson::new(ce, Some(cert_info.clone())))?;
    let _ = merged; // drop previous version of the cert

    // check if the cert is revoked
    let is_revoked = matches!(valid_cert.revocation_status(), RevocationStatus::Revoked(_));

    // check and normalize user_ids
    let norm = validate_and_strip_user_ids(&valid_cert, my_domain, &certificate.email)
        .map_err(|e| ReturnBadJson::new(e, Some(cert_info.clone())))?;

    let cert_info_norm: CertInfo = (&norm)
        .try_into()
        .map_err(|e| {
            CertError::new(
                CertStatus::InternalError,
                format!("process_cert: CertInfo::from_cert() failed for 'norm' {e:?}"),
            )
        })
        .map_err(|ce| ReturnBadJson::new(ce, None))?;

    let armored = pgp::cert_to_armored(&norm).map_err(|e|
        // this should probably never happen?
        ReturnBadJson::new(
            CertError::new(
                CertStatus::InternalError,
                format!("process_cert: Couldn't re-armor cert {e:?}"),
            ),
            Some(cert_info.clone()),
        ))?;

    let action;
    let upload;

    if persist {
        // "post" run
        upload = None; // don't recommend action after persisting

        let cert_info = Some(cert_info_norm.clone());

        if is_update {
            // update cert in db
            action = Some(Action::Update);

            // FIXME: how/when should changes to name/email be persisted?

            ca.cert_import_update(armored.as_bytes()).map_err(|e| {
                let error = CertError::new(
                    CertStatus::InternalError,
                    format!("process_cert: Error updating Cert in database: {e:?}"),
                );

                ReturnBadJson::new(error, cert_info.clone())
            })?;

            for rev in &certificate.revocations {
                ca.revocation_add(rev.as_bytes()).map_err(|e| {
                    let ce = CertError::new(
                        CertStatus::InternalError,
                        format!(
                            "process_cert: Error adding revocation to db: \
                                {e:?}"
                        ),
                    );
                    ReturnBadJson::new(ce, cert_info.clone())
                })?;
            }
        } else {
            // add new cert to db
            action = Some(Action::New);

            let name = certificate.name.as_deref();
            let emails = certificate
                .email
                .iter()
                .map(|e| e.deref())
                .collect::<Vec<_>>();

            ca.cert_import_new(
                armored.as_bytes(),
                certificate
                    .revocations
                    .iter()
                    .map(|r| r.as_bytes())
                    .collect::<Vec<_>>()
                    .as_ref(),
                name,
                emails.as_slice(),
                Some(restd::CERTIFICATION_DAYS),
            )
            .map_err(|e| {
                let error = CertError::new(
                    CertStatus::InternalError,
                    format!("process_cert: Error importing Cert into db: {e:?}"),
                );
                ReturnBadJson::new(error, cert_info.clone())
            })?;
        }
    } else {
        // "check" run: set action and upload
        action = match is_update {
            true => Some(Action::Update),
            false => Some(Action::New),
        };

        upload = match is_update || is_revoked || signed_by {
            true => Some(Upload::Recommended),
            false => Some(Upload::Possible),
        };
    }

    // get the last known value of delisted/inactive
    // (either from db lookup, above - or assume the default 'false')
    let delisted = if is_update {
        cert_in_ca_db.as_ref().unwrap().delisted
    } else {
        false
    };
    let inactive = if is_update {
        cert_in_ca_db.as_ref().unwrap().inactive
    } else {
        false
    };

    let certificate = Certificate {
        cert: armored,
        email: certificate.email.clone(),
        name: certificate.name.clone(),
        revocations: certificate.revocations.clone(),
        delisted: Some(delisted),
        inactive: Some(inactive),
    };

    let warn = get_warnings(&norm).map_err(|ce| ReturnBadJson::new(ce, Some(cert_info.clone())))?;

    Ok(ReturnGoodJson {
        certificate,
        cert_info: cert_info_norm,
        warn,
        action,
        upload,
    })
}

/// Accept an armored certificate ring.
///
/// The input may be in one of two shapes:
/// 1) an armored collection of certs
/// 2) a signed message, containing a plain collection of certs, that
/// has been signed by one of the certs
///
/// Returns a vec of Cert - and the position of the (claimed) signer Cert, if
/// any (the signature is not verified, only the issuer is checked).
fn unpack_certring(certring: &str) -> Result<(Vec<Cert>, Option<usize>), Box<dyn Error>> {
    // determine the shape of our input data
    if let Ok(msg) = Message::from_str(certring) {
        // 1) a signed message that contains a certring (?)
        if let Some(l) = msg.body() {
            // we expect the literal to contain an armored keyring
            let certs = pgp::armored_keyring_to_certs(&l.body())?;

            if let Some(Packet::Signature(s)) = msg
                .descendants()
                .find(|p| matches!(p, Packet::Signature(_)))
            {
                // first check by sig issuer fingerprint, then by issuer keyid
                for sig_kh in s.get_issuers() {
                    for (n, c) in certs.iter().enumerate() {
                        // check if c (or any of its subkeys) matches sig_issuers
                        if c.keys().any(|k| k.key_handle().aliases(&sig_kh)) {
                            return Ok((certs, Some(n)));
                        }
                    }
                }
            }
            // We didn't identify a signature, but still found a certring
            return Ok((certs, None));
        }

        Err(anyhow::anyhow!("No Literal found in Message").into())
    } else {
        // 2) a plain keyring (unsigned)
        Ok((pgp::armored_keyring_to_certs(&certring)?, None))
    }
}

pub fn process_certs(
    ca: &Oca,
    certificate: &Certificate,
    persist: bool,
) -> Result<Vec<CertResultJson>, ReturnError> {
    let (certs, signer) = unpack_certring(&certificate.cert).map_err(|e| {
        ReturnError::new(
            ReturnStatus::BadKeyring,
            format!("process_certs: Error processing user-provided certring:\n{e:?}"),
        )
    })?;

    // get the domain of this CA
    let my_domain = ca.domainname();

    // iterate over certs and collect results for each cert
    Ok(certs
        .iter()
        .enumerate()
        .map(|(n, cert)| {
            let is_signer = Some(n) == signer;
            process_cert(cert, is_signer, my_domain, certificate, ca, persist).into()
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use crate::process_certs::unpack_certring;

    #[test]
    fn test_certring() {
        const ALICE_ASC: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----

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
XAGda3g14niMoT45jmI=
=ERvg
-----END PGP PUBLIC KEY BLOCK-----";

        let res = unpack_certring(ALICE_ASC);

        assert!(res.is_ok());

        let (certs, sig) = res.unwrap();
        assert_eq!(certs.len(), 2);
        assert!(sig.is_none());
    }

    #[test]
    fn test_sig_certring() {
        const ALICE_SIG_ASC: &str = "-----BEGIN PGP MESSAGE-----

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
q594M1fe9j8=
=C1FG
-----END PGP MESSAGE-----";

        let res = unpack_certring(ALICE_SIG_ASC);

        assert!(res.is_ok());

        let (certs, sig) = res.unwrap();
        assert_eq!(certs.len(), 2);
        assert!(sig.is_some());

        let fp = certs[sig.unwrap()].fingerprint();
        assert_eq!(fp.to_hex(), "47772C7D6BA429491DAD2E1867214E3EC12D32C1");
    }
}
