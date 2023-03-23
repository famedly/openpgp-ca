// SPDX-FileCopyrightText: 2019-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use chrono::{DateTime, Utc};
use sequoia_openpgp::cert::CertRevocationBuilder;
use sequoia_openpgp::packet::{signature::SignatureBuilder, Signature, UserID};
use sequoia_openpgp::serialize::Serialize;
use sequoia_openpgp::types::{ReasonForRevocation, SignatureType};
use sequoia_openpgp::{armor, cert, Cert, Packet};

use crate::backend::CertificationBackend;
use crate::pgp;

/// Abstraction of operations that need private key material
pub(crate) trait CaSec {
    fn cert(&self) -> Result<Cert>;
    fn sign_user_ids(
        &self,
        cert: &Cert,
        uids_certify: &[&UserID],
        duration_days: Option<u64>,
    ) -> Result<Vec<Signature>>;
    fn ca_generate_revocations(&self, output: PathBuf) -> Result<()>;
    fn sign_detached(&self, data: &[u8]) -> Result<String>;
    fn bridge_to_remote_ca(&self, remote_ca: Cert, scope_regexes: Vec<String>) -> Result<Cert>;
    fn bridge_revoke(&self, remote_ca: &Cert) -> Result<(Signature, Cert)>;
}

/// A CaSec that uses a CertificationBackend internally
pub struct CaSecCB<CertificationBackend> {
    // Contain only public key material
    ca_cert: Cert,

    // Stored as `Rc` because DbCa needs to be shared for different purposes in softkey mode
    cb: Rc<CertificationBackend>,
}

impl<T: CertificationBackend> CaSecCB<T> {
    pub(crate) fn new(t: Rc<T>, ca_cert: Cert) -> Self {
        Self { cb: t, ca_cert }
    }

    /// Get Cert for this CA (may contain private key material, depending on the backend)
    fn get_ca_cert(&self) -> Result<&Cert> {
        Ok(&self.ca_cert)
    }

    /// Get the User ID of this CA
    fn ca_userid(&self) -> Result<UserID> {
        let cert = self.get_ca_cert()?;
        let uids: Vec<_> = cert.userids().collect();

        if uids.len() != 1 {
            return Err(anyhow::anyhow!("ERROR: CA has != 1 user_id"));
        }

        Ok(uids[0].userid().clone())
    }

    /// Get the email of this CA
    fn ca_email(&self) -> Result<String> {
        let email = self.ca_userid()?.email()?;

        if let Some(email) = email {
            Ok(email)
        } else {
            Err(anyhow::anyhow!("CA user_id has no email"))
        }
    }
}

impl<T: CertificationBackend> CaSec for CaSecCB<T> {
    fn cert(&self) -> Result<Cert> {
        Ok(self.ca_cert.clone())
    }

    /// CA certifies a specified list of User IDs of a cert.
    ///
    /// This fn does not perform any checks as a precondition for adding new
    /// certifications.
    fn sign_user_ids(
        &self,
        cert: &Cert,
        uids_certify: &[&UserID],
        duration_days: Option<u64>,
    ) -> Result<Vec<Signature>> {
        let ca_cert = self.get_ca_cert()?; // CA cert (must include CA User ID)

        // Collect certifications by the CA
        let mut packets: Vec<Signature> = Vec::new();

        let userids = cert
            .userids()
            // sign only userids that are in "uids_certify"
            .filter(|u| uids_certify.contains(&u.userid()))
            .map(|u| u.userid());

        for userid in userids {
            // make certification
            let mut sb = SignatureBuilder::new(SignatureType::GenericCertification);

            // If an expiration setting for the certifications has been
            // provided, apply it to the signatures
            if let Some(days) = duration_days {
                // The signature should be valid for the specified
                // number of `days`
                sb = sb.set_signature_validity_period(Duration::from_secs(
                    pgp::SECONDS_IN_DAY * days,
                ))?;
            }

            // Include 'Signer's UserID' packet
            // (https://tools.ietf.org/html/rfc4880#section-5.2.3.22)
            // to make it easier to find the CA key via WKD
            if let Some(uid) = ca_cert.userids().next() {
                sb = sb.set_signers_user_id(uid.userid().value())?;
            } else {
                return Err(anyhow::anyhow!(
                    "ERROR: No User ID in CA cert. This should never happen."
                ));
            }

            self.cb
                .certify(&mut |signer: &mut dyn sequoia_openpgp::crypto::Signer| {
                    let sig = userid.bind(signer, cert, sb.clone())?;

                    // collect in packets
                    packets.push(sig);

                    Ok(())
                })?;
        }

        // Insert all newly created certifications into the user cert
        Ok(packets)
    }

    /// Generate a set of revocation certificates for the CA key.
    ///
    /// This outputs a set of revocations with creation dates spaced
    /// in 30 day increments, from now to 120x 30days in the future (around
    /// 10 years). For each of those points in time, one hard and one soft
    /// revocation certificate is generated.
    ///
    /// The output file is human readable, contains some informational
    /// explanation, followed by the CA certificate and the list of
    /// revocation certificates
    fn ca_generate_revocations(&self, output: PathBuf) -> Result<()> {
        let ca_pub = self.get_ca_cert()?;

        let mut file = std::fs::File::create(output)?;

        // write informational header
        writeln!(
            &mut file,
            "This file contains revocation certificates for the OpenPGP CA \n\
            instance '{}'.",
            self.ca_email()?
        )?;
        writeln!(&mut file)?;

        let msg = r#"These revocations can be used to invalidate the CA's key.
This is useful e.g. if the (private) CA key gets compromised (i.e. available
to a third party), or when the CA key becomes inaccessible to you.

CAUTION: This file needs to be kept safe from third parties who could use
the revocations to adversarially invalidate your CA certificate!
Keep in mind that an attacker can use these revocations to
perform a denial of service attack on your CA at the most inconvenient
moment. When a revocation certificate has been published for your CA, you
will need to start over with a fresh CA key.

Please store this file appropriately, to avoid it becoming accessible to
adversaries."#;

        writeln!(&mut file, "{msg}\n\n")?;

        writeln!(
            &mut file,
            "For reference, the certificate of your CA is\n\n{}\n",
            pgp::cert_to_armored(ca_pub)?
        )?;

        writeln!(
            &mut file,
            "Revocation certificates (ordered by 'creation time') follow:\n"
        )?;

        let now = SystemTime::now();
        let thirty_days = Duration::new(30 * 24 * 60 * 60, 0);

        for i in 0..=120 {
            let t = now + i * thirty_days;

            let dt: DateTime<Utc> = t.into();
            let date = dt.format("%Y-%m-%d");

            self.cb
                .certify(&mut |signer: &mut dyn sequoia_openpgp::crypto::Signer| {
                    let hard = CertRevocationBuilder::new()
                        .set_signature_creation_time(t)?
                        .set_reason_for_revocation(
                            ReasonForRevocation::KeyCompromised,
                            b"Certificate has been compromised",
                        )?
                        .build(signer, ca_pub, None)?;

                    let header = vec![(
                        "Comment".to_string(),
                        format!("Hard revocation (certificate compromised) ({date})"),
                    )];
                    writeln!(
                        &mut file,
                        "{}\n",
                        &pgp::revoc_to_armored(&hard, Some(header))?
                    )?;

                    Ok(())
                })?;

            self.cb
                .certify(&mut |signer: &mut dyn sequoia_openpgp::crypto::Signer| {
                    let soft = CertRevocationBuilder::new()
                        .set_signature_creation_time(t)?
                        .set_reason_for_revocation(
                            ReasonForRevocation::KeyRetired,
                            b"Certificate retired",
                        )?
                        .build(signer, ca_pub, None)?;

                    let header = vec![(
                        "Comment".to_string(),
                        format!("Soft revocation (certificate retired) ({date})"),
                    )];
                    writeln!(
                        &mut file,
                        "{}\n",
                        &pgp::revoc_to_armored(&soft, Some(header))?
                    )?;

                    Ok(())
                })?;
        }

        Ok(())
    }

    /// Generate a detached signature with the CA key, for 'data'
    fn sign_detached(&self, data: &[u8]) -> Result<String> {
        let mut sink = vec![];

        self.cb
            .sign(&mut |signer: &mut dyn sequoia_openpgp::crypto::Signer| {
                let sig =
                    SignatureBuilder::new(SignatureType::Binary).sign_message(signer, data)?;
                let p = Packet::Signature(sig);

                let mut writer = armor::Writer::new(&mut sink, armor::Kind::Message)?;
                p.export(&mut writer)?;
                writer.finalize()?;

                Ok(())
            })?;

        Ok(std::str::from_utf8(&sink)?.to_string())
    }

    /// Add trust signature to the cert of a remote CA.
    ///
    /// If `scope_regexes` is empty, no regex scoping is added to the trust
    /// signature.
    fn bridge_to_remote_ca(&self, remote_ca: Cert, scope_regexes: Vec<String>) -> Result<Cert> {
        // There should be exactly one User ID in the remote CA Cert
        let uids: Vec<_> = remote_ca.userids().collect();

        if uids.len() == 1 {
            let userid = uids[0].userid();

            let mut packets: Vec<Packet> = Vec::new();

            let mut builder = SignatureBuilder::new(SignatureType::GenericCertification)
                .set_trust_signature(255, 120)?;

            // add all regexes
            for regex in &scope_regexes {
                builder = builder.add_regular_expression(regex.as_bytes())?;
            }

            self.cb
                .certify(&mut |signer: &mut dyn sequoia_openpgp::crypto::Signer| {
                    // Create one tsig for each signer
                    let tsig = userid.bind(signer, &remote_ca, builder.clone())?;
                    packets.push(tsig.into());

                    Ok(())
                })?;

            // FIXME: expiration?

            let signed = remote_ca.insert_packets(packets)?;

            Ok(signed)
        } else {
            Err(anyhow::anyhow!(
                "Remote CA cert doesn't have exactly one User ID"
            ))
        }
    }

    // FIXME: justus thinks this might not be supported by implementations
    fn bridge_revoke(&self, remote_ca: &Cert) -> Result<(Signature, Cert)> {
        // there should be exactly one userid in the remote CA Cert
        let uids: Vec<_> = remote_ca.userids().collect();

        let mut revocation_sig = None;
        let mut revoked = None;

        if uids.len() == 1 {
            let remote_uid = uids[0].userid();

            self.cb
                .certify(&mut |signer: &mut dyn sequoia_openpgp::crypto::Signer| {
                    // set_trust_signature, set_regular_expression(s), expiration
                    let rev = cert::UserIDRevocationBuilder::new()
                        .set_reason_for_revocation(
                            ReasonForRevocation::Unspecified,
                            b"removing OpenPGP CA bridge",
                        )?
                        .build(signer, remote_ca, remote_uid, None)?;

                    revocation_sig = Some(rev.clone());
                    revoked = Some(remote_ca.clone().insert_packets(Packet::from(rev))?);

                    Ok(())
                })?;

            if let (Some(sig), Some(cert)) = (revocation_sig, revoked) {
                Ok((sig, cert))
            } else {
                Err(anyhow::anyhow!("Failed to generate revocation signature"))
            }
        } else {
            Err(anyhow::anyhow!(
                "expect remote CA cert to have exactly one user_id"
            ))
        }
    }
}
