// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::ca::DbCa;
use crate::db::models;
use crate::pgp::Pgp;

use sequoia_openpgp::cert;
use sequoia_openpgp::cert::CertRevocationBuilder;
use sequoia_openpgp::packet::{signature, Signature, UserID};
use sequoia_openpgp::serialize::stream::Armorer;
use sequoia_openpgp::serialize::stream::{Message, Signer};
use sequoia_openpgp::types::{ReasonForRevocation, SignatureType};
use sequoia_openpgp::{Cert, Packet};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use sequoia_openpgp::packet::signature::SignatureBuilder;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Abstraction of operations that need private key material
pub trait CaSec {
    /// Initialize OpenPGP CA Admin database entry.
    ///
    /// This generates a new OpenPGP Key for the Admin role and stores the
    /// private Key in the OpenPGP CA database.
    ///
    /// `domainname` is the domain that this CA Admin is in charge of,
    /// `name` is a descriptive name for the CA Admin
    ///
    /// Only one CA Admin can be configured per database.
    fn ca_init(&self, domainname: &str, name: Option<&str>) -> Result<()>;

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
    fn ca_generate_revocations(&self, output: PathBuf) -> Result<()>;

    /// Add trust-signature(s) from CA users to the CA's Cert.
    ///
    /// This receives an armored version of the CA's public key, finds
    /// any trust-signatures on it and merges those into "our" local copy of
    /// the CA key.
    ///
    /// FIXME: should this be in ca_public?
    fn ca_import_tsig(&self, cert: &str) -> Result<()>;

    /// Generate a detached signature with the CA key, for 'text'
    fn sign_detached(&self, text: &str) -> Result<String>;

    fn sign_user_ids(
        &self,
        user_cert: &Cert,
        uids_certify: &[&UserID],
        duration_days: Option<u64>,
    ) -> Result<Cert>;

    fn bridge_to_remote_ca(
        &self,
        remote_ca_cert: Cert,
        scope_regexes: Vec<String>,
    ) -> Result<Cert>;

    fn bridge_revoke(
        &self,
        remote_ca_cert: &Cert,
    ) -> Result<(Signature, Cert)>;

    /// Get a sequoia `Cert` object for the CA from the database.
    ///
    /// This returns a full version of the CA Cert, including private key
    /// material.
    ///
    /// This is the OpenPGP Cert of the CA.
    ///
    /// CAUTION: getting the private key is not possible for OpenPGP cards,
    /// this fn should only be used for tests.
    fn ca_get_priv_key(&self) -> Result<Cert>;
}

/// Implementation of CaSec based on a DbCa backend that contains the
/// private key material for the CA.
impl CaSec for DbCa {
    fn ca_init(&self, domainname: &str, name: Option<&str>) -> Result<()> {
        if self.db().is_ca_initialized()? {
            return Err(anyhow::anyhow!("CA has already been initialized",));
        }

        // domainname syntax check
        if !publicsuffix::Domain::has_valid_syntax(domainname) {
            return Err(anyhow::anyhow!(
                "Invalid domainname: '{}'",
                domainname
            ));
        }

        let name = match name {
            Some(name) => Some(name),
            _ => Some("OpenPGP CA"),
        };

        let (cert, _) = Pgp::make_ca_cert(domainname, name)?;

        let ca_key = &Pgp::cert_to_armored_private_key(&cert)?;

        self.db().ca_insert(
            models::NewCa { domainname },
            ca_key,
            &cert.fingerprint().to_hex(),
        )
    }

    fn ca_generate_revocations(&self, output: PathBuf) -> Result<()> {
        let ca = self.ca_get_priv_key()?;

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

        writeln!(&mut file, "{}\n\n", msg)?;

        writeln!(
            &mut file,
            "For reference, the certificate of your CA is\n\n{}\n",
            Pgp::cert_to_armored(&ca)?
        )?;

        writeln!(
            &mut file,
            "Revocation certificates (ordered by 'creation time') follow:\n"
        )?;

        let now = SystemTime::now();
        let thirty_days = Duration::new(30 * 24 * 60 * 60, 0);

        let mut signer = ca
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()?
            .into_keypair()?;

        for i in 0..=120 {
            let t = now + i * thirty_days;

            let dt: DateTime<Utc> = t.into();
            let date = dt.format("%Y-%m-%d");

            let hard = CertRevocationBuilder::new()
                .set_signature_creation_time(t)?
                .set_reason_for_revocation(
                    ReasonForRevocation::KeyCompromised,
                    b"Certificate has been compromised",
                )?
                .build(&mut signer, &ca, None)?;

            let header = vec![(
                "Comment".to_string(),
                format!(
                    "Hard revocation (certificate compromised) ({})",
                    date
                ),
            )];
            writeln!(
                &mut file,
                "{}\n",
                &Pgp::revoc_to_armored(&hard, Some(header))?
            )?;

            let soft = CertRevocationBuilder::new()
                .set_signature_creation_time(t)?
                .set_reason_for_revocation(
                    ReasonForRevocation::KeyRetired,
                    b"Certificate retired",
                )?
                .build(&mut signer, &ca, None)?;

            let header = vec![(
                "Comment".to_string(),
                format!("Soft revocation (certificate retired) ({})", date),
            )];
            writeln!(
                &mut file,
                "{}\n",
                &Pgp::revoc_to_armored(&soft, Some(header))?
            )?;
        }

        Ok(())
    }

    /// Accept a copy of the CA certificate that includes one or more trust
    /// signatures from third parties. Take those third party trust
    /// signatures and merge them into our local copy of the CA key.
    fn ca_import_tsig(&self, cert: &str) -> Result<()> {
        let ca_cert = self.ca_get_priv_key()?;

        let cert_import = Pgp::armored_to_cert(cert)?;

        // The imported cert must have the same Fingerprint as the CA cert
        if ca_cert.fingerprint() != cert_import.fingerprint() {
            return Err(anyhow::anyhow!(
                "The imported cert has an unexpected Fingerprint",
            ));
        }

        // Get the third party tsig(s) from the imported cert
        let tsigs = Pgp::get_trust_sigs(&cert_import)?;

        // add tsig(s) to our "own" version of the CA key
        let mut packets: Vec<Packet> = Vec::new();
        tsigs.iter().for_each(|s| packets.push(s.clone().into()));

        let signed = ca_cert
            .insert_packets(packets)
            .context("Merging tsigs into CA Key failed")?;

        // update in DB
        let (_, mut cacert) = self
            .db()
            .get_ca()
            .context("Failed to load CA cert from database")?;

        cacert.priv_cert = Pgp::cert_to_armored_private_key(&signed)
            .context("Failed to re-armor CA Cert")?;

        self.db()
            .cacert_update(&cacert)
            .context("Update of CA Cert in DB failed")
    }

    fn sign_detached(&self, text: &str) -> Result<String> {
        let ca_cert = self.ca_get_priv_key()?;

        let signing_keypair = ca_cert
            .keys()
            .secret()
            .with_policy(Pgp::SP, None)
            .supported()
            .alive()
            .revoked(false)
            .for_signing()
            .next()
            .unwrap()
            .key()
            .clone()
            .into_keypair()?;

        let mut sink = vec![];
        {
            let message = Message::new(&mut sink);
            let message = Armorer::new(message).build()?;

            let mut signer =
                Signer::new(message, signing_keypair).detached().build()?;

            // Write the data directly to the `Signer`.
            signer.write_all(text.as_bytes())?;
            signer.finalize()?;
        }

        Ok(std::str::from_utf8(&sink)?.to_string())
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
    ) -> Result<Cert> {
        let ca_cert = self.ca_get_priv_key()?;
        let mut ca_keys = Pgp::get_cert_keys(&ca_cert, None);

        // Collect certifications by the CA
        let mut packets: Vec<Packet> = Vec::new();

        let userids = cert
            .userids()
            // sign only userids that are in "uids_certify"
            .filter(|u| uids_certify.contains(&u.userid()))
            .map(|u| u.userid());

        for userid in userids {
            for signer in &mut ca_keys {
                // make certification
                let mut sb = signature::SignatureBuilder::new(
                    SignatureType::GenericCertification,
                );

                // If an expiration setting for the certifications has been
                // provided, apply it to the signatures
                if let Some(days) = duration_days {
                    // The signature should be valid for the specified
                    // number of `days`
                    sb = sb.set_signature_validity_period(
                        Duration::from_secs(Pgp::SECONDS_IN_DAY * days),
                    )?;
                }

                // Include 'Signer's UserID' packet
                // (https://tools.ietf.org/html/rfc4880#section-5.2.3.22)
                // to make it easier to find the CA key via WKD
                if let Some(uid) = ca_cert.userids().next() {
                    sb = sb.set_signers_user_id(uid.userid().value())?;
                } else {
                    return Err(anyhow::anyhow!(
                        "ERROR: No User ID in CA cert. \
                        This should never happen."
                    ));
                }

                let sig = userid.bind(signer, cert, sb)?;

                // Collect certifications
                packets.push(sig.into());
            }
        }

        // Insert all newly created certifications into the user cert
        cert.clone().insert_packets(packets)
    }

    /// Add trust signature to the cert of a remote CA.
    ///
    /// If `scope_regexes` is empty, no regex scoping is added to the trust
    /// signature.
    fn bridge_to_remote_ca(
        &self,
        remote_ca: Cert,
        scope_regexes: Vec<String>,
    ) -> Result<Cert> {
        let ca_cert = self.ca_get_priv_key()?;

        // There should be exactly one User ID in the remote CA Cert
        let uids: Vec<_> = remote_ca.userids().collect();

        if uids.len() == 1 {
            let userid = uids[0].userid();

            let mut ca_keys = Pgp::get_cert_keys(&ca_cert, None);

            let mut packets: Vec<Packet> = Vec::new();

            // Create one tsig for each signer
            for signer in &mut ca_keys {
                let mut builder =
                    SignatureBuilder::new(SignatureType::GenericCertification)
                        .set_trust_signature(255, 120)?;

                // add all regexes
                for regex in &scope_regexes {
                    builder =
                        builder.add_regular_expression(regex.as_bytes())?;
                }

                let tsig = userid.bind(signer, &remote_ca, builder)?;

                packets.push(tsig.into());
            }

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

        if uids.len() == 1 {
            let remote_uid = uids[0].userid();

            let ca_cert = self.ca_get_priv_key()?;

            // set_trust_signature, set_regular_expression(s), expiration
            let mut cert_keys = Pgp::get_cert_keys(&ca_cert, None);

            // this CA should have exactly one key that can certify
            if cert_keys.len() != 1 {
                return Err(anyhow::anyhow!(
                    "this CA should have exactly one key that can certify",
                ));
            }

            let signer = &mut cert_keys[0];

            let revocation_sig = cert::UserIDRevocationBuilder::new()
                .set_reason_for_revocation(
                    ReasonForRevocation::Unspecified,
                    b"removing OpenPGP CA bridge",
                )?
                .build(signer, &remote_ca, remote_uid, None)?;

            let revoked = remote_ca
                .clone()
                .insert_packets(Packet::from(revocation_sig.clone()))?;

            Ok((revocation_sig, revoked))
        } else {
            Err(anyhow::anyhow!(
                "expect remote CA cert to have exactly one user_id",
            ))
        }
    }

    fn ca_get_priv_key(&self) -> Result<Cert> {
        let (_, cert) = self.db().get_ca()?;

        Pgp::armored_to_cert(&cert.priv_cert)
    }
}