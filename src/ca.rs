// Copyright 2019-2020 Heiko Schaefer heiko@schaefer.name
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// OpenPGP CA is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// OpenPGP CA is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with OpenPGP CA.  If not, see <https://www.gnu.org/licenses/>.

//! OpenPGP CA as a library
//!
//! Example usage:
//! ```
//! # use openpgp_ca_lib::ca::OpenpgpCa;
//! # use tempfile;
//! // all state of an OpenPGP CA instance is persisted in one SQLite database
//! let db_filename = "/tmp/openpgp-ca.sqlite";
//! # // for Doc-tests we need a random database filename
//! # let file = tempfile::NamedTempFile::new().unwrap();
//! # let db_filename = file.path().to_str().unwrap();
//!
//! // start a new OpenPGP CA instance (implicitely creates the database file)
//! let openpgp_ca = OpenpgpCa::new(Some(db_filename)).expect("Failed to set up CA");
//!
//! // initialize the CA Admin (with domainname and a symbolic name)
//! openpgp_ca.ca_init("example.org", Some("Example Org OpenPGP CA Key")).unwrap();
//!
//! // create a new user, with all signatures
//! // (the private key is printed to stdout and needs to be manually
//! // processed from there)
//! openpgp_ca.usercert_new(Some(&"Alice"), &["alice@example.org"], false).unwrap();
//! ```

use std::collections::{HashMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::SystemTime;

use sequoia_openpgp as openpgp;

use openpgp::cert::amalgamation::ValidateAmalgamation;
use openpgp::packet::Signature;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::{Cert, Fingerprint, KeyID, Packet};

use crate::db::Db;
use crate::models;
use crate::pgp::Pgp;

use crate::models::Revocation;
use anyhow::{Context, Result};

/// OpenpgpCa exposes the functionality of OpenPGP CA as a library
/// (the command line utility 'openpgp-ca' is built on top of this library)
pub struct OpenpgpCa {
    db: Db,
}

impl OpenpgpCa {
    /// Instantiate a new OpenpgpCa object.
    ///
    /// The SQLite backend filename can be configured:
    /// - explicitly via the db_url parameter,
    /// - the environment variable OPENPGP_CA_DB, or
    /// - the .env DATABASE_URL
    pub fn new(db_url: Option<&str>) -> Result<Self> {
        let db_url = if let Some(s) = db_url {
            Some(s.to_owned())
        } else if let Ok(database) = env::var("OPENPGP_CA_DB") {
            Some(database)
        } else {
            // load config from .env
            dotenv::dotenv().ok();

            // diesel naming convention for .env
            Some(env::var("DATABASE_URL").unwrap())
        };

        let db = Db::new(db_url.as_deref())?;
        db.migrations();

        Ok(OpenpgpCa { db })
    }

    // -------- CAs

    /// Initialize OpenPGP CA Admin database entry.
    ///
    /// This generates a new OpenPGP Key for the Admin role and stores the
    /// private Key in the OpenPGP CA database.
    ///
    /// `domainname` is the domain that this CA Admin is in charge of,
    /// `name` is a descriptive name for the CA Admin
    ///
    /// Only one CA Admin can be configured per database.
    pub fn ca_init(&self, domainname: &str, name: Option<&str>) -> Result<()> {
        if self.db.get_ca()?.is_some() {
            return Err(
                anyhow::anyhow!("ERROR: CA has already been created",),
            );
        }

        // domainname syntax check
        if !publicsuffix::Domain::has_valid_syntax(domainname) {
            return Err(anyhow::anyhow!(
                "Parameter is not a valid domainname",
            ));
        }

        let name = match name {
            Some(name) => Some(name),
            _ => Some("OpenPGP CA"),
        };

        let (cert, _) = Pgp::make_ca_cert(domainname, name)?;

        let ca_key = &Pgp::priv_cert_to_armored(&cert)?;

        self.db.insert_ca(models::NewCa { domainname }, ca_key)?;

        Ok(())
    }

    /// Get the Ca and Cacert objects from the database
    ///
    /// The Ca object is permanent and shouldn't change after initial
    /// creation.
    ///
    /// The Cacert contains the Key material for the CA.
    /// When the CA Cert gets updated (e.g. it gets signed by a CA user), the
    /// Cert in the database will be updated.
    ///
    /// If a new Cert gets created for the CA, a new Cacert row is
    /// inserted into the database.
    pub fn ca_get(&self) -> Result<Option<(models::Ca, models::Cacert)>> {
        self.db.get_ca()
    }

    /// Get a sequoia `Cert` object for the CA from the database.
    ///
    /// This is the "private" OpenPGP Cert of the CA.
    pub fn ca_get_cert(&self) -> Result<Cert> {
        match self.db.get_ca()? {
            Some((_, cert)) => Ok(Pgp::armored_to_cert(&cert.cert)?),
            _ => panic!("get_ca_cert() failed"),
        }
    }

    /// Print information about the Ca to stdout.
    ///
    /// This shows the domainname of this OpenPGP CA instance and the
    /// private Cert of the CA.
    pub fn ca_show(&self) -> Result<()> {
        let (ca, ca_cert) = self
            .db
            .get_ca()
            .context("failed to load CA from database")?
            .unwrap();
        println!("\nOpenPGP CA for Domain: {}", ca.domainname);
        println!();
        println!("{}", ca_cert.cert);
        Ok(())
    }

    /// Returns the public key of the CA as an armored String
    pub fn ca_get_pubkey_armored(&self) -> Result<String> {
        let cert = self.ca_get_cert()?;
        let ca_pub = Pgp::cert_to_armored(&cert)
            .context("failed to transform CA key to armored pubkey")?;

        Ok(ca_pub)
    }

    /// Add trust-signature(s) from CA users to the CA's Cert.
    ///
    /// This receives an armored version of the CA's public key, finds
    /// any trust-signatures on it and merges those into "our" local copy of
    /// the CA key.
    pub fn ca_import_tsig(&self, key: &str) -> Result<()> {
        use diesel::prelude::*;
        self.db.get_conn().transaction::<_, anyhow::Error, _>(|| {
            let ca_cert = self.ca_get_cert().unwrap();

            let cert_import = Pgp::armored_to_cert(key)?;

            // make sure the keys have the same Fingerprint
            if ca_cert.fingerprint() != cert_import.fingerprint() {
                return Err(anyhow::anyhow!(
                    "The imported cert has an unexpected Fingerprint",
                ));
            }

            // get the tsig(s) from import
            let tsigs = Self::get_trust_sigs(&cert_import)?;

            // add tsig(s) to our "own" version of the CA key
            let mut packets: Vec<Packet> = Vec::new();
            tsigs.iter().for_each(|s| packets.push(s.clone().into()));

            let signed = ca_cert
                .merge_packets(packets)
                .context("merging tsigs into CA Key failed")?;

            // update in DB
            let (_, mut ca_cert) = self
                .db
                .get_ca()
                .context("failed to load CA from database")?
                .unwrap();

            ca_cert.cert = Pgp::priv_cert_to_armored(&signed)
                .context("failed to armor CA Cert")?;

            self.db
                .update_cacert(&ca_cert)
                .context("Update of CA Cert in DB failed")?;

            Ok(())
        })
    }

    // -------- usercerts

    /// Create a new OpenPGP CA User.
    ///
    /// The CA Cert is automatically trust-signed with this new user
    /// Cert and the user Cert is signed by the CA. This is the
    /// "Centralized key creation workflow"
    ///
    /// This generates a new OpenPGP Cert for the new User.
    /// The private Cert material is printed to stdout and NOT stored
    /// in OpenPGP CA.
    ///
    /// The public Cert is stored in the OpenPGP CA database.
    pub fn usercert_new(
        &self,
        name: Option<&str>,
        emails: &[&str],
        password: bool,
    ) -> Result<()> {
        let ca_cert = self.ca_get_cert().unwrap();

        // make user key (signed by CA)
        let (user, revoc, pass) = Pgp::make_user_cert(emails, name, password)
            .context("make_user failed")?;

        // sign user key with CA key
        let certified = Pgp::sign_user_emails(&ca_cert, &user, Some(emails))
            .context("sign_user failed")?;

        // user tsigns CA key
        let tsigned_ca = Pgp::tsign_ca(ca_cert, &user, pass.as_deref())
            .context("failed: user tsigns CA")?;

        let tsigned_ca_armored = Pgp::priv_cert_to_armored(&tsigned_ca)?;

        let pub_key = &Pgp::cert_to_armored(&certified)?;
        let revoc = Pgp::sig_to_armored(&revoc)?;

        let res = self.db.add_usercert(
            name,
            (pub_key, &user.fingerprint().to_hex()),
            emails,
            &[revoc],
            Some(&tsigned_ca_armored),
            None,
        );

        if res.is_err() {
            eprint!("{:?}", res);
            return Err(anyhow::anyhow!("Couldn't insert user"));
        }

        // the private key needs to be handed over to the user, print for now
        println!(
            "new user key for {}:\n{}",
            name.unwrap_or(""),
            &Pgp::priv_cert_to_armored(&certified)?
        );
        if let Some(pass) = pass {
            println!("password for this key: '{}'\n", pass);
        } else {
            println!("no password set for this key\n");
        }
        // --

        Ok(())
    }

    /// update existing or create independent new usercert,
    /// receives a pub cert from armored string
    fn usercert_import_update_or_create(
        &self,
        key: &str,
        revoc_certs: Vec<String>,
        name: Option<&str>,
        emails: &[&str],
        updates_id: Option<i32>,
    ) -> Result<()> {
        let user_cert = Pgp::armored_to_cert(&key)?;

        let existing =
            self.db.get_usercert(&user_cert.fingerprint().to_hex())?;

        // check if a usercert with this fingerprint already exists?
        if let Some(mut existing) = existing {
            // yes - update existing Usercert in DB

            if updates_id.is_some() && updates_id.unwrap() != existing.id {
                return Err(anyhow::anyhow!(
                    "updates_id was specified, but is inconsistent for key update"
                ));
            }

            // set of email addresses should be the same
            let existing_emails: HashSet<_> = self
                .db
                .get_emails_by_usercert(&existing)?
                .iter()
                .map(|e| e.addr.to_owned())
                .collect();
            let emails: HashSet<_> =
                emails.iter().map(|&s| s.to_string()).collect();

            if emails != existing_emails {
                return Err(anyhow::anyhow!(
                    "expecting the same set of email addresses on key update",
                ));
            }

            // FIXME: should the CA sign this cert?

            // this "update" workflow is not handling revocation certs for now
            if !revoc_certs.is_empty() {
                return Err(anyhow::anyhow!(
                    "not expecting a revocation cert on key update",
                ));
            }

            // merge existing and new public key, update in DB usercert
            let c1 = Pgp::armored_to_cert(&existing.pub_cert)?;

            let updated = c1.merge(user_cert)?;
            let armored = Pgp::cert_to_armored(&updated)?;

            existing.pub_cert = armored;
            self.db.update_usercert(&existing)?;
        } else {
            // no - this is a new usercert that we need to create in the DB

            let ca_cert = self.ca_get_cert().unwrap();

            // sign only the User IDs that have been specified
            let certified =
                Pgp::sign_user_emails(&ca_cert, &user_cert, Some(emails))?;

            // use name from User IDs, if no name was passed
            let name = match name {
                Some(name) => Some(name.to_owned()),
                None => {
                    let userids: Vec<_> = user_cert.userids().collect();
                    if userids.len() == 1 {
                        let userid = &userids[0];
                        userid.userid().name()?
                    } else {
                        None
                    }
                }
            };

            // use emails from User IDs, if no emails were passed
            let emails = if !emails.is_empty() {
                emails.iter().map(|&s| s.to_owned()).collect()
            } else {
                let userids: Vec<_> = user_cert.userids().collect();
                let emails: Vec<String> = userids
                    .iter()
                    .map(|uid| uid.userid().email().unwrap_or(None).unwrap())
                    .collect();
                emails
            };

            // map Vec<String> -> Vec<&str>
            let emails: Vec<&str> = emails.iter().map(|s| &**s).collect();

            let pub_key = &Pgp::cert_to_armored(&certified)?;

            self.db.add_usercert(
                name.as_deref(),
                (pub_key, &certified.fingerprint().to_hex()),
                &emails[..],
                &revoc_certs,
                None,
                updates_id,
            )?;
        }

        Ok(())
    }

    /// Import an existing OpenPGP public Cert a new OpenPGP CA user.
    ///
    /// The `key` is expected as an armored public key.
    ///
    /// userids that correspond to `emails` will be signed by the CA.
    ///
    /// A symbolic `name` and a list of `emails` for this User can
    /// optionally be supplied. If those are not set, emails are taken from
    /// the list of userids in the public key. Also, if the
    /// key has exactly one userid, the symbolic name is taken from that
    /// userid.
    ///
    /// Optionally a revocation certificate can be supplied.
    pub fn usercert_import_new(
        &self,
        key: &str,
        revoc_certs: Vec<String>,
        name: Option<&str>,
        emails: &[&str],
    ) -> Result<()> {
        self.usercert_import_update_or_create(
            key,
            revoc_certs,
            name,
            emails,
            None,
        )
    }

    /// Import an updated public Key for an existing usercert
    pub fn usercert_import_update(
        &self,
        key: &str,
        usercert: &models::Usercert,
    ) -> Result<()> {
        // FIXME: If the fingerprint is the same, key data is merged.
        // FIXME: Is a new usercert created if the fingerprint differs?
        //         -> what should happen!?

        let emails = self.db.get_emails_by_usercert(usercert)?;
        let emails: Vec<_> = emails.iter().map(|e| e.addr.as_str()).collect();

        self.usercert_import_update_or_create(
            key,
            vec![],
            usercert.name.as_deref(),
            &emails[..],
            Some(usercert.id),
        )
    }

    /// Get the SystemTime for when the specified Usercert will expire
    pub fn usercert_expiration(
        usercert: &models::Usercert,
    ) -> Result<Option<SystemTime>> {
        let cert = Pgp::armored_to_cert(&usercert.pub_cert)?;
        Ok(Pgp::get_expiry(&cert)?)
    }

    /// Which usercerts will be expired in 'days' days?
    pub fn usercerts_expired(
        &self,
        days: u64,
    ) -> Result<HashMap<models::Usercert, (bool, Option<SystemTime>)>> {
        let mut map = HashMap::new();

        let days = Duration::new(60 * 60 * 24 * days, 0);
        let expiry_test = SystemTime::now().checked_add(days).unwrap();

        let usercerts = self
            .usercerts_get_all()
            .context("couldn't load usercerts")?;

        for usercert in usercerts {
            let cert = Pgp::armored_to_cert(&usercert.pub_cert)?;
            let exp = Pgp::get_expiry(&cert)?;
            let alive = cert
                .with_policy(&StandardPolicy::new(), expiry_test)?
                .alive()
                .is_ok();
            // cert.alive(&StandardPolicy::new(), expiry_test).is_ok();

            map.insert(usercert, (alive, exp));
        }

        Ok(map)
    }

    /// Check if a usercert is "possibly revoked"
    pub fn usercert_possibly_revoked(
        usercert: &models::Usercert,
    ) -> Result<bool> {
        let cert = Pgp::armored_to_cert(&usercert.pub_cert)?;
        Ok(Pgp::is_possibly_revoked(&cert))
    }

    /// For each user Cert, check if:
    /// - the user's Cert has been signed by the CA, and
    /// - the CA key has a trust-signature from the user's Cert
    ///
    /// Returns a map 'usercert -> (sig_from_ca, tsig_on_ca)'
    pub fn usercerts_check_certifications(
        &self,
    ) -> Result<HashMap<models::Usercert, (bool, bool)>> {
        let mut map = HashMap::new();

        let usercerts = self
            .usercerts_get_all()
            .context("couldn't load usercerts")?;

        for usercert in usercerts {
            let sig_from_ca = self
                .usercert_check_ca_sig(&usercert)
                .context("Failed while checking CA sig")?;

            let tsig_on_ca = self
                .usercert_check_tsig_on_ca(&usercert)
                .context("Failed while checking tsig on CA")?;

            map.insert(usercert, (sig_from_ca, tsig_on_ca));
        }

        Ok(map)
    }

    /// Check if this Usercert has been signed by the CA Key
    pub fn usercert_check_ca_sig(
        &self,
        usercert: &models::Usercert,
    ) -> Result<bool> {
        let user_cert = Pgp::armored_to_cert(&usercert.pub_cert)?;
        let sigs = Self::get_third_party_sigs(&user_cert)?;

        let ca = self.ca_get_cert()?;

        Ok(sigs
            .iter()
            .any(|s| s.issuer_fingerprint().unwrap() == &ca.fingerprint()))
    }

    /// Check if this Usercert has tsigned the CA Key
    pub fn usercert_check_tsig_on_ca(
        &self,
        usercert: &models::Usercert,
    ) -> Result<bool> {
        let ca = self.ca_get_cert()?;
        let tsigs = Self::get_trust_sigs(&ca)?;

        let user_cert = Pgp::armored_to_cert(&usercert.pub_cert)?;

        Ok(tsigs.iter().any(|t| {
            t.issuer_fingerprint().unwrap() == &user_cert.fingerprint()
        }))
    }

    /// Get sequoia Cert representation of a Usercert
    pub fn usercert_to_cert(usercert: &models::Usercert) -> Result<Cert> {
        Pgp::armored_to_cert(&usercert.pub_cert)
    }

    /// Get the armored "public key" representation of a Cert
    pub fn cert_to_armored(cert: &Cert) -> Result<String> {
        Pgp::cert_to_armored(cert)
    }

    /// Get a list of all Usercerts
    pub fn usercerts_get_all(&self) -> Result<Vec<models::Usercert>> {
        self.db.get_all_usercerts()
    }

    /// Get a list of the Usercerts that are associated with `email`
    pub fn usercerts_get(&self, email: &str) -> Result<Vec<models::Usercert>> {
        self.db.get_usercerts(email)
    }

    // -------- revocations

    /// Add a revocation certificate to the OpenPGP CA database (from a file).
    ///
    /// The matching usercert is looked up by issuer Fingerprint, if
    /// possible - or by exhaustive search otherwise.
    ///
    /// Verifies that applying the revocation cert can be validated by the
    /// usercert. Only if this is successful is the revocation stored.
    pub fn revocation_add(&self, revoc_file: &PathBuf) -> Result<()> {
        let revoc_cert = Pgp::load_revocation_cert(Some(revoc_file))
            .context("Couldn't load revocation cert")?;

        // find the matching usercert for this revocation certificate
        let mut usercert = None;
        // - search by fingerprint, if possible
        if let Some(sig_fingerprint) = Pgp::get_revoc_issuer_fp(&revoc_cert) {
            usercert = self.db.get_usercert(&sig_fingerprint.to_hex())?;
        }
        // - if match by fingerprint failed: test all usercerts
        if usercert.is_none() {
            usercert = self.search_revocable_usercert_by_keyid(&revoc_cert)?;
        }

        if let Some(usercert) = usercert {
            let cert = Pgp::armored_to_cert(&usercert.pub_cert)?;

            // verify that revocation certificate validates with cert
            if Self::validate_revocation(&cert, &revoc_cert)? {
                // update sig in DB
                let armored = Pgp::sig_to_armored(&revoc_cert)
                    .context("couldn't armor revocation cert")?;

                self.db.add_revocation(&armored, &usercert)?;

                Ok(())
            } else {
                let msg = format!(
                    "revocation couldn't be matched to a usercert: {:?}",
                    revoc_cert
                );

                Err(anyhow::anyhow!(msg))
            }
        } else {
            Err(anyhow::anyhow!("couldn't find cert for this fingerprint"))
        }
    }

    /// verify that applying `revoc_cert` to `cert` yields a new validated
    /// self revocation
    fn validate_revocation(
        cert: &Cert,
        revoc_cert: &Signature,
    ) -> Result<bool> {
        let before = cert.primary_key().self_revocations().len();

        let revoked = cert.to_owned().merge_packets(revoc_cert.to_owned())?;

        let after = revoked.primary_key().self_revocations().len();

        // expecting an additional self_revocation after merging revoc_cert
        if before + 1 != after {
            return Ok(false);
        }

        // does the self revocation verify?
        let key = revoked.primary_key().key();
        Ok(revoc_cert.verify_primary_key_revocation(key, key).is_ok())
    }

    /// Search all usercerts for the one that `revoc` can revoke.
    ///
    /// This assumes that the Signature has no issuer fingerprint.
    /// So if the Signature also has no issuer KeyID, it fails to find a
    /// usercert.
    fn search_revocable_usercert_by_keyid(
        &self,
        revoc: &Signature,
    ) -> Result<Option<models::Usercert>> {
        let r_keyid = revoc.issuer();
        if r_keyid.is_none() {
            return Err(anyhow::anyhow!("Signature has no issuer KeyID"));
        }
        let r_keyid = r_keyid.unwrap();

        for usercert in self.usercerts_get_all()? {
            let cert = Pgp::armored_to_cert(&usercert.pub_cert)?;

            // require that keyid of cert and Signature issuer match
            let c_keyid = cert.keyid();
            if &c_keyid != r_keyid {
                // ignore usercerts with non-matching KeyID
                continue;
            }

            // if KeyID matches, check if revocation validates
            if Self::validate_revocation(&cert, &revoc)? {
                return Ok(Some(usercert));
            }
        }
        Ok(None)
    }

    /// Get a list of all Revocations for a usercert
    pub fn revocations_get(
        &self,
        usercert: &models::Usercert,
    ) -> Result<Vec<models::Revocation>> {
        self.db.get_revocations(usercert)
    }

    /// Get reason and creation time for a Revocation
    pub fn revocation_details(
        &self,
        revocation: &Revocation,
    ) -> Result<(String, Option<SystemTime>)> {
        let rev = Pgp::armored_to_signature(&revocation.revocation)?;

        let creation = rev.signature_creation_time();

        if let Some((code, reason)) = rev.reason_for_revocation() {
            let reason = String::from_utf8(reason.to_vec())?;
            Ok((format!("{} ({})", code.to_string(), reason), creation))
        } else {
            Ok(("Revocation reason unknown".to_string(), creation))
        }
    }

    /// Get a Revocation by hash
    pub fn revocation_get_by_hash(
        &self,
        hash: &str,
    ) -> Result<models::Revocation> {
        if let Some(rev) = self.db.get_revocation_by_hash(hash)? {
            Ok(rev)
        } else {
            Err(anyhow::anyhow!("no revocation found"))
        }
    }

    /// Apply a revocation.
    ///
    /// The revocation is merged into the OpenPGP Cert of the Usercert.
    pub fn revocation_apply(&self, revoc: models::Revocation) -> Result<()> {
        use diesel::prelude::*;
        self.db.get_conn().transaction::<_, anyhow::Error, _>(|| {
            let usercert = self.db.get_usercert_by_id(revoc.usercert_id)?;

            if let Some(mut usercert) = usercert {
                let sig = Pgp::armored_to_signature(&revoc.revocation)?;
                let cert = Pgp::armored_to_cert(&usercert.pub_cert)?;

                let revocation: Packet = sig.into();
                let revoked = cert.merge_packets(vec![revocation])?;

                usercert.pub_cert = Pgp::cert_to_armored(&revoked)?;

                let mut revoc = revoc.clone();
                revoc.published = true;

                self.db
                    .update_usercert(&usercert)
                    .context("Couldn't update Usercert")?;

                self.db
                    .update_revocation(&revoc)
                    .context("Couldn't update Revocation")?;

                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "Couldn't find usercert for apply_revocation"
                ))
            }
        })
    }

    /// Get an armored representation of a Signature
    pub fn sig_to_armored(sig: &Signature) -> Result<String> {
        Pgp::sig_to_armored(sig)
    }

    // -------- emails

    /// Get all Emails for a Usercert
    pub fn emails_get(
        &self,
        usercert: &models::Usercert,
    ) -> Result<Vec<models::Email>> {
        self.db.get_emails_by_usercert(usercert)
    }

    // -------- bridges

    /// Make regex for trust signature from domain-name
    fn domain_to_regex(domain: &str) -> Result<String> {
        // "other.org" => "<[^>]+[@.]other\\.org>$"
        // FIXME: does this imply "subdomain allowed"?

        // syntax check domain
        if !publicsuffix::Domain::has_valid_syntax(domain) {
            return Err(anyhow::anyhow!(
                "Parameter is not a valid domainname"
            ));
        }

        // transform domain to regex
        let escaped_domain =
            &domain.split('.').collect::<Vec<_>>().join("\\.");
        Ok(format!("<[^>]+[@.]{}>$", escaped_domain))
    }

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
        &self,
        remote_key_file: &PathBuf,
        remote_email: Option<&str>,
        remote_scope: Option<&str>,
    ) -> Result<(models::Bridge, Fingerprint)> {
        let remote_ca_cert =
            Cert::from_file(remote_key_file).context("Failed to read key")?;

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

        let scope = match remote_scope {
            Some(scope) => {
                // if scope and domain don't match, warn/error?
                // (FIXME: error, unless --force parameter has been given?!)
                if scope != remote_cert_domain {
                    return Err(anyhow::anyhow!(
                        "scope and domain don't match, currently unsupported"
                    ));
                }

                scope
            }
            None => &remote_cert_domain,
        };

        let email = match remote_email {
            None => remote_cert_email,
            Some(email) => email.to_owned(),
        };

        let regex = Self::domain_to_regex(scope)?;

        let regexes = vec![regex];

        let bridged = Pgp::bridge_to_remote_ca(
            self.ca_get_cert()?,
            remote_ca_cert,
            regexes,
        )?;

        // store new bridge in DB
        let (ca_db, _) =
            self.db.get_ca().context("Couldn't find CA")?.unwrap();

        let new_bridge = models::NewBridge {
            email: &email,
            scope,
            pub_key: &Pgp::cert_to_armored(&bridged)?,
            cas_id: ca_db.id,
        };

        Ok((self.db.insert_bridge(new_bridge)?, bridged.fingerprint()))
    }

    /// Create a revocation Certificate for a Bridge and apply it the our
    /// copy of the remote CA's public key.
    ///
    /// Both the revoked remote public key and the revocation cert are
    /// printed to stdout.
    pub fn bridge_revoke(&self, email: &str) -> Result<()> {
        let bridge = self.db.search_bridge(email)?;
        if bridge.is_none() {
            return Err(anyhow::anyhow!("bridge not found"));
        }

        let mut bridge = bridge.unwrap();

        //        println!("bridge {:?}", &bridge.clone());
        //        let ca_id = bridge.clone().cas_id;

        let (_, ca_cert) = self.db.get_ca()?.unwrap();
        let ca_cert = Pgp::armored_to_cert(&ca_cert.cert)?;

        let bridge_pub = Pgp::armored_to_cert(&bridge.pub_key)?;

        // make sig to revoke bridge
        let (rev_cert, cert) = Pgp::bridge_revoke(&bridge_pub, &ca_cert)?;

        let revoc_cert_arm = &Pgp::sig_to_armored(&rev_cert)?;
        println!("revoc cert:\n{}", revoc_cert_arm);

        // save updated key (with revocation) to DB
        let revoked_arm = Pgp::cert_to_armored(&cert)?;
        println!("revoked remote key:\n{}", &revoked_arm);

        bridge.pub_key = revoked_arm;
        self.db.update_bridge(&bridge)?;

        Ok(())
    }

    /// Get a list of Bridges
    pub fn bridges_get(&self) -> Result<Vec<models::Bridge>> {
        self.db.list_bridges()
    }

    /// Get a specific Bridge
    pub fn bridges_search(&self, email: &str) -> Result<models::Bridge> {
        if let Some(bridge) = self.db.search_bridge(email)? {
            Ok(bridge)
        } else {
            Err(anyhow::anyhow!("bridge not found"))
        }
    }

    // --------- wkd

    /// Export all user keys (that have a userid in `domain`) and the CA key
    /// into a wkd directory structure
    ///
    /// https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-08
    pub fn wkd_export(&self, domain: &str, path: &Path) -> Result<()> {
        use sequoia_net::wkd;

        let ca_cert = self.ca_get_cert()?;
        wkd::insert(&path, domain, None, &ca_cert)?;

        for uc in self.usercerts_get_all()? {
            let c = Pgp::armored_to_cert(&uc.pub_cert)?;

            if Self::cert_has_uid_in_domain(&c, domain)? {
                wkd::insert(&path, domain, None, &c)?;
            }
        }

        Ok(())
    }

    // -------- update keys from public key sources

    /// Pull a key from WKD and merge any updates into our local version of
    /// this key
    pub fn update_from_wkd(&self, usercert: &models::Usercert) -> Result<()> {
        use sequoia_net::wkd;
        use tokio_core::reactor::Core;

        let emails = self.emails_get(&usercert)?;

        let mut merge = Pgp::armored_to_cert(&usercert.pub_cert)?;

        for email in emails {
            let mut core = Core::new().unwrap();
            let certs = core.run(wkd::get(&email.addr)).unwrap();

            for cert in certs {
                if cert.fingerprint().to_hex() == usercert.fingerprint {
                    merge = merge.merge(cert)?;
                }
            }
        }

        let mut updated = usercert.clone();
        updated.pub_cert = Pgp::cert_to_armored(&merge)?;

        self.db.update_usercert(&updated)?;

        Ok(())
    }

    /// Pull a key from hagrid and merge any updates into our local version of
    /// this key
    pub fn update_from_hagrid(
        &self,
        usercert: &models::Usercert,
    ) -> Result<()> {
        use tokio_core::reactor::Core;

        let mut merge = Pgp::armored_to_cert(&usercert.pub_cert)?;

        // get key from hagrid
        let c = sequoia_core::Context::new()?;
        let mut hagrid = sequoia_net::KeyServer::keys_openpgp_org(&c)?;

        let mut core = Core::new().unwrap();

        let f = (usercert.fingerprint).parse::<Fingerprint>()?;
        let cert = core.run(hagrid.get(&KeyID::from(f)))?;

        // update in DB
        merge = merge.merge(cert)?;

        let mut updated = usercert.clone();
        updated.pub_cert = Pgp::cert_to_armored(&merge)?;

        self.db.update_usercert(&updated)?;

        Ok(())
    }

    // -------- helper functions

    pub fn print_cert_info(armored: &str) -> Result<()> {
        let c = Pgp::armored_to_cert(&armored)?;
        for uid in c.userids() {
            println!("User ID: {}", uid.userid());
        }
        println!("Fingerprint '{}'", c);
        Ok(())
    }

    /// Is any uid of this cert for an email address in "domain"?
    fn cert_has_uid_in_domain(c: &Cert, domain: &str) -> Result<bool> {
        for uid in c.userids() {
            // is any uid in domain
            let email = uid.email()?;
            if let Some(email) = email {
                let split: Vec<_> = email.split('@').collect();

                if split.len() != 2 {
                    return Err(anyhow::anyhow!("unexpected email format"));
                }

                if split[1] == domain {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Get all trust sigs on User IDs in this Cert
    fn get_trust_sigs(c: &Cert) -> Result<Vec<Signature>> {
        Ok(Self::get_third_party_sigs(c)?
            .iter()
            .filter(|s| s.trust_signature().is_some())
            .cloned()
            .collect())
    }

    /// Get all third party sigs on User IDs in this Cert
    fn get_third_party_sigs(c: &Cert) -> Result<Vec<Signature>> {
        let mut res = Vec::new();
        let policy = StandardPolicy::new();

        for uid in c.userids() {
            let sigs =
                uid.with_policy(&policy, None)?.bundle().certifications();
            sigs.iter().for_each(|s| res.push(s.clone()));
        }

        Ok(res)
    }
}
