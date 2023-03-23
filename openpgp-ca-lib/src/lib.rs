// SPDX-FileCopyrightText: 2019-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

//! OpenPGP CA functionality as a library
//!
//! Example usage:
//! ```
//! # use openpgp_ca_lib::Uninit;
//! # use tempfile;
//! // all state of an OpenPGP CA instance is persisted in one SQLite database
//! let db_filename = "/tmp/openpgp-ca.sqlite";
//! # // for Doc-tests we need a random database filename
//! # let file = tempfile::NamedTempFile::new().unwrap();
//! # let db_filename = file.path().to_str().unwrap();
//!
//! // Set up a new, uninitialized OpenPGP CA database
//! // (implicitly creates the database file).
//! let ca_uninit = Uninit::new(Some(db_filename)).expect("Failed to set up CA");
//!
//! // Initialize the CA, create the CA key (with domain name and descriptive name)
//! let ca = ca_uninit
//!     .init_softkey("example.org", Some("Example Org OpenPGP CA Key"))
//!     .unwrap();
//!
//! // Create a new user, certified by the CA, and a trust signature by the user
//! // key on the CA key.
//! //
//! // The new private key for the user is printed to stdout and needs to be manually
//! // processed from there.
//! ca.user_new(Some(&"Alice"), &["alice@example.org"], None, false, false)
//!     .unwrap();
//! ```

#[macro_use]
extern crate diesel;

#[macro_use]
extern crate diesel_migrations;

/// The version of this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

mod backend;
mod bridge;
mod cert;
pub mod db;
mod export;
pub mod pgp;
mod revocation;
mod secret;
mod storage;
pub mod types;
mod update;

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::str::FromStr;
use std::time::SystemTime;

use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine};
use chrono::offset::Utc;
use chrono::DateTime;
use openpgp_card::algorithm::AlgoSimple;
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::state::Transaction;
use openpgp_card_sequoia::{state::Open, Card};
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::{Marshal, SerializeInto};
use sequoia_openpgp::Cert;

use crate::backend::card::{check_card_empty, CardBackend};
use crate::backend::softkey::SoftkeyBackend;
use crate::backend::split::SplitCa;
use crate::backend::{card, split, Backend};
use crate::db::models;
use crate::db::OcaDb;
use crate::secret::{CaSec, CaSecCB};
use crate::storage::{CaStorageRW, DbCa, UninitDb};
use crate::types::CertificationStatus;

/// List of cards that are blank (no fingerprint in any slot)
pub fn blank_cards() -> Result<Vec<String>> {
    let mut idents = vec![];

    for backend in PcscBackend::cards(None)? {
        let mut card: Card<Open> = backend.into();
        let transaction = card.transaction()?;

        if check_card_empty(&transaction)? {
            idents.push(transaction.application_identifier()?.ident());
        }
    }

    Ok(idents)
}

/// List of cards that match the CA cert `cert`
pub fn matching_cards(ca_cert: &[u8]) -> Result<Vec<String>> {
    let ca_cert = Cert::from_bytes(ca_cert).context("Cert::from_bytes failed")?;

    let mut idents = vec![];

    for backend in PcscBackend::cards(None)? {
        let mut card: Card<Open> = backend.into();
        let mut transaction = card.transaction()?;

        if card_matches(&mut transaction, &ca_cert).is_ok() {
            idents.push(transaction.application_identifier()?.ident());
        }
    }

    Ok(idents)
}

/// Does 'ca_cert' match the data on the opened card?
///
/// FIXME: also check the state of SIG and DEC slots?
fn card_matches(transaction: &mut Card<Transaction>, ca_cert: &Cert) -> Result<String> {
    let fps = transaction.fingerprints()?;
    let auth = fps
        .authentication()
        .context("No AUT key on card".to_string())?;

    let auth_fp = auth.to_string();

    let cardholder_name = transaction.cardholder_name()?;

    // Check that cardholder name is set to "OpenPGP CA".
    if cardholder_name.as_deref() != Some("OpenPGP CA") {
        return Err(anyhow::anyhow!(
            "Expected cardholder name 'OpenPGP CA' on OpenPGP card, found '{}'.",
            cardholder_name.unwrap_or_default()
        ));
    }

    // Make sure that the CA public key contains a User ID!
    // (So we can set the 'Signer's UserID' packet for easy WKD lookup of the CA cert)
    if ca_cert.userids().next().is_none() {
        return Err(anyhow::anyhow!(
            "Expect CA certificate to contain at least one User ID, but found none."
        ));
    }

    let pubkey =
        pgp::cert_to_armored(ca_cert).context("Failed to transform CA cert to armored pubkey")?;

    // CA pubkey and card auth key slot must match
    if ca_cert.fingerprint().to_hex() != auth_fp {
        return Err(anyhow::anyhow!(format!(
            "Auth key slot on card {} doesn't match primary (cert) fingerprint {}.",
            auth_fp,
            ca_cert.fingerprint().to_hex()
        )));
    }

    Ok(pubkey)
}

// Check the card `card_ident`, confirm that the cardholder name is set to
// "OpenPGP CA", and that the AUT slot contains the certification key.
fn check_if_card_matches(card_ident: &str, ca_cert: &Cert) -> Result<String> {
    // Open Smart Card
    let backend = PcscBackend::open_by_ident(card_ident, None)?;
    let mut card: Card<Open> = backend.into();
    let mut transaction = card.transaction()?;

    card_matches(&mut transaction, ca_cert).context(format!("On card {card_ident}"))
}

/// A CA instance that has a database, which is (possibly) not initialized yet.
/// No backend for private key operations is available at this stage.
pub struct Uninit {
    storage: UninitDb,
}

/// An initialized OpenPGP CA instance, with a configured backend.
/// Oca exposes the main functionality of OpenPGP CA.
pub struct Oca {
    storage: Box<dyn CaStorageRW>,
    secret: Box<dyn CaSec>,
}

impl Uninit {
    /// Instantiate a new Uninit object (with db, but without private key backend).
    ///
    /// This CA may be fully uninitialized and not be linked to a CA key yet.
    ///
    /// The SQLite backend filename can be configured:
    /// - explicitly via the db_url parameter, or
    /// - the environment variable OPENPGP_CA_DB.
    pub fn new(db_url: Option<&str>) -> Result<Self> {
        let db_url = if let Some(url) = db_url {
            url.to_owned()
        } else if let Ok(database) = env::var("OPENPGP_CA_DB") {
            database
        } else {
            return Err(anyhow::anyhow!("ERROR: no database configuration found"));
        };

        let db = Rc::new(OcaDb::new(&db_url)?);
        db.diesel_migrations_run();

        let storage = UninitDb::new(db);

        Ok(Self { storage })
    }

    /// Check if domainname is legal according to Mozilla's Public Suffix List
    fn check_domainname(domainname: &str) -> Result<()> {
        // domainname syntax check
        use addr::parser::DomainName;
        use addr::psl::List;
        if List.parse_domain_name(domainname).is_err() {
            return Err(anyhow::anyhow!("Invalid domainname: '{}'", domainname));
        }

        Ok(())
    }

    /// Init CA with softkey backend.
    ///
    /// This generates a new OpenPGP Key for the Admin role and stores the
    /// private Key in the OpenPGP CA database.
    ///
    /// `domainname` is the domain that this CA Admin is in charge of,
    /// `name` is a descriptive name for the CA Admin
    pub fn init_softkey(self, domainname: &str, name: Option<&str>) -> Result<Oca> {
        Self::check_domainname(domainname)?;
        let (cert, _) = pgp::make_ca_cert(domainname, name)?;

        self.storage
            .transaction(|| self.storage.ca_init_softkey(domainname, &cert))?;

        self.init_from_db_state()
    }

    /// Init "split mode front" CA (which uses a second CA as its backend)
    pub fn init_split_front(self, domainname: &str, ca_cert: &[u8]) -> Result<Oca> {
        Self::check_domainname(domainname)?;
        let cert = Cert::from_bytes(ca_cert).context("Cert::from_bytes failed")?;

        self.storage
            .transaction(|| self.storage.ca_init_split(domainname, &cert))?;

        self.init_from_db_state()
    }

    /// Init CA with OpenPGP card backend. Generate key material on the card.
    ///
    /// This assumes that:
    /// - all key slots on the card are currently empty
    /// - the PINs are set to their default values (User PIN is '123456', Admin PIN is '12345678')
    ///
    /// The User PIN is changed to a new, random 8-digit value and persisted in the CA database.
    ///
    /// The user is encouraged to change the Admin PIN to a different setting.
    pub fn init_card_generate_on_card(
        self,
        ident: &str,
        domain: &str,
        name: Option<&str>,
        algo: Option<AlgoSimple>,
    ) -> Result<Oca> {
        // The CA database must be uninitialized!
        if self.storage.is_ca_initialized()? {
            return Err(anyhow::anyhow!("CA database is already initialized"));
        }

        let email = format!("openpgp-ca@{domain}");
        let uid = pgp::ca_user_id(&email, name);
        let uid = String::from_utf8_lossy(uid.value()).to_string();

        // Generate key material on card, get the public key,
        // initialize the CA with these artifacts.
        let (ca_cert, user_pin) = card::generate_on_card(ident, domain, uid, algo)?;

        self.ca_init_card(ident, &user_pin, domain, &ca_cert)
    }

    pub fn init_card_generate_on_host(
        self,
        ident: &str,
        domain: &str,
        name: Option<&str>,
    ) -> Result<(Oca, String)> {
        // The CA database must be uninitialized!
        if self.storage.is_ca_initialized()? {
            return Err(anyhow::anyhow!("CA database is already initialized"));
        }

        // Generate a new CA private key
        let (ca_key, _) = pgp::make_ca_cert(domain, name)?;

        // Import key material to card.
        let user_pin = card::import_to_card(ident, &ca_key)?;

        // Private key material will get stripped implicitly by ca_init_card()
        let ca = self.ca_init_card(ident, &user_pin, domain, &ca_key)?;

        // return private key (unencrypted)
        let key = pgp::cert_to_armored_private_key(&ca_key)?;

        Ok((ca, key))
    }

    /// Import the CA's public key and use it with a pre-initialized OpenPGP card.
    pub fn init_card_import_card(
        self,
        card_ident: &str,
        user_pin: &str,
        domain: &str,
        ca_cert: &[u8],
    ) -> Result<Oca> {
        let ca_cert = Cert::from_bytes(ca_cert).context("Cert::from_bytes failed")?;

        // Check if user-supplied PIN is accepted by the card
        card::verify_user_pin(card_ident, user_pin)?;

        // FIXME: could add checks if the cert and the keys on the card really correspond?
        // (e.g.: could perform crypto operations on the card and test against cert?
        // however, this might surprisingly require touch confirmation!)

        self.ca_init_card(card_ident, user_pin, domain, &ca_cert)
    }

    /// Import existing CA private key onto a blank OpenPGP card.
    pub fn init_card_import_key(
        self,
        card_ident: &str,
        domain: &str,
        ca_key: &[u8],
    ) -> Result<Oca> {
        let ca_key = Cert::from_bytes(ca_key).context("Cert::from_bytes failed")?;
        if !ca_key.is_tsk() {
            return Err(anyhow::anyhow!(
                "No private key material found in file. Can't import to OpenPGP card."
            ));
        }

        // FIXME: handle password protected key file?

        // Import key material to card.
        let user_pin = card::import_to_card(card_ident, &ca_key)?;

        // Private key material will get stripped implicitly by ca_init_card()
        self.ca_init_card(card_ident, &user_pin, domain, &ca_key)
    }

    /// Migrate an existing softkey CA onto a blank OpenPGP card.
    ///
    /// Caution: If you want to keep a backup of your CA private key material,
    /// you need to make it before calling this!
    ///
    /// 1. The private CA key material gets imported to the blank OpenPGP card.
    ///
    /// 2. The CA is then switched from the softkey backend to the card backend. The CA private
    /// key material in the database is replaced with the CA public key material.
    ///
    /// 3. "VACUUM" is called on the database after removing the CA private key from the database.
    /// According to SQLite documentation, this will remove any traces of the key material from the
    /// database (however, no guarantees can be made about the underlying storage!).
    pub fn migrate_card_import_key(self, card_ident: &str) -> Result<Oca> {
        self.storage.transaction(|| {
            let ca_key = self.storage.ca_get_cert_private()?;
            if !ca_key.is_tsk() {
                return Err(anyhow::anyhow!(
                    "No private key material in CA database. Can't migrate to OpenPGP card."
                ));
            }

            // Import key material to card.
            let user_pin = card::import_to_card(card_ident, &ca_key)?;

            // Switch cacert in db
            let ca_pub = pgp::cert_to_armored(&ca_key.strip_secret_key_material())?;
            CardBackend::ca_replace_in_place(&self.storage, card_ident, &user_pin, &ca_pub)?;

            Ok(())
        })?;

        // Run VACUUM on sqlite.
        // SQLite guarantees that this removes remaining private key fragments from the database file.
        self.storage.vacuum()?;

        self.init_from_db_state()
    }

    /// Init with OpenPGP card backend
    fn ca_init_card(
        self,
        card_ident: &str,
        pin: &str,
        domainname: &str,
        ca_cert: &Cert,
    ) -> Result<Oca> {
        Self::check_domainname(domainname)?;

        // Open a separate scope for database-access.
        //
        // Without this block, init_from_db_state() [below] gets stuck while trying to clone
        // the internal Rc<OcaDb> (FIXME: understand why this happens?!)
        {
            // The CA database must be uninitialized!
            if self.storage.is_ca_initialized()? {
                return Err(anyhow::anyhow!("CA database is already initialized"));
            }

            let pubkey = check_if_card_matches(card_ident, ca_cert)?;

            self.storage.transaction(|| {
                CardBackend::ca_init(
                    &self.storage,
                    domainname,
                    card_ident,
                    pin,
                    &pubkey,
                    &ca_cert.fingerprint().to_hex(),
                )
            })?;
        }

        self.init_from_db_state()
    }

    /// Initialize OpenpgpCa object - this assumes a backend has previously been configured.
    fn init_from_db_state(self) -> Result<Oca> {
        // check database state of this CA
        let cacert = self.storage.cacert()?;

        match Backend::from_config(cacert.backend.as_deref())? {
            Backend::Softkey => {
                let softkey = SoftkeyBackend::new(self.storage.ca_get_cert_private()?);

                let ca_cert_pub = self.storage.ca_get_cert_pub()?;
                let ca_sec = CaSecCB::new(Rc::new(softkey), ca_cert_pub);

                let storage = Box::new(DbCa::new(self.storage.db()));

                Ok(Oca {
                    storage,
                    secret: Box::new(ca_sec),
                })
            }
            Backend::Card(card) => {
                let card_ca = CardBackend::new(&card.ident, &card.user_pin)?;

                let ca_cert = self.storage.ca_get_cert_pub()?;
                let ca_sec = CaSecCB::new(Rc::new(card_ca), ca_cert);

                let storage = Box::new(DbCa::new(self.storage.db()));

                Ok(Oca {
                    storage,
                    secret: Box::new(ca_sec),
                })
            }
            Backend::SplitFront => {
                let oca_db = self.storage.db();

                let storage = Box::new(DbCa::new(oca_db.clone()));
                let secret = Box::new(SplitCa::new(oca_db)?);

                Ok(Oca { storage, secret })
            }
            Backend::SplitBack(inner) => {
                // FIXME: generalize to "Softkey or Card"
                assert!(*inner == Backend::Softkey);
                let softkey = SoftkeyBackend::new(self.storage.ca_get_cert_private()?);
                let ca_cert_pub = self.storage.ca_get_cert_pub()?;
                let ca_sec = CaSecCB::new(Rc::new(softkey), ca_cert_pub);

                // FIXME: use no storage, or overlay-read only DB for inputs (?)
                let storage = Box::new(DbCa::new(self.storage.db()));

                Ok(Oca {
                    storage,
                    secret: Box::new(ca_sec),
                })
            }
        }
    }
}

impl Oca {
    /// Open an initialized Oca instance.
    ///
    /// The SQLite backend filename can be configured:
    /// - explicitly via the db_url parameter, or
    /// - the environment variable OPENPGP_CA_DB.
    pub fn open(db_url: Option<&str>) -> Result<Self> {
        let cau = Uninit::new(db_url)?;
        cau.init_from_db_state()
    }

    /// Change which card backs an OpenPGP CA instance
    /// (e.g. to switch to a replacement for a broken card).
    pub fn set_card_backend(self, card_ident: &str, user_pin: &str) -> Result<()> {
        let cacert = self.storage.cacert()?;

        let b = Backend::from_config(cacert.backend.as_deref())?;
        match b {
            Backend::Card(_c) => {
                // For now, we only allow switches from card-backend to card-backend

                // Check if user-supplied PIN is accepted by the card
                card::verify_user_pin(card_ident, user_pin)?;

                // Check if the card exists and contains the correct CA key
                let ca_cert = self.ca_get_cert_pub()?;
                let _pubkey = check_if_card_matches(card_ident, &ca_cert)?;

                // Update backend configuration in database
                let ca_pub = pgp::cert_to_armored(&ca_cert)?;

                let db = self.storage.into_uninit();
                CardBackend::ca_replace_in_place(&db, card_ident, user_pin, &ca_pub)?;

                Ok(())
            }
            Backend::Softkey => Err(anyhow::anyhow!(
                "Setting card backend from softkey is not supported."
            )),
            Backend::SplitFront | Backend::SplitBack(_) => Err(anyhow::anyhow!(
                "Setting card backend from split mode is not supported."
            )),
        }
    }

    // -------- CA

    /// Get the CaSec implementation to run operations that need CA
    /// private key material.
    ///
    /// Print information about the created CA instance to stdout.
    pub(crate) fn secret(&self) -> &dyn CaSec {
        &*self.secret
    }

    /// Generate revocations for the CA key, write to output file.
    pub fn ca_generate_revocations(&self, output: PathBuf) -> Result<()> {
        self.secret.ca_generate_revocations(output)
    }

    pub fn ca_import_tsig(&self, cert: &[u8]) -> Result<()> {
        self.storage.ca_import_tsig(cert)
    }

    pub fn ca_get_cert_pub(&self) -> Result<Cert> {
        self.storage.ca_get_cert_pub()
    }

    /// Returns the public key of the CA as an armored String
    pub fn ca_get_pubkey_armored(&self) -> Result<String> {
        let cert = self.ca_get_cert_pub()?;
        let ca_pub =
            pgp::cert_to_armored(&cert).context("Failed to transform CA key to armored pubkey")?;

        Ok(ca_pub)
    }

    pub fn get_ca_email(&self) -> Result<String> {
        self.storage.ca_email()
    }

    /// Get the domainname for this CA
    pub fn get_ca_domain(&self) -> Result<String> {
        Ok(self.storage.ca()?.domainname)
    }

    /// Print information about the Ca to stdout.
    ///
    /// This shows the domainname, fingerprint and creation time of this OpenPGP CA instance.
    pub fn ca_show(&self) -> Result<()> {
        let ca_cert = self
            .storage
            .cacert()
            .context("failed to load CA from database")?;

        let domain = self.get_ca_domain()?;

        let cert = Cert::from_str(&ca_cert.priv_cert)?;

        let created = cert.primary_key().key().creation_time();
        let created: DateTime<Utc> = created.into();

        println!("    CA Domain: {}", domain);
        println!("  Fingerprint: {}", cert.fingerprint());
        println!("Creation time: {}", created.format("%F %T %Z"));

        let backend = Backend::from_config(ca_cert.backend.as_deref())?;
        println!("   CA Backend: {backend}");

        Ok(())
    }

    /// Print private key of the Ca to stdout.
    pub fn ca_print_private(&self) -> Result<()> {
        let ca_cert = self
            .storage
            .cacert()
            .context("failed to load CA from database")?;
        println!("{}", ca_cert.priv_cert);
        Ok(())
    }

    /// Find all User IDs that have been certified by `ca_cert_old` and re-certify them
    /// with the current CA key.
    ///
    /// This can be useful after CA key rotation: when the CA has a new key, `ca_re_certify` issues
    /// fresh certifications for all previously CA-certified user certs.
    pub fn ca_re_certify(&self, ca_cert_old: &[u8], validity_days: u64) -> Result<()> {
        let ca_cert_old = pgp::to_cert(ca_cert_old)?;

        cert::certs_re_certify(self, ca_cert_old, validity_days)
    }

    /// Export certification requests for the backing CA in a simple human-readable output format
    /// (inspired by https://github.com/wiktor-k/airsigner/, but with some adjustments!).
    ///
    /// The output file is a tar-archive:
    /// - The archive contains a top-level file "csr.txt", which lists User IDs that should be
    ///   certified.
    /// - Current versions of all certs are provided in the tar in armored format, as individual
    ///   files "certs/<fingerprint>".
    ///
    /// One design goal of this format is to make it easy to implement small (and thus more easily
    /// auditable) certification services, which may use arbitrary underlying mechanisms
    /// (and/or PGP implementations) for signing.
    pub fn ca_split_export(&self, file: PathBuf) -> Result<()> {
        // FIXME: don't perform this operation if the backend mode is wrong/unexpected?
        let cacert = self.storage.cacert()?;

        let queue = self.storage.queue_not_done()?;
        SplitCa::export_csr_as_tar(file, queue, &cacert.fingerprint)?;

        Ok(())
    }

    pub fn ca_split_process(&self, import: PathBuf, export: PathBuf) -> Result<()> {
        // FIXME: check if our backend allows processing of split-mode certification requests!

        let input = File::open(import)?;
        let mut a = tar::Archive::new(input);

        let mut csr = String::new();
        let mut certs = HashMap::new();

        for file in a.entries()? {
            let mut file = file?;

            let name = file.header().path()?;
            if name.to_str() == Some(split::CSR_FILE) {
                file.read_to_string(&mut csr)?;
            } else if name.starts_with("certs/") {
                let mut s = String::new();
                file.read_to_string(&mut s)?;
                let c = Cert::from_str(&s)?;

                certs.insert(c.fingerprint().to_string(), c);
            } else {
                unimplemented!()
            }
        }

        // prepare output file
        let mut output = File::create(export)?;

        // FIXME: process first line, check if version and CA fp are acceptable
        for line in csr.lines().skip(1) {
            // "queue id" "user id number" "fingerprint" "days (0 if unlimited)" "user id"
            let v: Vec<_> = line.splitn(5, ' ').collect();

            let db_id: usize = usize::from_str(v[0])?;
            let uid_nr: usize = usize::from_str(v[1])?;
            let fp = v[2];
            let days_valid = match u64::from_str(v[3])? {
                0 => None,
                d => Some(d),
            };
            let uid = v[4];

            // Cert/User ID that should be certified
            let c = certs.get(fp).expect("missing cert"); // FIXME
            let uid = c
                .userids()
                .find(|u| u.userid().to_string() == uid)
                .unwrap() // FIXME unwrap
                .userid();

            // Generate certification
            let sigs = self.secret.sign_user_ids(c, &[uid][..], days_valid)?;
            assert_eq!(sigs.len(), 1); // FIXME

            let mut v: Vec<u8> = vec![];
            sigs[0].serialize(&mut v)?;

            let encoded: String = general_purpose::STANDARD_NO_PAD.encode(v);

            // Write a line in output file for this Signature
            writeln!(output, "{db_id} {uid_nr} {fp} {encoded}")?;
        }

        Ok(())
    }

    pub fn ca_split_import(&self, file: PathBuf) -> Result<()> {
        let file = File::open(file)?;
        for line in std::io::BufReader::new(file).lines() {
            let line = line?;

            let split: Vec<_> = line.split(' ').collect();
            assert_eq!(split.len(), 4);

            let _db_id = usize::from_str(split[0])?;
            let _uid_nr = usize::from_str(split[1])?;

            let fp = split[2];

            // base64-encoded serialized Signature
            let sig = split[3];
            let bytes = general_purpose::STANDARD.decode(sig).unwrap();

            let sig = Signature::from_bytes(&bytes)?;

            if let Some(cert) = self.storage.cert_by_fp(fp)? {
                let c = Cert::from_str(&cert.pub_cert)?;
                let certified = c.insert_packets(sig)?;

                self.storage.cert_update(&certified.to_vec()?)?;

                // FIXME: mark queue entry as done
            } else {
                // FIXME: mark queue entry as failed?
                println!("failed to load fp {fp}");

                unimplemented!()
            }
        }

        Ok(())
    }

    // -------- users / certs

    /// Get a list of all User Certs
    pub fn user_certs_get_all(&self) -> Result<Vec<models::Cert>> {
        let users = self.storage.users_sorted_by_name()?;
        let mut user_certs = Vec::new();
        for user in users {
            user_certs.append(&mut self.get_certs_by_user(&user)?);
        }
        Ok(user_certs)
    }

    /// Which certs will be expired in 'days' days?
    ///
    /// If a cert is not "alive" now, it will not get returned as expiring
    /// (otherwise old/abandoned certs would clutter the results)
    pub fn certs_expired(&self, days: u64) -> Result<HashMap<models::Cert, Option<SystemTime>>> {
        cert::certs_expired(self, days)
    }

    /// Check if this Cert has been certified by the CA Key, returns all
    /// certified User IDs
    pub fn cert_check_ca_sig(&self, cert: &models::Cert) -> Result<CertificationStatus> {
        cert::cert_check_ca_sig(self, cert).context("Failed while checking CA sig")
    }

    /// Check if this Cert has tsigned the CA Key
    pub fn cert_check_tsig_on_ca(&self, cert: &models::Cert) -> Result<bool> {
        cert::cert_check_tsig_on_ca(self, cert).context("Failed while checking tsig on CA")
    }

    /// Check all Certs for certifications from the CA. If a certification
    /// expires in less than `threshold_days` and it is not marked as
    /// 'inactive', make a new certification that is good for
    /// `validity_days` and update the Cert.
    pub fn certs_refresh_ca_certifications(
        &self,
        threshold_days: u64,
        validity_days: u64,
    ) -> Result<()> {
        cert::certs_refresh_ca_certifications(self, threshold_days, validity_days)
    }

    /// Create a new OpenPGP CA User.
    /// ("Centralized key creation workflow")
    ///
    /// This generates a fresh OpenPGP key for the new User.
    /// The private key is printed to stdout and NOT stored in OpenPGP CA.
    /// The public key material (Cert) is stored in the OpenPGP CA database.
    ///
    /// The CA Cert is trust-signed by this new user key and the user
    /// Cert is certified by the CA.
    pub fn user_new(
        &self,
        name: Option<&str>,
        emails: &[&str],
        duration_days: Option<u64>,
        password: bool,
        output_format_minimal: bool,
    ) -> Result<()> {
        // storage: ca_import_tsig + user_add

        cert::user_new(
            self,
            name,
            emails,
            duration_days,
            password,
            output_format_minimal,
        )
    }

    /// Import an existing OpenPGP Cert (public key) as a new OpenPGP CA user.
    ///
    /// The `cert` parameter accepts the user's armored public key.
    ///
    /// User IDs that correspond to `emails` will be signed by the CA.
    ///
    /// A symbolic `name` and a list of `emails` for this User can
    /// optionally be supplied. If those are not set, emails are taken from
    /// the list of User IDs in the public key. If the key has exactly one
    /// User ID, the symbolic name is taken from that User ID.
    ///
    /// Optionally, revocation certificates can be supplied for storage in
    /// OpenPGP CA.
    pub fn cert_import_new(
        &self,
        cert: &[u8],
        revoc_certs: &[&[u8]],
        name: Option<&str>,
        emails: &[&str],
        duration_days: Option<u64>,
    ) -> Result<()> {
        cert::cert_import_new(self, cert, revoc_certs, name, emails, duration_days)
    }

    /// Update existing Cert in database (e.g. if the user has extended
    /// the expiry date)
    pub fn cert_import_update(&self, cert: &[u8]) -> Result<()> {
        cert::cert_import_update(self, cert)
    }

    /// Mark a cert as "delisted" in the OpenPGP CA database.
    /// As a result, the cert will not be exported to WKD anymore.
    ///
    /// Note: existing CA certifications will still get renewed for delisted
    /// certs, but as the cert is not published via WKD, third parties might not
    /// learn about refreshed certifications.
    ///
    /// CAUTION:
    /// This method is probably rarely appropriate. In most cases, it's better
    /// to "deactivate" a cert (in almost all cases, it is best to continually
    /// serve the latest version of a cert to third parties, so they can learn
    /// about e.g. revocations on the cert)
    pub fn cert_delist(&self, fp: &str) -> Result<()> {
        self.storage.cert_delist(fp)
    }

    /// Mark a certificate as "deactivated".
    /// It will continue to be listed and exported to WKD.
    /// However, the certification by our CA will expire and not get renewed.
    ///
    /// This approach is probably appropriate in most cases to phase out a
    /// certificate.
    pub fn cert_deactivate(&self, fp: &str) -> Result<()> {
        self.storage.cert_deactivate(fp)
    }

    /// Get Cert by fingerprint.
    ///
    /// The fingerprint parameter is normalized (e.g. if it contains
    /// spaces, they will be filtered out).
    pub fn cert_get_by_fingerprint(&self, fingerprint: &str) -> Result<Option<models::Cert>> {
        let fp = pgp::normalize_fp(fingerprint)?;

        self.storage.cert_by_fp(&fp)
    }

    /// Get a list of all Certs for one User
    pub fn get_certs_by_user(&self, user: &models::User) -> Result<Vec<models::Cert>> {
        self.storage.certs_by_user(user)
    }

    /// Get a list of all Users, ordered by name
    pub fn users_get_all(&self) -> Result<Vec<models::User>> {
        self.storage.users_sorted_by_name()
    }

    /// Get a list of the Certs that are associated with `email`
    pub fn certs_by_email(&self, email: &str) -> Result<Vec<models::Cert>> {
        self.storage.certs_by_email(email)
    }

    /// Get database User(s) for database Cert
    pub fn cert_get_users(&self, cert: &models::Cert) -> Result<Option<models::User>> {
        self.storage.user_by_cert(cert)
    }

    /// Get the user name that is associated with this Cert.
    ///
    /// The name is only for display purposes, it is set to "<no name>" if
    /// no name can be found, or to "<multiple users>" if the Cert is
    /// associated with more than one User.
    pub fn cert_get_name(&self, cert: &models::Cert) -> Result<String> {
        if let Some(user) = self.cert_get_users(cert)? {
            Ok(user.name.unwrap_or_else(|| "<no name>".to_string()))
        } else {
            Ok("<no name>".to_string())
        }
    }

    pub fn print_certifications_status(&self) -> Result<()> {
        let mut count_ok = 0;

        let db_users = self.users_get_all()?;
        for db_user in &db_users {
            for db_cert in self.get_certs_by_user(db_user)? {
                let sigs_by_ca = self.cert_check_ca_sig(&db_cert)?;
                let tsig_on_ca = self.cert_check_tsig_on_ca(&db_cert)?;

                let sig_by_ca = !sigs_by_ca.certified.is_empty();

                if sig_by_ca && tsig_on_ca {
                    count_ok += 1;
                } else {
                    println!(
                        "No mutual certification for {}{}:",
                        db_cert.fingerprint,
                        db_user
                            .name
                            .as_deref()
                            .map(|s| format!(" ({s})"))
                            .unwrap_or_else(|| "".to_string()),
                    );

                    if !sig_by_ca {
                        println!("  No CA certification on any User ID");
                    }

                    if !tsig_on_ca {
                        println!("  Has not tsigned CA key.");
                    };

                    println!();
                }
            }
        }

        println!(
            "Checked {} user keys, {} of them have mutual certifications.",
            db_users.len(),
            count_ok
        );

        Ok(())
    }

    pub fn print_expiry_status(&self, exp_days: u64) -> Result<()> {
        let expiries = self.certs_expired(exp_days)?;

        if expiries.is_empty() {
            println!("No certificates will expire in the next {exp_days} days.");
        } else {
            println!(
                "The following {} certificate{} will expire in the next {} days.",
                expiries.len(),
                if expiries.len() == 1 { "" } else { "s" },
                exp_days
            );
            println!();
        }

        for (db_cert, expiry) in expiries {
            let name = self.cert_get_name(&db_cert)?;
            println!("name {}, fingerprint {}", name, db_cert.fingerprint);

            if let Some(exp) = expiry {
                let datetime: DateTime<Utc> = exp.into();
                println!(" expires: {}", datetime.format("%d/%m/%Y"));
            } else {
                println!(" no expiration date is set for this user key");
            }

            println!();
        }

        Ok(())
    }

    pub fn print_users(&self) -> Result<()> {
        for db_user in self.users_get_all()? {
            for db_cert in self.get_certs_by_user(&db_user)? {
                let sig_by_ca = self.cert_check_ca_sig(&db_cert)?;
                let tsig_on_ca = self.cert_check_tsig_on_ca(&db_cert)?;

                println!("OpenPGP certificate {}", db_cert.fingerprint);
                if let Some(name) = &db_user.name {
                    println!(" User '{name}'");
                }

                if !sig_by_ca.certified.is_empty() {
                    println!(" Identities certified by this CA:");
                    for uid in sig_by_ca.certified {
                        println!(" - '{}'", uid);
                    }
                }

                if tsig_on_ca {
                    println!(" Has trust-signed this CA");
                }

                let c = pgp::to_cert(db_cert.pub_cert.as_bytes())?;

                match pgp::get_expiry(&c) {
                    Ok(Some(exp)) => {
                        let datetime: DateTime<Utc> = exp.into();
                        println!(" Expiration {}", datetime.format("%d/%m/%Y"));
                    }
                    Ok(None) => println!(" No expiration is set"),
                    Err(e) => println!(" Expiration unknown ({})", e),
                }

                let revs = self.revocations_get(&db_cert)?;
                if !revs.is_empty() {
                    println!(" {} revocations available", revs.len());
                }

                if pgp::is_possibly_revoked(&c) {
                    println!(" This certificate has (possibly) been REVOKED");
                }
                println!();
            }
        }

        Ok(())
    }

    // -------- revocations

    /// Get a list of all Revocations for a cert
    pub fn revocations_get(&self, cert: &models::Cert) -> Result<Vec<models::Revocation>> {
        self.storage.revocations_by_cert(cert)
    }

    /// Add a revocation certificate to the OpenPGP CA database.
    ///
    /// The matching cert is looked up by issuer Fingerprint, if
    /// possible - or by exhaustive search otherwise.
    ///
    /// Verifies that applying the revocation cert can be validated by the
    /// cert. Only if this is successful is the revocation stored.
    pub fn revocation_add(&self, revoc_cert: &[u8]) -> Result<()> {
        self.storage.revocation_add(revoc_cert)
    }

    /// Add a revocation certificate to the OpenPGP CA database (from a file).
    pub fn revocation_add_from_file(&self, filename: &Path) -> Result<()> {
        let rev = std::fs::read(filename)?;

        self.revocation_add(&rev)
    }

    /// Get a Revocation by hash
    pub fn revocation_get_by_hash(&self, hash: &str) -> Result<models::Revocation> {
        if let Some(rev) = self.storage.revocation_by_hash(hash)? {
            Ok(rev)
        } else {
            Err(anyhow::anyhow!("No revocation found for {}", hash))
        }
    }

    /// Apply a revocation.
    ///
    /// The revocation is merged into out copy of the OpenPGP Cert.
    pub fn revocation_apply(&self, revoc: models::Revocation) -> Result<()> {
        self.storage.revocation_apply(revoc)
    }

    /// Get reason and creation time for a Revocation
    pub fn revocation_details(
        revocation: &models::Revocation,
    ) -> Result<(String, Option<SystemTime>)> {
        let rev = pgp::to_signature(revocation.revocation.as_bytes())?;

        let creation = rev.signature_creation_time();

        if let Some((code, reason)) = rev.reason_for_revocation() {
            let reason = String::from_utf8(reason.to_vec())?;
            Ok((format!("{code} ({reason})"), creation))
        } else {
            Ok(("Revocation reason unknown".to_string(), creation))
        }
    }

    /// Get an armored representation of a revocation certificate
    pub fn revoc_to_armored(sig: &Signature) -> Result<String> {
        pgp::revoc_to_armored(sig, None)
    }

    pub fn print_revocations(&self, email: &str) -> Result<()> {
        let certs = self.certs_by_email(email)?;
        if certs.is_empty() {
            println!("No OpenPGP keys found");
        } else {
            for cert in certs {
                let name = self.cert_get_name(&cert)?;

                println!(
                    "Revocations for OpenPGP key {}, user \"{}\"",
                    cert.fingerprint, name
                );
                let revoc = self.revocations_get(&cert)?;
                for r in revoc {
                    let (reason, time) = Self::revocation_details(&r)?;
                    let time = if let Some(time) = time {
                        let datetime: DateTime<Utc> = time.into();
                        format!("{}", datetime.format("%d/%m/%Y"))
                    } else {
                        "".to_string()
                    };
                    println!(" - revocation id {}: {} ({})", r.hash, reason, time);
                    if r.published {
                        println!("   this revocation has been APPLIED");
                    }

                    println!();
                }
            }
        }
        Ok(())
    }

    // -------- emails

    /// Get all Emails for a Cert
    pub fn emails_get(&self, cert: &models::Cert) -> Result<Vec<models::CertEmail>> {
        self.storage.emails_by_cert(cert)
    }

    /// Get all Emails
    pub fn get_emails_all(&self) -> Result<Vec<models::CertEmail>> {
        self.storage.emails()
    }

    // --------- bridges

    /// Get a list of Bridges
    pub fn bridges_get(&self) -> Result<Vec<models::Bridge>> {
        self.storage.list_bridges()
    }

    /// Get a specific Bridge
    pub fn bridges_search(&self, email: &str) -> Result<models::Bridge> {
        if let Some(bridge) = self.storage.bridge_by_email(email)? {
            Ok(bridge)
        } else {
            Err(anyhow::anyhow!("Bridge not found"))
        }
    }

    /// Get the Cert row for a Bridge
    pub fn bridge_get_cert(&self, bridge: &models::Bridge) -> Result<models::Cert> {
        if let Some(cert) = self.storage.cert_by_id(bridge.cert_id)? {
            Ok(cert)
        } else {
            Err(anyhow::anyhow!("No cert found for bridge {}", bridge.id))
        }
    }

    pub fn add_bridge(
        &self,
        email: Option<&str>,
        key_file: &Path,
        scope: Option<&str>,
        unscoped: bool,
    ) -> Result<(String, String)> {
        let (bridge, fingerprint) = bridge::bridge_new(self, key_file, email, scope, unscoped)?;

        Ok((bridge.email, fingerprint.to_string()))
    }

    /// Create a revocation Certificate for a Bridge and apply it the our
    /// copy of the remote CA's public key.
    ///
    /// Both the revoked remote public key and the revocation cert are
    /// printed to stdout.
    pub fn bridge_revoke(&self, email: &str) -> Result<()> {
        bridge::bridge_revoke(self, email)
    }

    pub fn print_bridges(&self, email: Option<String>) -> Result<()> {
        let bridges = if let Some(email) = email {
            vec![self.bridges_search(&email)?]
        } else {
            self.bridges_get()?
        };

        for bridge in bridges {
            println!("Bridge to '{}'", bridge.email);
            if let Some(db_cert) = self.storage.cert_by_id(bridge.cert_id)? {
                println!("{}", db_cert.pub_cert);
            }
            println!();
        }

        Ok(())
    }

    pub fn list_bridges(&self) -> Result<()> {
        self.bridges_get()?.iter().for_each(|bridge| {
            println!("Bridge to '{}', (scope: '{}')", bridge.email, bridge.scope)
        });
        Ok(())
    }

    // -------- export

    /// Export all user keys (that have a userid in `domain`) and the CA key
    /// into a wkd directory structure
    ///
    /// <https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-08>
    pub fn export_wkd(&self, domain: &str, path: &Path) -> Result<()> {
        export::wkd_export(self, domain, path)
    }

    /// Export the contents of a CA in Keylist format.
    ///
    /// <https://code.firstlook.media/keylist-rfc-explainer>
    ///
    /// `path`: filesystem path into which the exported keylist and signature
    /// files will be written.
    ///
    /// `signature_uri`: the https address from which the signature file will
    /// be retrievable
    ///
    /// `force`: by default, this fn fails if the files exist; when force is
    /// true, overwrite.
    pub fn export_keylist(&self, path: PathBuf, signature_uri: String, force: bool) -> Result<()> {
        export::export_keylist(self, path, signature_uri, force)
    }

    /// Export Certs from this CA into files, with filenames based on email
    /// addresses of user ids.
    pub fn export_certs_as_files(&self, email_filter: Option<String>, path: &str) -> Result<()> {
        export::export_certs_as_files(self, email_filter, path)
    }

    pub fn print_certring(&self, email_filter: Option<String>) -> Result<()> {
        export::print_certring(self, email_filter)
    }

    // -------- Update certs from public sources

    /// Pull updates for all certs from WKD and merge them into our local
    /// storage.
    pub fn update_from_wkd(&self) -> Result<()> {
        for c in self.user_certs_get_all()? {
            match update::update_from_wkd(self, &c) {
                Ok(true) => {
                    println!("Got update for cert {}", c.fingerprint);
                }
                Ok(false) => {
                    println!("No changes for cert {}", c.fingerprint);
                }
                Err(e) => {
                    eprintln!("Failed to update cert {}: {}", c.fingerprint, e);
                }
            }
        }
        Ok(())
    }

    /// Update all certs from the hagrid keyserver (<https://keys.openpgp.org/>)
    /// and merge any updates into our local storage for this cert.
    pub fn update_from_keyserver(&self) -> Result<()> {
        for c in self.user_certs_get_all()? {
            match update::update_from_hagrid(self, &c) {
                Ok(true) => {
                    println!("Got update for cert {}", c.fingerprint);
                }
                Ok(false) => {
                    println!("No changes for cert {}", c.fingerprint);
                }
                Err(e) => {
                    eprintln!("Failed to update cert {}: {}", c.fingerprint, e);
                }
            }
        }
        Ok(())
    }
}
