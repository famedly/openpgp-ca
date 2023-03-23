// SPDX-FileCopyrightText: 2019-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::rc::Rc;

use anyhow::{Context, Result};
use diesel::result::Error;
use sequoia_openpgp::packet::UserID;
use sequoia_openpgp::{Cert, Packet};

use crate::backend::Backend;
use crate::db::models::NewQueue;
use crate::db::{models, OcaDb};
use crate::pgp;

pub(crate) fn ca_get_cert_pub(db: &Rc<OcaDb>) -> Result<Cert> {
    Ok(ca_get_cert_private(db)?.strip_secret_key_material())
}

pub(crate) fn ca_get_cert_private(db: &Rc<OcaDb>) -> Result<Cert> {
    let (_, cacert) = db.get_ca()?;

    let cert = pgp::to_cert(cacert.priv_cert.as_bytes())?;
    Ok(cert)
}

/// DB access for an uninitialized CA instance
pub(crate) struct UninitDb {
    db: Rc<OcaDb>,
}

impl UninitDb {
    pub(crate) fn new(db: Rc<OcaDb>) -> Self {
        Self { db }
    }

    pub(crate) fn db(self) -> Rc<OcaDb> {
        self.db
    }

    pub(crate) fn transaction<T, E, F>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E>,
        E: From<Error>,
    {
        self.db.transaction(f)
    }

    pub(crate) fn vacuum(&self) -> Result<()> {
        self.db.vacuum()
    }

    pub(crate) fn is_ca_initialized(&self) -> Result<bool> {
        self.db.is_ca_initialized()
    }

    pub(crate) fn cacert(&self) -> Result<models::Cacert> {
        let (_, cacert) = self.db.get_ca()?;
        Ok(cacert)
    }

    pub(crate) fn ca_insert(
        &self,
        ca: models::NewCa,
        ca_key: &str,
        fingerprint: &str,
        backend: Option<&str>,
    ) -> Result<()> {
        self.db.ca_insert(ca, ca_key, fingerprint, backend)
    }

    pub(crate) fn cacert_update(&self, cacert: &models::Cacert) -> Result<()> {
        self.db.cacert_update(cacert)
    }

    /// Get the Cert of the CA (without private key material).
    pub(crate) fn ca_get_cert_pub(&self) -> Result<Cert> {
        ca_get_cert_pub(&self.db)
    }

    /// Get the Cert of the CA (with private key material, if available).
    ///
    /// Depending on the backend, the private key material is available in
    /// the database - or not.
    pub(crate) fn ca_get_cert_private(&self) -> Result<Cert> {
        ca_get_cert_private(&self.db)
    }

    // -----

    /// Initialize OpenPGP CA Admin database entry.
    /// Takes a `cert` with private key material and initializes a softkey-based CA.
    ///
    /// Only one CA Admin can be configured per database.
    pub(crate) fn ca_init_softkey(&self, domainname: &str, cert: &Cert) -> Result<()> {
        if self.db.is_ca_initialized()? {
            return Err(anyhow::anyhow!("CA has already been initialized",));
        }

        let ca_key = pgp::cert_to_armored_private_key(cert)?;

        self.db.ca_insert(
            models::NewCa { domainname },
            &ca_key,
            &cert.fingerprint().to_hex(),
            None,
        )
    }

    /// Initialize OpenPGP CA instance for split mode.
    /// Takes a `cert` with public key material and initializes a split-mode CA.
    pub(crate) fn ca_init_split(&self, domainname: &str, cert: &Cert) -> Result<()> {
        if self.db.is_ca_initialized()? {
            return Err(anyhow::anyhow!("CA has already been initialized",));
        }

        let ca = pgp::cert_to_armored(cert)?;

        self.db.ca_insert(
            models::NewCa { domainname },
            &ca,
            &cert.fingerprint().to_hex(),
            Backend::SplitFront.to_config().as_deref(),
        )
    }
}

/// DB storage for the secret-key relevant functionality of a split-mode CA instance
pub(crate) struct QueueDb {
    db: Rc<OcaDb>,
}

impl QueueDb {
    pub(crate) fn new(db: Rc<OcaDb>) -> Self {
        Self { db }
    }

    pub(crate) fn queue_insert(&self, q: NewQueue) -> Result<()> {
        self.db.queue_insert(q)
    }
}

pub(crate) trait CaStorage {
    fn ca(&self) -> Result<models::Ca>;
    fn cacert(&self) -> Result<models::Cacert>;

    fn ca_get_cert_pub(&self) -> Result<Cert>;
    fn ca_userid(&self) -> Result<UserID>;
    fn ca_email(&self) -> Result<String>;

    fn certs(&self) -> Result<Vec<models::Cert>>;
    fn cert_by_id(&self, id: i32) -> Result<Option<models::Cert>>;
    fn cert_by_fp(&self, fingerprint: &str) -> Result<Option<models::Cert>>;
    fn certs_by_email(&self, email: &str) -> Result<Vec<models::Cert>>;
    fn certs_by_user(&self, user: &models::User) -> Result<Vec<models::Cert>>;

    fn emails(&self) -> Result<Vec<models::CertEmail>>;
    fn emails_by_cert(&self, cert: &models::Cert) -> Result<Vec<models::CertEmail>>;
    fn user_by_cert(&self, cert: &models::Cert) -> Result<Option<models::User>>;
    fn users_sorted_by_name(&self) -> Result<Vec<models::User>>;

    fn revocation_exists(&self, revocation: &[u8]) -> Result<bool>;
    fn revocations_by_cert(&self, cert: &models::Cert) -> Result<Vec<models::Revocation>>;
    fn revocation_by_hash(&self, hash: &str) -> Result<Option<models::Revocation>>;

    fn list_bridges(&self) -> Result<Vec<models::Bridge>>;
    fn bridge_by_email(&self, email: &str) -> Result<Option<models::Bridge>>;

    fn queue_not_done(&self) -> Result<Vec<models::Queue>>;
}

pub(crate) trait CaStorageWrite {
    fn into_uninit(self: Box<Self>) -> UninitDb;

    fn cacert_update(self, cacert: &models::Cacert) -> Result<()>;

    fn ca_import_tsig(&self, cert: &[u8]) -> Result<()>;

    fn cert_add(
        &self,
        pub_cert: &str,
        fingerprint: &str,
        user_id: Option<i32>,
    ) -> Result<models::Cert>;
    fn cert_update(&self, cert: &models::Cert) -> Result<()>;

    fn user_add(
        &self,
        name: Option<&str>,
        cert_fp: (&str, &str),
        emails: &[&str],
        revocation_certs: &[String],
        ca_cert_tsigned: Option<&[u8]>,
    ) -> Result<models::User>;

    fn revocation_add(&self, revocation: &[u8]) -> Result<()>;
    fn revocation_apply(&self, db_revoc: models::Revocation) -> Result<()>;

    fn bridge_add(
        &self,
        remote_armored: &str,
        remote_fp: &str,
        remote_email: &str,
        scope: &str,
    ) -> Result<models::Bridge>;
}

pub(crate) trait CaStorageRW: CaStorage + CaStorageWrite {}

/// DB storage for a regular CA instance
pub(crate) struct DbCa {
    db: Rc<OcaDb>,
}

impl CaStorageRW for DbCa {}

impl DbCa {
    pub(crate) fn new(db: Rc<OcaDb>) -> Self {
        Self { db }
    }

    pub(crate) fn transaction<T, E, F>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E>,
        E: From<Error>,
    {
        self.db.transaction(f)
    }
}

impl CaStorage for DbCa {
    fn ca(&self) -> Result<models::Ca> {
        let (ca, _) = self.db.get_ca()?;
        Ok(ca)
    }

    fn cacert(&self) -> Result<models::Cacert> {
        let (_, cacert) = self.db.get_ca()?;
        Ok(cacert)
    }

    /// Get the Cert of the CA (without private key material).
    fn ca_get_cert_pub(&self) -> Result<Cert> {
        ca_get_cert_pub(&self.db)
    }

    /// Get the User ID of this CA
    fn ca_userid(&self) -> Result<UserID> {
        let cert = self.ca_get_cert_pub()?;
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

    fn certs(&self) -> Result<Vec<models::Cert>> {
        self.db.certs()
    }

    fn cert_by_id(&self, id: i32) -> Result<Option<models::Cert>> {
        self.db.cert_by_id(id)
    }

    fn cert_by_fp(&self, fingerprint: &str) -> Result<Option<models::Cert>> {
        self.db.cert_by_fp(fingerprint)
    }

    fn certs_by_email(&self, email: &str) -> Result<Vec<models::Cert>> {
        self.db.certs_by_email(email)
    }

    fn certs_by_user(&self, user: &models::User) -> Result<Vec<models::Cert>> {
        self.db.certs_by_user(user)
    }

    fn emails(&self) -> Result<Vec<models::CertEmail>> {
        self.db.emails()
    }

    fn emails_by_cert(&self, cert: &models::Cert) -> Result<Vec<models::CertEmail>> {
        self.db.emails_by_cert(cert)
    }

    fn user_by_cert(&self, cert: &models::Cert) -> Result<Option<models::User>> {
        self.db.user_by_cert(cert)
    }

    fn users_sorted_by_name(&self) -> Result<Vec<models::User>> {
        self.db.users_sorted_by_name()
    }

    fn revocation_exists(&self, revocation: &[u8]) -> Result<bool> {
        self.db.revocation_exists(revocation)
    }

    fn revocations_by_cert(&self, cert: &models::Cert) -> Result<Vec<models::Revocation>> {
        self.db.revocations_by_cert(cert)
    }

    fn revocation_by_hash(&self, hash: &str) -> Result<Option<models::Revocation>> {
        self.db.revocation_by_hash(hash)
    }

    fn list_bridges(&self) -> Result<Vec<models::Bridge>> {
        self.db.list_bridges()
    }

    // ------

    fn bridge_by_email(&self, email: &str) -> Result<Option<models::Bridge>> {
        self.db.bridge_by_email(email)
    }

    fn queue_not_done(&self) -> Result<Vec<models::Queue>> {
        self.db.queue_not_done()
    }
}

impl CaStorageWrite for DbCa {
    fn into_uninit(self: Box<Self>) -> UninitDb {
        UninitDb::new(self.db)
    }

    fn cacert_update(self, cacert: &models::Cacert) -> Result<()> {
        self.db.cacert_update(cacert)
    }

    fn ca_import_tsig(&self, ca_cert_tsigned: &[u8]) -> Result<()> {
        self.transaction(|| self.db.ca_import_tsig(ca_cert_tsigned))
    }

    fn cert_add(
        &self,
        pub_cert: &str,
        fingerprint: &str,
        user_id: Option<i32>,
    ) -> Result<models::Cert> {
        self.db.cert_add(pub_cert, fingerprint, user_id)
    }

    fn cert_update(&self, cert: &models::Cert) -> Result<()> {
        self.db.cert_update(cert)
    }

    fn user_add(
        &self,
        name: Option<&str>,
        (pub_cert, fingerprint): (&str, &str),
        emails: &[&str],
        revocation_certs: &[String],
        ca_cert_tsigned: Option<&[u8]>,
    ) -> Result<models::User> {
        self.transaction(|| {
            if self.db.cert_by_fp(fingerprint)?.is_some() {
                // Make sure the fingerprint doesn't exist (as part of the transaction)
                return Err(anyhow::anyhow!(
                    "A cert with this fingerprint already exists"
                ));
            }

            if let Some(ca_cert_tsigned) = ca_cert_tsigned {
                self.ca_import_tsig(ca_cert_tsigned)?;
            }

            self.db
                .user_add(name, (pub_cert, fingerprint), emails, revocation_certs)
        })
    }

    /// Store a new revocation in the database.
    ///
    /// This implicitly searches for a cert that the revocation can be applied to.
    /// If no suitable cert is found, an error is returned.
    fn revocation_add(&self, revocation: &[u8]) -> Result<()> {
        self.transaction(|| {
            // Check if this revocation already exists in db
            if self.revocation_exists(revocation)? {
                return Ok(()); // this revocation is already stored -> do nothing
            }

            let mut revocation = pgp::to_signature(revocation)
                .context("revocation_add: Couldn't process revocation")?;

            // Find the matching cert for this revocation certificate
            let mut cert = None;
            // 1) Search by fingerprint, if possible
            if let Some(issuer_fp) = pgp::get_revoc_issuer_fp(&revocation)? {
                cert = self.cert_by_fp(&issuer_fp.to_hex())?;
            }
            // 2) If match by fingerprint failed: test revocation for each cert
            if cert.is_none() {
                cert = crate::revocation::search_revocable_cert_by_keyid(
                    self.certs()?,
                    &mut revocation,
                )?;
            }

            if let Some(cert) = cert {
                let c = pgp::to_cert(cert.pub_cert.as_bytes())?;

                // verify that revocation certificate validates with cert
                if crate::revocation::validate_revocation(&c, &mut revocation)? {
                    let revocations = self.revocations_by_cert(&cert)?;
                    if !crate::revocation::check_for_equivalent_revocation(
                        revocations,
                        &revocation,
                    )? {
                        // update sig in DB
                        let armored = pgp::revoc_to_armored(&revocation, None)
                            .context("couldn't armor revocation cert")?;

                        let _ = self.db.revocation_add(&armored, &cert)?;
                    }

                    Ok(())
                } else {
                    Err(anyhow::anyhow!(format!(
                        "Revocation couldn't be matched to a cert:\n{revocation:?}"
                    )))
                }
            } else {
                Err(anyhow::anyhow!("Couldn't find cert for this fingerprint"))
            }
        })
    }

    /// Merge a revocation into the cert that it applies to, thus revoking that
    /// cert in the OpenPGP CA database.
    fn revocation_apply(&self, mut db_revoc: models::Revocation) -> Result<()> {
        self.transaction(|| {
            if let Some(mut db_cert) = self.db.cert_by_id(db_revoc.cert_id)? {
                let sig = pgp::to_signature(db_revoc.revocation.as_bytes())?;
                let c = pgp::to_cert(db_cert.pub_cert.as_bytes())?;

                let revocation: Packet = sig.into();
                let revoked = c.insert_packets(vec![revocation])?;

                db_cert.pub_cert = pgp::cert_to_armored(&revoked)?;

                db_revoc.published = true;

                self.db
                    .cert_update(&db_cert)
                    .context("Couldn't update Cert")?;

                self.db
                    .revocation_update(&db_revoc)
                    .context("Couldn't update Revocation")?;

                Ok(())
            } else {
                Err(anyhow::anyhow!("Couldn't find cert for apply_revocation"))
            }
        })
    }

    fn bridge_add(
        &self,
        remote_armored: &str,
        remote_fp: &str,
        remote_email: &str,
        scope: &str,
    ) -> Result<models::Bridge> {
        self.transaction(|| {
            // Cert of remote CA
            let db_cert = self.cert_add(remote_armored, remote_fp, None)?;

            // Add entry for bridge in our database
            let new_bridge = models::NewBridge {
                email: remote_email,
                scope,
                cert_id: db_cert.id,
                cas_id: self.ca()?.id,
            };
            self.db.bridge_insert(new_bridge)
        })
    }
}
