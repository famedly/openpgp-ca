// SPDX-FileCopyrightText: 2019-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::rc::Rc;

use anyhow::Result;
use diesel::result::Error;
use sequoia_openpgp::packet::UserID;
use sequoia_openpgp::Cert;

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
    ) -> Result<models::User>;

    fn revocation_add(&self, revocation: &str, cert: &models::Cert) -> Result<models::Revocation>;
    fn revocation_update(&self, revocation: &models::Revocation) -> Result<()>;

    fn bridge_insert(&self, bridge: models::NewBridge) -> Result<models::Bridge>;
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
    fn ca_import_tsig(&self, cert: &[u8]) -> Result<()> {
        self.db.ca_import_tsig(cert)
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
    ) -> Result<models::User> {
        self.db
            .user_add(name, (pub_cert, fingerprint), emails, revocation_certs)
    }

    fn revocation_add(&self, revocation: &str, cert: &models::Cert) -> Result<models::Revocation> {
        self.db.revocation_add(revocation, cert)
    }

    fn revocation_update(&self, revocation: &models::Revocation) -> Result<()> {
        self.db.revocation_update(revocation)
    }

    fn bridge_insert(&self, bridge: models::NewBridge) -> Result<models::Bridge> {
        self.db.bridge_insert(bridge)
    }
}
