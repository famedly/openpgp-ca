// SPDX-FileCopyrightText: 2019-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

//! OpenPGP CA database access and model.

use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel::result::Error;

pub mod models;
mod schema;

use models::*;
use schema::*;

use crate::pgp;

/// Database access layer
pub(crate) struct OcaDb {
    url: String,
    conn: SqliteConnection,
}

impl OcaDb {
    pub(crate) fn new(db_url: &str) -> Result<Self> {
        let conn =
            SqliteConnection::establish(db_url).context(format!("Error connecting to {db_url}"))?;

        // Enable handling of foreign key constraints in sqlite
        diesel::sql_query("PRAGMA foreign_keys=1;")
            .execute(&conn)
            .context("Couldn't set 'PRAGMA foreign_keys=1;'")?;

        Ok(OcaDb {
            conn,
            url: db_url.to_string(),
        })
    }

    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    pub(crate) fn transaction<T, E, F>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E>,
        E: From<Error>,
    {
        self.conn.transaction(f)
    }

    /// Runs the "VACUUM" command on the database, which:
    /// "rebuilds the database file, repacking it into a minimal amount of disk space".
    ///
    /// "Running VACUUM will clean the database of all traces of deleted content, thus
    /// preventing an adversary from recovering deleted content"
    ///
    /// <https://www.sqlite.org/lang_vacuum.html>
    pub(crate) fn vacuum(&self) -> Result<()> {
        diesel::sql_query("VACUUM;")
            .execute(&self.conn)
            .context("Error while running 'VACUUM;'")?;

        Ok(())
    }

    // --- building block functions ---

    fn user_insert(&self, user: NewUser) -> Result<User> {
        let inserted_count = diesel::insert_into(users::table)
            .values(&user)
            .execute(&self.conn)?;

        if inserted_count != 1 {
            return Err(anyhow::anyhow!(
                "insert_user: insert should return count '1'"
            ));
        }

        // retrieve our new row, including the generated id
        let u: Vec<User> = users::table
            .order(users::id.desc())
            .limit(inserted_count as i64)
            .load(&self.conn)?
            .into_iter()
            .rev()
            .collect();

        if u.len() == 1 {
            Ok(u[0].clone())
        } else {
            Err(anyhow::anyhow!("insert_user: unexpected insert failure"))
        }
    }

    fn cert_insert(&self, cert: NewCert) -> Result<Cert> {
        let inserted_count = diesel::insert_into(certs::table)
            .values(&cert)
            .execute(&self.conn)?;

        if inserted_count != 1 {
            return Err(anyhow::anyhow!(
                "insert_cert: insert should return count '1'"
            ));
        }

        // retrieve our new row, including the generated id
        let c: Vec<Cert> = certs::table
            .order(certs::id.desc())
            .limit(inserted_count as i64)
            .load(&self.conn)?
            .into_iter()
            .rev()
            .collect();

        if c.len() == 1 {
            Ok(c[0].clone())
        } else {
            Err(anyhow::anyhow!("insert_cert: unexpected insert failure"))
        }
    }

    fn revocation_insert(&self, revoc: NewRevocation) -> Result<Revocation> {
        let inserted_count = diesel::insert_into(revocations::table)
            .values(&revoc)
            .execute(&self.conn)?;

        if inserted_count != 1 {
            return Err(anyhow::anyhow!(
                "insert_revocation: insert should return count '1'"
            ));
        }

        // retrieve our new row, including the generated id
        let r: Vec<Revocation> = revocations::table
            .order(revocations::id.desc())
            .limit(inserted_count as i64)
            .load(&self.conn)?
            .into_iter()
            .rev()
            .collect();

        if r.len() == 1 {
            Ok(r[0].clone())
        } else {
            Err(anyhow::anyhow!(
                "insert_revocation: unexpected insert failure"
            ))
        }
    }

    fn email_insert(&self, email: NewCertEmail) -> Result<CertEmail> {
        let inserted_count = diesel::insert_into(certs_emails::table)
            .values(&email)
            .execute(&self.conn)
            .context("Error saving new email")?;

        if inserted_count != 1 {
            return Err(anyhow::anyhow!(
                "insert_email: insert should return count '1'"
            ));
        }

        // retrieve our new row, including the generated id
        let e: Vec<CertEmail> = certs_emails::table
            .order(certs_emails::id.desc())
            .limit(inserted_count as i64)
            .load(&self.conn)?
            .into_iter()
            .collect();

        if e.len() != 1 {
            return Err(anyhow::anyhow!(
                "insert_email: unexpected insert failure [emails]"
            ));
        }

        Ok(e[0].clone())
    }

    pub(crate) fn queue_by_id(&self, id: i32) -> Result<Option<Queue>> {
        let mut db: Vec<Queue> = queue::table
            .filter(queue::id.eq(id))
            .load::<Queue>(&self.conn)
            .context("Error loading Queue by id")?;

        match db.len() {
            0 => Ok(None),
            1 => Ok(Some(db.pop().unwrap())),
            _ => Err(anyhow::anyhow!("queue_by_id: expected 0 or 1 entries")),
        }
    }

    pub(crate) fn queue_insert(&self, q: NewQueue) -> Result<()> {
        let inserted_count = diesel::insert_into(queue::table)
            .values(&q)
            .execute(&self.conn)
            .context("Error saving new queue entry")?;

        if inserted_count != 1 {
            return Err(anyhow::anyhow!(
                "queue_insert: insert should return count '1'"
            ));
        }

        Ok(())
    }

    // get all queue entries that aren't marked as "done"
    pub(crate) fn queue_not_done(&self) -> Result<Vec<Queue>> {
        queue::table
            .filter(queue::done.eq(false))
            .order(queue::id)
            .load::<Queue>(&self.conn)
            .context("Error loading queue entries")
    }

    pub(crate) fn queue_update(&self, queue: &Queue) -> Result<()> {
        diesel::update(queue)
            .set(queue)
            .execute(&self.conn)
            .context("Error updating Queue")?;

        Ok(())
    }

    // --- public ---

    pub(crate) fn is_ca_initialized(&self) -> Result<bool> {
        let cas = cas::table
            .load::<Ca>(&self.conn)
            .context("Error loading CAs")?;

        Ok(cas.len() == 1)
    }

    pub(crate) fn get_ca(&self) -> Result<(Ca, Cacert)> {
        let cas = cas::table
            .load::<Ca>(&self.conn)
            .context("Error loading CAs")?;

        match cas.len() {
            0 => Err(anyhow::anyhow!("CA is not initialized")),
            1 => {
                let ca = cas[0].clone();

                let ca_certs: Vec<_> = cacerts::table
                    .filter(cacerts::ca_id.eq(ca.id))
                    .filter(cacerts::active)
                    .load::<Cacert>(&self.conn)
                    .context("Error loading CA Certs")?;

                match ca_certs.len() {
                    0 => Err(anyhow::anyhow!("No CA cert found")),
                    1 => Ok((ca, ca_certs[0].to_owned())),
                    _ => {
                        // FIXME: which cert(s) should be returned?
                        // -> there can be more than one "active" cert,
                        // as well as even more "inactive" certs.
                        Err(anyhow::anyhow!(
                            "More than one active cacert in DB, illegal state."
                        ))
                    }
                }
            }
            _ => Err(anyhow::anyhow!(
                "More than one CA in database, this should never happen."
            )),
        }
    }

    pub(crate) fn ca_insert(
        &self,
        domainname: &str,
        ca_key: &str,
        fingerprint: &str,
        backend: Option<&str>,
    ) -> Result<()> {
        let ca = NewCa { domainname };

        diesel::insert_into(cas::table)
            .values(&ca)
            .execute(&self.conn)
            .context("Error saving new CA")?;

        // Retrieve our new row, including the generated id
        let cas = cas::table
            .load::<Ca>(&self.conn)
            .context("Error loading CAs")?;
        let ca = cas.first().unwrap();

        // Store Cert for the CA
        let ca_cert = NewCacert {
            fingerprint,
            ca_id: ca.id,
            priv_cert: ca_key.to_string(),
            backend,
            active: true,
        };
        self.cacert_insert(&ca_cert)?;

        Ok(())
    }

    pub(crate) fn cacerts_delete(&self) -> Result<()> {
        diesel::delete(cacerts::table)
            .execute(&self.conn)
            .context("Error while deleting cacerts entries")?;
        Ok(())
    }

    pub(crate) fn cacert_insert(&self, ca_cert: &NewCacert) -> Result<()> {
        diesel::insert_into(cacerts::table)
            .values(ca_cert)
            .execute(&self.conn)
            .context("Error saving new CA Cert")?;

        Ok(())
    }

    /// Replace the content of a Cacert entry.
    ///
    /// The assumption is that the new cacert is a modified version of the existing one
    /// (unchanged primary fingerprint).
    ///
    /// However, this is not enforced in this fn.
    pub(crate) fn cacert_update(&self, cacert: &Cacert) -> Result<()> {
        diesel::update(cacert)
            .set(cacert)
            .execute(&self.conn)
            .context("Error updating CaCert")?;

        Ok(())
    }

    /// Add trust-signature(s) from a user Cert to the CA's Cert.
    ///
    /// This receives the CA's public key (optionally armored), finds any trust-signatures on
    /// it and merges those into "our" local copy of the CA key.
    pub(crate) fn ca_import_tsig(&self, cert: &[u8]) -> Result<()> {
        let (_, mut ca_cert) = self
            .get_ca()
            .context("Failed to load CA cert from database")?;
        let ca = pgp::to_cert(ca_cert.priv_cert.as_bytes())?;

        let cert_import = pgp::to_cert(cert)?;

        let joined = pgp::merge_in_tsigs(ca, cert_import)?;

        // update in DB
        ca_cert.priv_cert =
            pgp::cert_to_armored_private_key(&joined).context("Failed to re-armor CA Cert")?;

        self.cacert_update(&ca_cert)
            .context("Update of CA Cert in DB failed")
    }

    pub(crate) fn users_sorted_by_name(&self) -> Result<Vec<User>> {
        users::table
            .order((users::name, users::id))
            .load::<User>(&self.conn)
            .context("Error loading users")
    }

    pub(crate) fn user_by_cert(&self, cert: &Cert) -> Result<Option<User>> {
        match cert.user_id {
            None => Ok(None),
            Some(search_id) => {
                let users = users::table
                    .filter(users::id.eq(search_id))
                    .load::<User>(&self.conn)?;

                match users.len() {
                    0 => Ok(None),
                    1 => Ok(Some(users[0].clone())),
                    _ => {
                        // This should not be possible
                        Err(anyhow::anyhow!(
                            "get_user_by_cert: Found more than one user for cert"
                        ))
                    }
                }
            }
        }
    }

    pub(crate) fn user_add(
        &self,
        name: Option<&str>,
        (pub_cert, fingerprint): (&str, &str),
        emails: &[&str],
        revocation_certs: &[String],
    ) -> Result<User> {
        // User
        let (ca, _) = self.get_ca().context("Couldn't find CA")?;

        let user = self.user_insert(NewUser { name, ca_id: ca.id })?;

        let cert = self.cert_add(pub_cert, fingerprint, Some(user.id))?;

        // Revocations
        for revocation in revocation_certs {
            let hash = &pgp::revocation_to_hash(revocation.as_bytes())?;
            self.revocation_insert(NewRevocation {
                hash,
                revocation,
                cert_id: cert.id,
                published: false,
            })?;
        }

        // Emails
        for &addr in emails {
            self.email_insert(NewCertEmail {
                addr: addr.to_owned(),
                cert_id: cert.id,
            })?;
        }
        Ok(user)
    }

    #[allow(dead_code)]
    pub(crate) fn user_update(&self, user: &User) -> Result<()> {
        diesel::update(user)
            .set(user)
            .execute(&self.conn)
            .context("Error updating User")?;

        Ok(())
    }

    pub(crate) fn cert_add(
        &self,
        pub_cert: &str,
        fingerprint: &str,
        user_id: Option<i32>,
    ) -> Result<Cert> {
        let cert = NewCert {
            pub_cert,
            fingerprint,
            delisted: false,
            inactive: false,
            user_id,
        };
        self.cert_insert(cert)
    }

    pub fn cert_update(&self, cert: &Cert) -> Result<()> {
        diesel::update(cert)
            .set(cert)
            .execute(&self.conn)
            .context("Error updating Cert")?;

        Ok(())
    }

    pub fn cert_by_id(&self, id: i32) -> Result<Option<Cert>> {
        let db: Vec<Cert> = certs::table
            .filter(certs::id.eq(id))
            .load::<Cert>(&self.conn)
            .context("Error loading Cert by id")?;

        Ok(db.get(0).cloned())
    }

    pub(crate) fn cert_by_fp(&self, fingerprint: &str) -> Result<Option<Cert>> {
        let c = certs::table
            .filter(certs::fingerprint.eq(fingerprint))
            .load::<Cert>(&self.conn)
            .context("Error loading Cert by fingerprint")?;

        match c.len() {
            0 => Ok(None),
            1 => Ok(Some(c[0].clone())),
            _ => Err(anyhow::anyhow!("get_cert: expected 0 or 1 cert")),
        }
    }

    pub(crate) fn certs_by_email(&self, email: &str) -> Result<Vec<Cert>> {
        let cert_ids = certs_emails::table
            .filter(certs_emails::addr.eq(email))
            .select(certs_emails::cert_id);

        certs::table
            .filter(certs::id.eq_any(cert_ids))
            .load::<Cert>(&self.conn)
            .context("could not load certs")
    }

    /// All Certs that belong to `user`, ordered by certs::id
    pub(crate) fn certs_by_user(&self, user: &User) -> Result<Vec<Cert>> {
        Ok(Cert::belonging_to(user)
            .order(certs::id)
            .load::<Cert>(&self.conn)?)
    }

    /// Get all Certs
    pub(crate) fn certs(&self) -> Result<Vec<Cert>> {
        certs::table
            .load::<Cert>(&self.conn)
            .context("Error loading certs")
    }

    pub(crate) fn revocations_by_cert(&self, cert: &Cert) -> Result<Vec<Revocation>> {
        Ok(Revocation::belonging_to(cert).load::<Revocation>(&self.conn)?)
    }

    pub(crate) fn revocation_add(&self, revocation: &str, cert: &Cert) -> Result<Revocation> {
        let hash = &pgp::revocation_to_hash(revocation.as_bytes())?;

        self.revocation_insert(NewRevocation {
            hash,
            revocation,
            cert_id: cert.id,
            published: false,
        })
    }

    /// Check if this exact revocation (bitwise) already exists in the DB
    pub(crate) fn revocation_exists(&self, revocation: &[u8]) -> Result<bool> {
        let hash = &pgp::revocation_to_hash(revocation)?;
        Ok(self.revocation_by_hash(hash)?.is_some())
    }

    pub(crate) fn revocation_by_hash(&self, hash: &str) -> Result<Option<Revocation>> {
        let db: Vec<Revocation> = revocations::table
            .filter(revocations::hash.eq(hash))
            .load::<Revocation>(&self.conn)
            .context("Error loading Revocation by hash")?;

        assert!(
            db.len() <= 1,
            "unexpected duplicate hash in revocations table"
        );

        Ok(db.get(0).cloned())
    }

    pub(crate) fn revocation_update(&self, revocation: &Revocation) -> Result<()> {
        diesel::update(revocation)
            .set(revocation)
            .execute(&self.conn)
            .context("Error updating Revocation")?;

        Ok(())
    }

    pub(crate) fn emails_by_cert(&self, cert: &Cert) -> Result<Vec<CertEmail>> {
        certs_emails::table
            .filter(certs_emails::cert_id.eq(cert.id))
            .load(&self.conn)
            .context("could not load emails")
    }

    pub(crate) fn emails(&self) -> Result<Vec<CertEmail>> {
        certs_emails::table
            .load(&self.conn)
            .context("could not load emails")
    }

    pub(crate) fn bridge_insert(&self, bridge: NewBridge) -> Result<Bridge> {
        let inserted_count = diesel::insert_into(bridges::table)
            .values(&bridge)
            .execute(&self.conn)
            .context("Error saving new bridge")?;

        if inserted_count != 1 {
            return Err(anyhow::anyhow!(
                "insert_user: insert should return count '1'"
            ));
        }

        let b: Vec<Bridge> = bridges::table
            .order(bridges::id.desc())
            .limit(inserted_count as i64)
            .load(&self.conn)?
            .into_iter()
            .rev()
            .collect();

        if b.len() == 1 {
            Ok(b[0].clone())
        } else {
            Err(anyhow::anyhow!("insert_user: unexpected insert failure"))
        }
    }

    pub(crate) fn bridge_by_email(&self, email: &str) -> Result<Option<Bridge>> {
        let res = bridges::table
            .filter(bridges::email.eq(email))
            .load::<Bridge>(&self.conn)
            .context("Error loading bridge")?;

        match res.len() {
            0 => Ok(None),
            1 => Ok(Some(res[0].clone())),
            _ => Err(anyhow::anyhow!(format!(
                "search_bridge for {} found {} results, expected <=1. \
                 (Database constraints should make this impossible)",
                email,
                res.len()
            ))),
        }
    }

    pub(crate) fn list_bridges(&self) -> Result<Vec<Bridge>> {
        bridges::table
            .load::<Bridge>(&self.conn)
            .context("Error loading bridges")
    }

    pub(crate) fn diesel_migrations_run(&self) {
        embed_migrations!();

        embedded_migrations::run(&self.conn).unwrap_or_else(|e| {
            panic!("failed to configure database, error {}", e);
        });
    }
}
