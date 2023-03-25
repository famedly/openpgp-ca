// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::ops::Add;
use std::path::PathBuf;
use std::rc::Rc;
use std::str::FromStr;

use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use sequoia_openpgp::packet::{Signature, UserID};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::{Marshal, SerializeInto};
use sequoia_openpgp::Cert;
use serde::{Deserialize, Serialize};

use crate::db::models::{Bridge, Cacert, NewQueue, Queue, Revocation, User};
use crate::db::{models, OcaDb};
use crate::pgp;
use crate::secret::CaSec;
use crate::storage::{ca_get_cert_pub, CaStorage, CaStorageRW, CaStorageWrite, QueueDb, UninitDb};

pub(crate) const CSR_FILE: &str = "csr.txt";

#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum QueueEntry {
    CertificationReq(CertificationReq),
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CertificationReq {
    cert: String,
    user_ids: Vec<String>,
    days: Option<u64>,
}

impl CertificationReq {
    pub(crate) fn cert(&self) -> Result<Cert> {
        Cert::from_str(&self.cert)
    }

    pub(crate) fn days(&self) -> Option<u64> {
        self.days
    }

    pub(crate) fn user_ids(&self) -> &[String] {
        &self.user_ids
    }
}

/// Backend for the secret-key-material relevant parts of a split CA instance
pub(crate) struct SplitCa {
    #[allow(dead_code)]
    db: QueueDb,
}

impl SplitCa {
    pub(crate) fn new(db: Rc<OcaDb>) -> Result<Self> {
        Ok(Self {
            db: QueueDb::new(db),
        })
    }

    pub(crate) fn export_csr_as_tar(output: PathBuf, queue: Vec<Queue>, ca_fp: &str) -> Result<()> {
        // ca_fp is stored in the request list as a safeguard against users accidentally signing
        // with the wrong CA key.
        let mut csr_file: String = format!("certification request list [v1] for CA {}\n", ca_fp);

        let mut certs: HashMap<String, Cert> = HashMap::new();

        for entry in queue {
            let task = entry.task;
            let qe: QueueEntry = serde_json::from_str(&task)?;

            match qe {
                QueueEntry::CertificationReq(cr) => {
                    let cert = cr.cert()?;

                    let user_ids = cr.user_ids();
                    let days = cr.days();

                    let fp = cert.fingerprint().to_string();

                    // write a line for each user id certification request:
                    // "queue id" "user id number" "fingerprint" "days (0 if unlimited)" "user id"
                    for (i, uid) in user_ids.iter().enumerate() {
                        let line =
                            format!("{} {} {} {} {}\n", entry.id, i, fp, days.unwrap_or(0), uid,);
                        csr_file = csr_file.add(&line);
                    }

                    // merge Cert into HashMap of certs
                    let c = certs.get(&fp);
                    match c {
                        None => certs.insert(fp, cert),
                        Some(c) => certs.insert(fp, c.clone().merge_public(cert)?),
                    };
                }
            }
        }

        // Write all files as tar
        let file = File::create(output).unwrap();
        let mut a = tar::Builder::new(file);

        let csr_file = csr_file.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_size(csr_file.len() as u64);
        header.set_cksum();
        a.append_data(&mut header, CSR_FILE, csr_file)?;

        for (fp, c) in certs {
            let cert = pgp::cert_to_armored(&c)?;
            let cert = cert.as_bytes();

            let mut header = tar::Header::new_gnu();
            header.set_size(cert.len() as u64);
            header.set_cksum();

            a.append_data(&mut header, format!("certs/{fp}"), cert)?;
        }

        Ok(())
    }
}

impl CaSec for SplitCa {
    fn cert(&self) -> Result<Cert> {
        self.db.cert()
    }

    /// Returns an empty vec -> the certifications are created asynchronously.
    fn sign_user_ids(
        &self,
        cert: &Cert,
        uids_certify: &[&UserID],
        duration_days: Option<u64>,
    ) -> Result<Vec<Signature>> {
        // If no User IDs are requested to be signed, we can ignore the request
        if uids_certify.is_empty() {
            return Ok(vec![]);
        }

        let c = pgp::cert_to_armored(cert)?;

        let cr = CertificationReq {
            user_ids: uids_certify.iter().map(|u| u.to_string()).collect(),
            cert: c,
            days: duration_days,
        };

        // Wrap the CertificationReq in a QueueEntry and store as a JSON string.
        let qe = QueueEntry::CertificationReq(cr);
        let serialized = serde_json::to_string(&qe)?;

        let q = NewQueue {
            task: &serialized,
            done: false,
        };

        // Store the certification task in the queue
        self.db.queue_insert(q)?;

        // The Signatures cannot be generated here, so we return an empty vec
        Ok(vec![])
    }

    fn ca_generate_revocations(&self, _output: PathBuf) -> Result<()> {
        Err(anyhow::anyhow!(
            "Operation is not supported on a split-mode CA front instance. Please perform it on your back CA instance."
        ))
    }

    // This operation is currently only used by "keylist export".
    // The user should run this command on the back CA instance
    // that has access to the CA key material.
    fn sign_detached(&self, _data: &[u8]) -> Result<String> {
        Err(anyhow::anyhow!(
            "Operation is not currently supported on a split-mode CA instance. Please perform it on your back CA instance."
        ))
    }

    fn bridge_to_remote_ca(&self, _remote_ca: Cert, _scope_regexes: Vec<String>) -> Result<Cert> {
        todo!()
    }

    fn bridge_revoke(&self, _remote_ca: &Cert) -> Result<(Signature, Cert)> {
        Err(anyhow::anyhow!(
            "Operation is not currently supported on a split-mode CA instance. Please perform it on your back CA instance."
        ))
    }
}

pub(crate) fn process(ca_sec: &dyn CaSec, import: PathBuf, export: PathBuf) -> Result<()> {
    let input = File::open(import)?;
    let mut a = tar::Archive::new(input);

    let mut csr = String::new();
    let mut certs = HashMap::new();

    for file in a.entries()? {
        let mut file = file?;

        let name = file.header().path()?;
        if name.to_str() == Some(CSR_FILE) {
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
        let sigs = ca_sec.sign_user_ids(c, &[uid][..], days_valid)?;
        assert_eq!(sigs.len(), 1); // FIXME

        let mut v: Vec<u8> = vec![];
        sigs[0].serialize(&mut v)?;

        let encoded: String = general_purpose::STANDARD_NO_PAD.encode(v);

        // Write a line in output file for this Signature
        writeln!(output, "{db_id} {uid_nr} {fp} {encoded}")?;
    }

    Ok(())
}

pub(crate) fn ca_split_import(storage: &dyn CaStorageRW, file: PathBuf) -> Result<()> {
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

        if let Some(cert) = storage.cert_by_fp(fp)? {
            let c = Cert::from_str(&cert.pub_cert)?;
            let certified = c.insert_packets(sig)?;

            storage.cert_update(&certified.to_vec()?)?;

            // FIXME: mark queue entry as done
        } else {
            // FIXME: mark queue entry as failed?
            return Err(anyhow::anyhow!("failed to load fp {fp}"));
        }
    }

    Ok(())
}

pub(crate) struct SplitBackDb {
    // read-only from separate oca file
    readonly: Rc<OcaDb>,
}

impl SplitBackDb {
    pub(crate) fn new(readonly: Rc<OcaDb>) -> Self {
        Self { readonly }
    }
}

/// This implementation mimics the DbCa implementation,
/// using self.readonly as the datasource, if set.
/// If self.readonly is None, the impl returns Errors.
impl CaStorage for SplitBackDb {
    fn ca(&self) -> Result<models::Ca> {
        let (ca, _) = self.readonly.get_ca()?;
        Ok(ca)
    }

    fn cacert(&self) -> Result<models::Cacert> {
        let (_, cacert) = self.readonly.get_ca()?;
        Ok(cacert)
    }

    /// Get the Cert of the CA (without private key material).
    fn ca_get_cert_pub(&self) -> Result<Cert> {
        ca_get_cert_pub(&self.readonly)
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
        self.readonly.certs()
    }

    fn cert_by_id(&self, id: i32) -> Result<Option<models::Cert>> {
        self.readonly.cert_by_id(id)
    }

    fn cert_by_fp(&self, fingerprint: &str) -> Result<Option<models::Cert>> {
        self.readonly.cert_by_fp(fingerprint)
    }

    fn certs_by_email(&self, email: &str) -> Result<Vec<models::Cert>> {
        self.readonly.certs_by_email(email)
    }

    fn certs_by_user(&self, user: &models::User) -> Result<Vec<models::Cert>> {
        self.readonly.certs_by_user(user)
    }

    fn emails(&self) -> Result<Vec<models::CertEmail>> {
        self.readonly.emails()
    }

    fn emails_by_cert(&self, cert: &models::Cert) -> Result<Vec<models::CertEmail>> {
        self.readonly.emails_by_cert(cert)
    }

    fn user_by_cert(&self, cert: &models::Cert) -> Result<Option<models::User>> {
        self.readonly.user_by_cert(cert)
    }

    fn users_sorted_by_name(&self) -> Result<Vec<models::User>> {
        self.readonly.users_sorted_by_name()
    }

    fn revocation_exists(&self, revocation: &[u8]) -> Result<bool> {
        self.readonly.revocation_exists(revocation)
    }

    fn revocations_by_cert(&self, cert: &models::Cert) -> Result<Vec<models::Revocation>> {
        self.readonly.revocations_by_cert(cert)
    }

    fn revocation_by_hash(&self, hash: &str) -> Result<Option<models::Revocation>> {
        self.readonly.revocation_by_hash(hash)
    }

    fn list_bridges(&self) -> Result<Vec<models::Bridge>> {
        self.readonly.list_bridges()
    }

    // ------

    fn bridge_by_email(&self, email: &str) -> Result<Option<models::Bridge>> {
        self.readonly.bridge_by_email(email)
    }

    fn queue_not_done(&self) -> Result<Vec<models::Queue>> {
        self.readonly.queue_not_done()
    }
}

/// Returns Errors for all fn, because a SplitBackDb should never
/// be written to
/// (some fn throw unimplemented, because they should definitely
/// not be called on this Database implementation and indicate a
/// wrong use of this struct)
impl CaStorageWrite for SplitBackDb {
    fn into_uninit(self: Box<Self>) -> UninitDb {
        unimplemented!("This should never be used with a SplitBackDb")
    }

    fn cacert_update(self, _cacert: &Cacert) -> Result<()> {
        Err(anyhow::anyhow!(
            "Unsupported operation on Split-mode backend CA"
        ))
    }

    fn ca_import_tsig(&self, _cert: &[u8]) -> Result<()> {
        Err(anyhow::anyhow!(
            "Unsupported operation on Split-mode backend CA"
        ))
    }

    fn cert_add(
        &self,
        _pub_cert: &str,
        _fingerprint: &str,
        _user_id: Option<i32>,
    ) -> Result<crate::db::models::Cert> {
        Err(anyhow::anyhow!(
            "Unsupported operation on Split-mode backend CA"
        ))
    }

    fn cert_update(&self, _cert: &[u8]) -> Result<()> {
        Err(anyhow::anyhow!(
            "Unsupported operation on Split-mode backend CA"
        ))
    }

    fn cert_delist(&self, _fp: &str) -> Result<()> {
        Err(anyhow::anyhow!(
            "Unsupported operation on Split-mode backend CA"
        ))
    }

    fn cert_deactivate(&self, _fp: &str) -> Result<()> {
        Err(anyhow::anyhow!(
            "Unsupported operation on Split-mode backend CA"
        ))
    }

    fn user_add(
        &self,
        _name: Option<&str>,
        _cert_fp: (&str, &str),
        _emails: &[&str],
        _revocation_certs: &[String],
        _ca_cert_tsigned: Option<&[u8]>,
    ) -> Result<User> {
        Err(anyhow::anyhow!(
            "Unsupported operation on Split-mode backend CA"
        ))
    }

    fn revocation_add(&self, _revocation: &[u8]) -> Result<()> {
        Err(anyhow::anyhow!(
            "Unsupported operation on Split-mode backend CA"
        ))
    }

    fn revocation_apply(&self, _db_revoc: Revocation) -> Result<()> {
        Err(anyhow::anyhow!(
            "Unsupported operation on Split-mode backend CA"
        ))
    }

    fn bridge_add(
        &self,
        _remote_armored: &str,
        _remote_fp: &str,
        _remote_email: &str,
        _scope: &str,
    ) -> Result<Bridge> {
        Err(anyhow::anyhow!(
            "Unsupported operation on Split-mode backend CA"
        ))
    }
}

impl CaStorageRW for SplitBackDb {}
