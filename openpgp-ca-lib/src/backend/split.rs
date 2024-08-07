// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use std::collections::LinkedList;
use std::fs::File;
use std::path::PathBuf;
use std::rc::Rc;
use std::str::FromStr;

use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use chrono::{DateTime, TimeZone, Utc};
use crossterm::event::{read, Event, KeyCode, KeyEvent, KeyModifiers};
use sequoia_openpgp::packet::{Signature, UserID};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::{Marshal, SerializeInto};
use sequoia_openpgp::{Cert, Packet};
use serde::{Deserialize, Serialize};

use crate::db::models::{Bridge, Cacert, NewQueue, Queue, Revocation, User};
use crate::db::{models, OcaDb};
use crate::pgp;
use crate::secret::CaSec;
use crate::storage::{ca_get_cert_pub, CaStorage, CaStorageRW, CaStorageWrite, QueueDb, UninitDb};

// Internal version identifier, to be incremented when the JSON request format changes
// in an incompatible way.
//
// NOTE: In most problematic cases, Serde will fail to deserialize before the version is read.
const SPLIT_OCA_REQUEST_VERSION: u32 = 1;

// Internal version identifier, to be incremented when the JSON request format changes
// in an incompatible way.
//
// NOTE: In most problematic cases, Serde will fail to deserialize before the version is read.
const SPLIT_OCA_RESPONSE_VERSION: u32 = 1;

const CHRONO_FMT: &str = "%Y-%m-%d %H:%M:%S %Z";
const CHRONO_FMT_NAIVE: &str = "%Y-%m-%d %H:%M:%S";

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SplitOcaRequests {
    version: u32,
    ca_fingerprint: String,
    created: DateTime<Utc>, // informational timestamp
    queue: LinkedList<(i32, DateTime<Utc>, QueueEntry)>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum QueueEntry {
    CertificationReq(CertificationReq),
    BridgeReq(BridgeReq),
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CertificationReq {
    cert: String,
    user_ids: Vec<String>,
    days: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct BridgeReq {
    cert: String,
    scope_regexes: Vec<String>,
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

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SplitOcaResponse {
    version: u32,
    ca_fingerprint: String,
    created: DateTime<Utc>, // informational timestamp
    queue: LinkedList<(i32, QueueResponse)>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum QueueResponse {
    CertificationResp(CertificationResp),
    BridgeResp(BridgeResp),
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CertificationResp {
    fingerprint: String,
    sigs: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct BridgeResp {
    cert: String,
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

    pub(crate) fn export_csr_queue(output: PathBuf, queue: Vec<Queue>, ca_fp: &str) -> Result<()> {
        if !queue.is_empty() {
            let mut qes: LinkedList<(i32, DateTime<Utc>, QueueEntry)> = LinkedList::new();

            for entry in &queue {
                let task = &entry.task;
                let qe: QueueEntry = serde_json::from_str(task)?;

                let created = Utc.from_utc_datetime(&entry.created);

                qes.push_back((entry.id, created, qe));
            }

            let sor = SplitOcaRequests {
                version: SPLIT_OCA_REQUEST_VERSION,
                ca_fingerprint: ca_fp.to_string(),
                created: Utc::now(),
                queue: qes,
            };

            let output = File::create(output)?;
            serde_json::to_writer_pretty(output, &sor)?;

            println!(
                "Exported queue with {} entries for processing by the back instance",
                queue.len()
            );
        } else {
            println!("The queue contains no requests for the back instance, didn't export.");
        }

        Ok(())
    }
}

impl CaSec for SplitCa {
    fn cert(&self) -> Result<Cert> {
        self.db.cert()
    }

    /// Always returns an empty vec -> the certifications are created asynchronously.
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

        let created = Utc::now().naive_utc();

        let q = NewQueue {
            created,
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

    fn bridge_to_remote_ca(&self, remote_ca: Cert, scope_regexes: Vec<String>) -> Result<Cert> {
        let c = pgp::cert_to_armored(&remote_ca)?;

        let br = BridgeReq {
            scope_regexes,
            cert: c,
        };

        // Wrap the CertificationReq in a QueueEntry and store as a JSON string.
        let qe = QueueEntry::BridgeReq(br);
        let serialized = serde_json::to_string(&qe)?;

        let created = Utc::now().naive_utc();

        let q = NewQueue {
            created,
            task: &serialized,
            done: false,
        };

        // Store the certification task in the queue
        self.db.queue_insert(q)?;

        // The Signatures cannot be generated here, so we return the unchanged Cert
        // FIXME: change return type?
        Ok(remote_ca)
    }

    fn bridge_revoke(&self, _remote_ca: &Cert) -> Result<(Signature, Cert)> {
        Err(anyhow::anyhow!(
            "Operation is not currently supported on a split-mode CA instance. Please perform it on your back CA instance."
        ))
    }
}

fn gen_certification(
    ca_sec: &dyn CaSec,
    c: &Cert,
    uids: &[String],
    days_valid: Option<u64>,
) -> Result<QueueResponse> {
    let u: Vec<_> = c
        .userids()
        .filter(|u| uids.contains(&u.userid().to_string()))
        .map(|ca| ca.userid())
        .collect();

    // Generate certifications
    let s = ca_sec.sign_user_ids(c, &u[..], days_valid)?;

    // Map Signatures to base64 encoded Strings
    let mut sigs: Vec<_> = vec![];
    for sig in s {
        let mut v: Vec<u8> = vec![];
        sig.serialize(&mut v)?;
        let base64: String = general_purpose::STANDARD.encode(v);
        sigs.push(base64);
    }

    let resp = CertificationResp {
        sigs,
        fingerprint: c.fingerprint().to_hex(),
    };

    Ok(QueueResponse::CertificationResp(resp))
}

fn gen_bridge(ca_sec: &dyn CaSec, c: Cert, scope_regexes: Vec<String>) -> Result<QueueResponse> {
    let tsigned = ca_sec.bridge_to_remote_ca(c, scope_regexes)?;
    let cert = pgp::cert_to_armored(&tsigned)?;

    let resp = BridgeResp { cert };

    Ok(QueueResponse::BridgeResp(resp))
}

fn get_raw_key() -> Result<KeyEvent> {
    crossterm::terminal::enable_raw_mode()?;

    // Loop until we get a KeyEvent
    loop {
        let event = read()?;

        if let Event::Key(key_event) = event {
            crossterm::terminal::disable_raw_mode()?;

            return Ok(key_event);
        }
    }
}

// FIXME:
// The interactive handling of certifications should take place in the frontend,
// not in this library.
pub(crate) fn certify(
    ca_sec: &dyn CaSec,
    import: PathBuf,
    export: PathBuf,
    batch: bool,
) -> Result<()> {
    let input = File::open(import)?;
    let reqs: SplitOcaRequests = serde_json::from_reader(input)?;

    if reqs.version != SPLIT_OCA_REQUEST_VERSION {
        return Err(anyhow::anyhow!(
            "Unexpected version {} in request file",
            reqs.version
        ));
    }

    if reqs.ca_fingerprint != ca_sec.cert()?.fingerprint().to_hex() {
        return Err(anyhow::anyhow!(
            "Unexpected CA fingerprint {} in request file (doesn't match this back CA)",
            reqs.ca_fingerprint
        ));
    }

    println!(
        "Processing {} certification requests, exported on {}.",
        reqs.queue.len(),
        reqs.created.format(CHRONO_FMT)
    );
    println!();

    // queue responses
    let mut qrs: LinkedList<(i32, QueueResponse)> = LinkedList::new();

    for (db_id, created, qe) in reqs.queue {
        match qe {
            QueueEntry::CertificationReq(cr) => {
                // Cert/User ID that should be certified
                let c = cr.cert()?;
                let days_valid = cr.days();
                let uids = cr.user_ids();

                let mut doit = || -> Result<()> {
                    let qr = gen_certification(ca_sec, &c, uids, days_valid)?;
                    qrs.push_back((db_id, qr));
                    Ok(())
                };

                if !batch {
                    // interactive mode
                    println!(
                        "Request for User ID certification [created {}]:",
                        created.format(CHRONO_FMT)
                    );
                    println!();
                    println!("Bind key {} with", c.fingerprint().to_hex(),);
                    for u in uids {
                        println!("- '{}'", u);
                    }

                    // FIXME: show if a previous certification by this CA exists
                    // and inform the CA operator, if so.
                    // [see sequoia-sq:src/commands/mod.rs:active_certification]

                    println!();
                    println!("Certify? [y/n]");

                    let key_event = get_raw_key()?;
                    if key_event.code == KeyCode::Char('y')
                        && key_event.modifiers == KeyModifiers::NONE
                    {
                        doit()?;
                    } else {
                        println!();
                        println!("Skipping this queue entry");
                    }

                    println!();
                    println!();
                } else {
                    // batch mode
                    doit()?;
                }
            }
            QueueEntry::BridgeReq(br) => {
                let c = Cert::from_str(&br.cert)?;

                let mut doit = || -> Result<()> {
                    let qr = gen_bridge(ca_sec, c.clone(), br.scope_regexes.clone())?;
                    qrs.push_back((db_id, qr));
                    Ok(())
                };

                if !batch {
                    // interactive mode
                    println!(
                        "Request for bridge certification [created {}]:",
                        created.format(CHRONO_FMT)
                    );
                    println!();
                    println!("Remote key {}", c.fingerprint().to_hex());
                    println!("Scoped for:");
                    for scope in &br.scope_regexes {
                        println!("- '{}'", scope);
                    }

                    println!();
                    println!("Certify? [y/n]");

                    let key_event = get_raw_key()?;
                    if key_event.code == KeyCode::Char('y')
                        && key_event.modifiers == KeyModifiers::NONE
                    {
                        doit()?;
                    } else {
                        println!();
                        println!("Skipping this queue entry");
                    }

                    println!();
                    println!();
                } else {
                    // batch mode
                    doit()?;
                }
            }
        }
    }

    let sor = SplitOcaResponse {
        version: SPLIT_OCA_RESPONSE_VERSION,
        ca_fingerprint: ca_sec.cert()?.fingerprint().to_hex(),
        created: Utc::now(),
        queue: qrs,
    };

    // Write to output file
    let output = File::create(export)?;
    serde_json::to_writer_pretty(output, &sor)?;

    println!("Processed {} certification requests", sor.queue.len());

    Ok(())
}

pub(crate) fn ca_split_import(storage: &dyn CaStorageRW, file: PathBuf) -> Result<()> {
    let input = File::open(file)?;
    let sor: SplitOcaResponse = serde_json::from_reader(input)?;

    if sor.version != SPLIT_OCA_RESPONSE_VERSION {
        return Err(anyhow::anyhow!(
            "Unexpected response format version {}",
            sor.version
        ));
    }

    if sor.ca_fingerprint != storage.ca_get_cert_pub()?.fingerprint().to_hex() {
        return Err(anyhow::anyhow!(
            "Unexpected remote CA {}",
            sor.ca_fingerprint
        ));
    }

    let len = sor.queue.len();

    // count queue entries that have already been imported (if any)
    let mut done: usize = 0;

    for (db_id, qr) in sor.queue {
        if let Some(q) = storage.queue(db_id)? {
            // has this queue entry already been marked as "done"?

            if q.done {
                done += 1;

                // already done: skip processing this entry
                continue;
            }
        } else {
            return Err(anyhow::anyhow!(
                "Got a result for an unexpected queue id: {}",
                db_id
            ));
        }

        match qr {
            QueueResponse::CertificationResp(cr) => {
                let mut packets: Vec<Packet> = vec![];
                for s in cr.sigs {
                    let bytes = general_purpose::STANDARD
                        .decode(s)
                        .map_err(|e| anyhow::anyhow!("Error while decoding base64: {}", e))?;
                    let s = Signature::from_bytes(&bytes)?.into();
                    packets.push(s);
                }

                if let Some(cert) = storage.cert_by_fp(&cr.fingerprint)? {
                    let c = Cert::from_str(&cert.pub_cert)?;
                    let certified = c.insert_packets(packets)?;

                    storage.cert_update(&certified.to_vec()?)?;
                } else {
                    // FIXME: mark queue entry as failed?
                    return Err(anyhow::anyhow!("failed to load fp {}", cr.fingerprint));
                }
            }
            QueueResponse::BridgeResp(br) => {
                // Merge update to bridge cert into database
                // (presumably the update consists of a new tsig from our CA)
                storage.cert_update(br.cert.as_bytes())?;
            }
        }

        // Mark queue entry as done.
        // FIXME: this should share a transaction with "cert_update"
        storage.queue_mark_done(db_id)?;
    }

    println!("Imported {len} certifications from the back instance.");
    if done > 0 {
        println!("WARN: {done} certifications were ignored (they were already imported).");
    }

    Ok(())
}

pub(crate) fn ca_split_show_queue(storage: &dyn CaStorageRW) -> Result<()> {
    let queue = storage.queue_not_done()?;
    for q in queue {
        let qe: QueueEntry = serde_json::from_str(&q.task)?;
        match qe {
            QueueEntry::CertificationReq(cr) => {
                let c = Cert::from_str(&cr.cert)?;

                println!("Certification request [#{}]", q.id);
                println!("  For User IDs {:?}", cr.user_ids);
                println!("  On {}", c.fingerprint().to_hex());
                if let Some(days) = cr.days {
                    println!("  Limited to {} days", days);
                } else {
                    println!("  No expiration");
                }
                println!("  Queued: {} UTC", q.created.format(CHRONO_FMT_NAIVE));
                println!();
            }
            QueueEntry::BridgeReq(br) => {
                let c = Cert::from_str(&br.cert)?;

                println!("Bridging request [#{}]", q.id,);
                println!("  For {}", c.fingerprint().to_hex(),);
                if br.scope_regexes.is_empty() {
                    println!("  Unscoped.");
                } else {
                    print!("  Scoped to");
                    for s in br.scope_regexes {
                        print!(" '{}'", s)
                    }
                    println!();
                }
                println!("  Queued: {} UTC", q.created.format(CHRONO_FMT_NAIVE));
                println!();
            }
        }
    }

    Ok(())
}

pub(crate) struct SplitBackDb {
    // read-only from separate oca file
    readonly: Option<Rc<OcaDb>>,
}

impl SplitBackDb {
    pub(crate) fn new(readonly: Option<Rc<OcaDb>>) -> Self {
        Self { readonly }
    }
}

/// This implementation mimics the DbCa implementation,
/// using self.readonly as the datasource, if set.
/// If self.readonly is None, the impl returns Errors.
impl CaStorage for SplitBackDb {
    fn ca(&self) -> Result<models::Ca> {
        if let Some(readonly) = &self.readonly {
            let (ca, _) = readonly.get_ca()?;
            Ok(ca)
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    fn cacert(&self) -> Result<models::Cacert> {
        if let Some(readonly) = &self.readonly {
            let (_, cacert) = readonly.get_ca()?;
            Ok(cacert)
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    /// Get the Cert of the CA (without private key material).
    fn ca_get_cert_pub(&self) -> Result<Cert> {
        if let Some(readonly) = &self.readonly {
            ca_get_cert_pub(readonly)
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    fn certs(&self) -> Result<Vec<models::Cert>> {
        if let Some(readonly) = &self.readonly {
            readonly.certs()
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    fn cert_by_id(&self, id: i32) -> Result<Option<models::Cert>> {
        if let Some(readonly) = &self.readonly {
            readonly.cert_by_id(id)
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    fn cert_by_fp(&self, fingerprint: &str) -> Result<Option<models::Cert>> {
        if let Some(readonly) = &self.readonly {
            readonly.cert_by_fp(fingerprint)
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    fn certs_by_email(&self, email: &str) -> Result<Vec<models::Cert>> {
        if let Some(readonly) = &self.readonly {
            readonly.certs_by_email(email)
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    fn certs_by_user(&self, user: &models::User) -> Result<Vec<models::Cert>> {
        if let Some(readonly) = &self.readonly {
            readonly.certs_by_user(user)
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    fn emails(&self) -> Result<Vec<models::CertEmail>> {
        if let Some(readonly) = &self.readonly {
            readonly.emails()
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    fn emails_by_cert(&self, cert: &models::Cert) -> Result<Vec<models::CertEmail>> {
        if let Some(readonly) = &self.readonly {
            readonly.emails_by_cert(cert)
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    fn user_by_cert(&self, cert: &models::Cert) -> Result<Option<models::User>> {
        if let Some(readonly) = &self.readonly {
            readonly.user_by_cert(cert)
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    fn users_sorted_by_name(&self) -> Result<Vec<models::User>> {
        if let Some(readonly) = &self.readonly {
            readonly.users_sorted_by_name()
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    fn revocation_exists(&self, revocation: &[u8]) -> Result<bool> {
        if let Some(readonly) = &self.readonly {
            readonly.revocation_exists(revocation)
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    fn revocations_by_cert(&self, cert: &models::Cert) -> Result<Vec<models::Revocation>> {
        if let Some(readonly) = &self.readonly {
            readonly.revocations_by_cert(cert)
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    fn revocation_by_hash(&self, hash: &str) -> Result<Option<models::Revocation>> {
        if let Some(readonly) = &self.readonly {
            readonly.revocation_by_hash(hash)
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    fn list_bridges(&self) -> Result<Vec<models::Bridge>> {
        if let Some(readonly) = &self.readonly {
            readonly.list_bridges()
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    // ------

    fn bridge_by_email(&self, email: &str) -> Result<Option<models::Bridge>> {
        if let Some(readonly) = &self.readonly {
            readonly.bridge_by_email(email)
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    fn queue(&self, id: i32) -> Result<Option<Queue>> {
        if let Some(readonly) = &self.readonly {
            readonly.queue_by_id(id)
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
    }

    fn queue_not_done(&self) -> Result<Vec<models::Queue>> {
        if let Some(readonly) = &self.readonly {
            readonly.queue_not_done()
        } else {
            Err(anyhow::anyhow!(
                "Operation unsupported: split-mode backend CA without overlay database"
            ))
        }
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

    fn cacert_update(self: Box<Self>, _cacert: &Cacert) -> Result<()> {
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

    fn queue_mark_done(&self, _id: i32) -> Result<()> {
        unimplemented!("This should never be used with a SplitBackDb")
    }
}

impl CaStorageRW for SplitBackDb {}
