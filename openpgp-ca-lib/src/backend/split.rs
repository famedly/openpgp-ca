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

use crate::db::models::{NewQueue, Queue};
use crate::db::OcaDb;
use crate::pgp;
use crate::secret::CaSec;
use crate::storage::{CaStorageRW, QueueDb};

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
