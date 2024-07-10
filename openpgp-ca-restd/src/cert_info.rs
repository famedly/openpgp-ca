// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::convert::{TryFrom, TryInto};
use std::time::SystemTime;

use anyhow::Context;
use chrono::{DateTime, Utc};
use sequoia_openpgp::cert::amalgamation::key::ErasedKeyAmalgamation;
use sequoia_openpgp::cert::amalgamation::{ComponentAmalgamation, ValidateAmalgamation};
use sequoia_openpgp::packet::key;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::Cert;
use serde::{Deserialize, Serialize};

const POLICY: &StandardPolicy = &StandardPolicy::new();

/// Human-readable, factual information about an OpenPGP certificate
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertInfo {
    pub user_ids: Vec<UserId>,

    pub primary: Key,
    pub subkeys: Vec<Key>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserId {
    pub email: Option<String>,
    pub name: Option<String>,

    /// If the UserID consists of valid utf8, this field contains the raw data
    /// (in many cases this will be redundant with the data in email + name).
    ///
    /// NOTE: this field contains user-provided utf8. It may contain html or
    /// quotes, which the frontend might need to protect itself against.
    pub raw: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocations: Option<Vec<Revocation>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Key {
    pub fingerprint: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,

    pub creation_time: DateTime<Utc>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    /// if this (sub-)key has an expiration_time, `expires_in_sec` shows in
    /// how many seconds it will expire (e.g. "+1000" means "will expire in
    /// 1000 seconds"), or if negative, how long ago it has expired (e.g.
    /// "-1000" means "has expired 1000s ago)
    pub expires_in_sec: Option<i64>,

    pub algo: String,
    pub bits: usize,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocations: Option<Vec<Revocation>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Revocation {
    pub reason: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub information: Option<String>,

    pub time: Option<DateTime<Utc>>,
}

impl TryFrom<&Cert> for CertInfo {
    type Error = anyhow::Error;

    fn try_from(cert: &Cert) -> Result<Self, Self::Error> {
        let mut user_ids: Vec<UserId> = vec![];

        for userid in cert.userids() {
            user_ids.push((&userid).try_into()?)
        }

        let ka: ErasedKeyAmalgamation<_> = cert.primary_key().into();
        let primary: Key = (&ka).into();

        let subkeys = cert
            .keys()
            .subkeys()
            .map(|ka| {
                let ka: ErasedKeyAmalgamation<_> = ka.into();
                (&ka).into()
            })
            .collect();

        let ci = CertInfo {
            user_ids,
            primary,
            subkeys,
        };

        Ok(ci)
    }
}

impl TryFrom<&ComponentAmalgamation<'_, sequoia_openpgp::packet::UserID>> for UserId {
    type Error = anyhow::Error;

    fn try_from(
        uid: &ComponentAmalgamation<sequoia_openpgp::packet::UserID>,
    ) -> Result<Self, Self::Error> {
        let email = uid
            .email2()
            .context("ERROR while converting userid.email")?
            .map(|s| s.to_string());

        let name = uid
            .name2()
            .context("ERROR while converting userid.name")?
            .map(|s| s.to_string());

        let raw = String::from_utf8(uid.value().to_vec()).ok();

        let revocations: Vec<_> = uid.self_revocations().map(|rev| rev.into()).collect();

        let revocations = if revocations.is_empty() {
            None
        } else {
            Some(revocations)
        };

        Ok(UserId {
            email,
            name,
            raw,
            revocations,
        })
    }
}

impl From<&ErasedKeyAmalgamation<'_, key::PublicParts>> for Key {
    fn from(ka: &ErasedKeyAmalgamation<key::PublicParts>) -> Self {
        let (expiration, flags) = if let Ok(valid_sk) = ka.clone().with_policy(POLICY, None) {
            (valid_sk.key_expiration_time(), valid_sk.key_flags())
        } else {
            (None, None)
        };

        let expires_in_sec = if let Some(exp) = expiration {
            let now = SystemTime::now();

            if exp > now {
                // expiration is in the future
                Some(exp.duration_since(now).unwrap().as_secs() as i64)
            } else {
                // expiration is in the past
                Some(-(now.duration_since(exp).unwrap().as_secs() as i64))
            }
        } else {
            None
        };

        let fingerprint = ka.fingerprint().to_spaced_hex();

        let creation = ka.creation_time();

        let algo = ka.pk_algo();
        let algo = algo.to_string();
        let bits = ka.key().mpis().bits().unwrap_or(0);

        let flags = if let Some(f) = flags {
            if !f.is_empty() {
                Some(format!("{f:?}"))
            } else {
                None
            }
        } else {
            None
        };

        let revocations: Vec<_> = ka.self_revocations().map(|rev| rev.into()).collect();

        let revocations = if revocations.is_empty() {
            None
        } else {
            Some(revocations)
        };

        Key {
            fingerprint,
            flags,
            creation_time: creation.into(),
            expiration_time: expiration.map(|time| time.into()),
            expires_in_sec,
            algo,
            bits,
            revocations,
        }
    }
}

impl From<&Signature> for Revocation {
    fn from(rev: &Signature) -> Self {
        let rfr = rev.reason_for_revocation();

        if let Some(r) = rfr {
            let reason = Some(r.0.to_string());

            let information = if let Ok(msg) = String::from_utf8(r.1.to_vec()) {
                if !msg.is_empty() {
                    Some(msg)
                } else {
                    None
                }
            } else {
                Some("ERROR: bad utf8".to_string())
            };

            let rev_time = rev.signature_creation_time();
            let time = rev_time.map(|time| time.into());

            Revocation {
                reason,
                information,
                time,
            }
        } else {
            Revocation {
                reason: None,
                information: None,
                time: None,
            }
        }
    }
}
