// SPDX-FileCopyrightText: 2019-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

// temporary workaround for https://github.com/rust-lang/rust-clippy/issues/9014 [2022-07-27]
#![allow(clippy::extra_unused_lifetimes)]

//! Database model for OpenPGP CA

use crate::db::schema::*;

#[derive(Queryable, Debug, Clone, AsChangeset, Identifiable)]
pub(crate) struct Ca {
    pub id: i32,
    pub domainname: String,
}

#[derive(Insertable, Debug)]
#[table_name = "cas"]
pub(crate) struct NewCa<'a> {
    pub domainname: &'a str,
}

#[derive(Queryable, Debug, Associations, Clone, AsChangeset, Identifiable)]
#[changeset_options(treat_none_as_null = "true")]
#[belongs_to(Ca)]
pub(crate) struct Cacert {
    pub id: i32,
    pub active: bool, // exactly one cacert must be active per ca_id
    pub fingerprint: String,
    pub priv_cert: String, // private key if softkey backend, public key if card backend
    pub backend: Option<String>,
    // https://docs.diesel.rs/diesel/associations/index.html
    pub ca_id: i32,
}

#[derive(Insertable)]
#[table_name = "cacerts"]
pub(crate) struct NewCacert<'a> {
    pub active: bool,
    pub fingerprint: &'a str,
    pub priv_cert: String,
    pub backend: Option<&'a str>, // backend configuration, if not softkey
    pub ca_id: i32,
}

/// A user as modeled in the CA
#[derive(Identifiable, Queryable, Debug, Associations, Clone, AsChangeset, PartialEq, Eq, Hash)]
#[changeset_options(treat_none_as_null = "true")]
#[belongs_to(Ca)]
pub struct User {
    pub id: i32,
    pub name: Option<String>,
    // https://docs.diesel.rs/diesel/associations/index.html
    pub ca_id: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "users"]
pub(crate) struct NewUser<'a> {
    pub name: Option<&'a str>,
    pub ca_id: i32,
}

/// A user certificate as modeled in the CA (linked to users)
#[derive(Identifiable, Queryable, Debug, Associations, Clone, AsChangeset, PartialEq, Eq, Hash)]
#[changeset_options(treat_none_as_null = "true")]
#[belongs_to(User)]
pub struct Cert {
    pub id: i32,
    pub fingerprint: String,
    pub pub_cert: String,
    pub user_id: Option<i32>,
    pub delisted: bool,
    pub inactive: bool,
}

#[derive(Insertable, Debug)]
#[table_name = "certs"]
pub(crate) struct NewCert<'a> {
    pub fingerprint: &'a str,
    pub pub_cert: &'a str,
    pub user_id: Option<i32>,
    pub delisted: bool,
    pub inactive: bool,
}

/// Email addresses that are associated with user certificates
#[derive(Associations, Identifiable, Queryable, Debug, Clone, AsChangeset)]
#[table_name = "certs_emails"]
#[belongs_to(Cert)]
pub struct CertEmail {
    pub id: i32,
    pub addr: String,
    pub cert_id: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "certs_emails"]
pub(crate) struct NewCertEmail {
    pub addr: String,
    pub cert_id: i32,
}

/// Revocation certificates (linked to user certificates)
#[derive(Identifiable, Queryable, Debug, Associations, Clone, AsChangeset)]
#[belongs_to(Cert)]
pub struct Revocation {
    pub id: i32,
    pub hash: String,
    pub revocation: String,
    pub published: bool,
    // FIXME - https://docs.diesel.rs/diesel/associations/index.html
    pub cert_id: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "revocations"]
pub(crate) struct NewRevocation<'a> {
    pub hash: &'a str,
    pub revocation: &'a str,
    pub published: bool,
    pub cert_id: i32,
}

/// Bridges between this CA and an external CA
#[derive(Identifiable, Queryable, Clone, AsChangeset, Debug)]
pub struct Bridge {
    pub id: i32,
    pub email: String,
    pub scope: String,
    pub cert_id: i32,
    pub cas_id: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "bridges"]
pub(crate) struct NewBridge<'a> {
    pub email: &'a str,
    pub scope: &'a str,
    pub cert_id: i32,
    pub cas_id: i32,
}

/// Queue entries
#[derive(Identifiable, Queryable, Clone, AsChangeset, Debug)]
#[table_name = "queue"]
pub struct Queue {
    pub id: i32,
    pub task: String,
    pub done: bool,
}

#[derive(Insertable, Debug)]
#[table_name = "queue"]
pub(crate) struct NewQueue<'a> {
    pub task: &'a str,
    pub done: bool,
}

// FIXME: prefs table
