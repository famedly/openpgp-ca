// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

extern crate core;

use std::env;

use anyhow::Result;
use openpgp_ca_lib::{pgp, Uninit};
use rusqlite::Connection;

use crate::util::gnupg_test_wrapper;

mod util;

// Running these tests in a dev environment against a local card:
// IDENT="FFFE:01234567" cargo test init_on_card --no-default-features --features card -- --nocapture

#[test]
#[cfg_attr(not(feature = "card"), ignore)]
/// Generate a CA key on the card, create a user with the CA and check that is is certified.
fn init_on_card() -> Result<()> {
    let ident = env::var("IDENT").expect("IDENT is unset in environment");
    util::reset_card(&ident)?;

    let (_gpg, cau) = util::setup_one_uninit()?;
    let ca = cau.init_card_generate_on_card(&ident, "example.org", None, None)?;

    ca.user_new(
        Some("Alice"),
        &["alice@example.org"],
        None,
        false,
        false,
        None,
    )?;

    let certs = ca.user_certs_get_all()?;
    assert_eq!(certs.len(), 1);
    let alice = &certs[0];

    assert!(
        !ca.cert_check_ca_sig(alice)?.certified.is_empty(),
        "Alice is not certified by CA"
    );

    assert!(
        ca.cert_check_tsig_on_ca(alice)?,
        "CA cert is not signed by Alice"
    );

    assert_eq!(
        ca.ca_get_cert_pub()?.fingerprint(),
        util::card_auth_slot_fingerprint(&ident)?,
        "CA fingerprint in database and AUT fingerprint on card don't match"
    );

    Ok(())
}

#[test]
#[cfg_attr(not(feature = "card"), ignore)]
/// Initialize a softkey CA and export its private key.
/// Import the private CA key into a new card-backed CA.
/// Create a user with the new CA and check that is is certified.
fn init_card_import_key() -> Result<()> {
    let ident = env::var("IDENT").expect("IDENT is unset in environment");
    util::reset_card(&ident)?;

    // Initialize a softkey CA instance to generate a pre-existing private CA key
    let gpg = gnupg_test_wrapper::make_context()?;

    let mut ca_path = gpg.get_homedir().to_path_buf();
    ca_path.push("ca.sqlite");
    assert!(ca_path.to_str().is_some());

    let cau_old = Uninit::new(ca_path.to_str())?;
    let _ca_old = cau_old.init_softkey("example.org", None, None)?;

    // Retrieve the "old" CA key
    let sqlite = Connection::open(ca_path)?;
    // Grab CA key directly from sqlite db for this test
    let ca_private: String = sqlite
        .query_row("SELECT priv_cert FROM cacerts", &[], |row| row.get(0))
        .unwrap();

    // Set up a new Card-based CA using the "old" CA private key
    let (_gpg, cau) = util::setup_one_uninit()?;
    let ca = cau.init_card_import_key(&ident, "example.org", ca_private.as_bytes())?;

    ca.user_new(
        Some("Alice"),
        &["alice@example.org"],
        None,
        false,
        false,
        None,
    )?;

    let certs = ca.user_certs_get_all()?;
    assert_eq!(certs.len(), 1);
    let alice = &certs[0];

    assert!(
        !ca.cert_check_ca_sig(alice)?.certified.is_empty(),
        "Alice is not certified by CA"
    );

    assert!(
        ca.cert_check_tsig_on_ca(alice)?,
        "CA cert is not signed by Alice"
    );

    assert_eq!(
        ca.ca_get_cert_pub()?.fingerprint(),
        util::card_auth_slot_fingerprint(&ident)?,
        "CA fingerprint in database and AUT fingerprint on card don't match"
    );

    Ok(())
}

#[test]
#[cfg_attr(not(feature = "card"), ignore)]
/// Initialize a card-backed CA, get its public key and User PIN.
///
/// Initialize a new card-backed CA based on the public key and OpenPGP card of the first CA.
/// Create a user with the new CA and check that is is certified.
fn init_card_import_card() -> Result<()> {
    let ident = env::var("IDENT").expect("IDENT is unset in environment");
    util::reset_card(&ident)?;

    // Initialize a softkey CA instance to generate a pre-existing private CA key
    let gpg = gnupg_test_wrapper::make_context()?;

    let mut ca_path = gpg.get_homedir().to_path_buf();
    ca_path.push("ca.sqlite");
    assert!(ca_path.to_str().is_some());

    let cau_old = Uninit::new(ca_path.to_str())?;
    let (ca_old, _ca_private) =
        cau_old.init_card_generate_on_host(&ident, "example.org", None, None)?;

    let ca_pub = ca_old.ca_get_cert_pub()?;

    // Retrieve the User PIN
    let sqlite = Connection::open(ca_path)?;
    // Grab PIN directly from sqlite db for this test
    let backend: String = sqlite
        .query_row("SELECT backend FROM cacerts", &[], |row| row.get(0))
        .unwrap();
    assert!(backend.starts_with("card;"));

    let pin = backend.split(';').last().unwrap();

    // -- Set up a new Card-based CA using the pre-existing CA key material on the card
    let (_gpg, cau) = util::setup_one_uninit()?;
    let ca = cau.init_card_import_card(
        &ident,
        pin,
        "example.org",
        pgp::cert_to_armored(&ca_pub)?.as_bytes(),
    )?;

    ca.user_new(
        Some("Alice"),
        &["alice@example.org"],
        None,
        false,
        false,
        None,
    )?;

    let certs = ca.user_certs_get_all()?;
    assert_eq!(certs.len(), 1);
    let alice = &certs[0];

    assert!(
        !ca.cert_check_ca_sig(alice)?.certified.is_empty(),
        "Alice is not certified by CA"
    );

    assert!(
        ca.cert_check_tsig_on_ca(alice)?,
        "CA cert is not signed by Alice"
    );

    assert_eq!(
        ca.ca_get_cert_pub()?.fingerprint(),
        util::card_auth_slot_fingerprint(&ident)?,
        "CA fingerprint in database and AUT fingerprint on card don't match"
    );

    Ok(())
}

#[test]
#[cfg_attr(not(feature = "card"), ignore)]
/// Initialize a softkey CA instance. Create a user in it.
/// Migrate the CA to be a card-backed CA instance. Check that the user is still considered
/// certified.
fn card_import_migrate() -> Result<()> {
    let ident = env::var("IDENT").expect("IDENT is unset in environment");
    util::reset_card(&ident)?;

    // Initialize a softkey CA instance to generate a pre-existing private CA key
    let gpg = gnupg_test_wrapper::make_context()?;

    let mut ca_path = gpg.get_homedir().to_path_buf();
    ca_path.push("ca.sqlite");
    assert!(ca_path.to_str().is_some());

    {
        // Set up "pre-existing" softkey CA instance

        let cau_old = Uninit::new(ca_path.to_str())?;
        let ca_old = cau_old.init_softkey("example.org", None, None)?;

        ca_old.user_new(
            Some("Alice"),
            &["alice@example.org"],
            None,
            false,
            false,
            None,
        )?;
    }

    // Migrate the softkey instance to a card-backed one
    let cau = Uninit::new(ca_path.to_str())?;
    let ca = cau.migrate_card_import_key(&ident)?;

    let certs = ca.user_certs_get_all()?;
    assert_eq!(certs.len(), 1);
    let alice = &certs[0];

    assert!(
        !ca.cert_check_ca_sig(alice)?.certified.is_empty(),
        "Alice is not certified by CA"
    );

    assert!(
        ca.cert_check_tsig_on_ca(alice)?,
        "CA cert is not signed by Alice"
    );

    assert_eq!(
        ca.ca_get_cert_pub()?.fingerprint(),
        util::card_auth_slot_fingerprint(&ident)?,
        "CA fingerprint in database and AUT fingerprint on card don't match"
    );

    Ok(())
}
