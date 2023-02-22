// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use std::env;
use std::path::PathBuf;

use anyhow::Result;
use openpgp_ca_lib::Oca;
use tempfile::TempDir;

mod util;

#[test]
#[cfg_attr(not(feature = "softkey"), ignore)]
fn split_certify_soft() -> Result<()> {
    let (_gpg, cau) = util::setup_one_uninit()?;

    // Make new softkey CA
    let ca = cau.init_softkey("example.org", None)?;

    split_certify(ca)
}

#[test]
#[cfg_attr(not(feature = "card"), ignore)]
fn split_certify_card() -> Result<()> {
    let ident = env::var("IDENT").expect("IDENT is unset in environment");
    util::reset_card(&ident)?;

    let (_gpg, cau) = util::setup_one_uninit()?;

    // Make new card-based CA
    let (ca, _privkey) = cau.init_card_generate_on_host(&ident, "example.org", None)?;

    split_certify(ca)
}

/// Tests certifying a User ID in a split CA.
///
/// Split `ca` into a front and back instance.
/// Create a user "Alice" in the front instance (causing a certification request).
/// Perform an export-certify-import cycle between front and back instance.
/// Assert that Alice's User ID is certified in the front instance.
fn split_certify(ca: Oca) -> Result<()> {
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.into_path();

    let mut csr_file = tmp_path.clone();
    csr_file.push("csr.txt");

    let mut sigs_file = tmp_path.clone();
    sigs_file.push("certs.txt");

    // Split original CA into back and front instances
    let mut front_path = tmp_path.clone();
    front_path.push("front.oca");
    let mut back_path = tmp_path;
    back_path.push("back.oca");

    ca.ca_split_into(&front_path, &back_path)?;
    let front = Oca::open(front_path.to_str())?;
    let back = Oca::open(back_path.to_str())?;

    // Make user on online ca
    front.user_new(Some("Alice"), &["alice@example.org"], None, false, false, None)?;

    let certs = front.user_certs_get_all()?;
    assert_eq!(certs.len(), 1);

    let cert = &certs[0];

    let alice = front.cert_check_ca_sig(cert)?;
    assert_eq!(alice.certified.len(), 0);
    assert_eq!(alice.uncertified.len(), 1);

    // Ask backing ca to certify alice

    front.ca_split_export(csr_file.clone())?;
    back.ca_split_certify(csr_file, sigs_file.clone(), true)?;
    front.ca_split_import(sigs_file)?;

    let certs = front.user_certs_get_all()?;
    assert_eq!(certs.len(), 1);

    let cert = &certs[0];

    let alice = front.cert_check_ca_sig(cert)?;
    assert_eq!(alice.certified.len(), 1);
    assert_eq!(alice.uncertified.len(), 0);

    Ok(())
}

#[test]
#[cfg_attr(not(feature = "softkey"), ignore)]
fn split_add_bridge_soft() -> Result<()> {
    let (_gpg, cau) = util::setup_one_uninit()?;

    // Make new softkey CA
    let ca = cau.init_softkey("example.org", None)?;

    split_add_bridge(ca)
}

#[test]
#[cfg_attr(not(feature = "card"), ignore)]
fn split_add_bridge_card() -> Result<()> {
    let ident = env::var("IDENT").expect("IDENT is unset in environment");
    util::reset_card(&ident)?;

    let (_gpg, cau) = util::setup_one_uninit()?;

    // Make new card-based CA
    let (ca, _privkey) = cau.init_card_generate_on_host(&ident, "example.org", None)?;

    split_add_bridge(ca)
}

/// Tests configuring a remote CA as a bridge in a split CA.
///
/// Split `ca1` into a front and back instance.
/// Create a separate (softkey based) `ca2` to act as a "remote" CA.
/// Configured as a bridge in `ca1`.
/// Perform an export-certify-import cycle between front and back instance.
/// Assert that `ca2` is certified as a bridge in the front instance.
fn split_add_bridge(ca1: Oca) -> Result<()> {
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.into_path();

    let mut csr_file = tmp_path.clone();
    csr_file.push("csr.txt");

    let mut sigs_file = tmp_path.clone();
    sigs_file.push("certs.txt");

    // Make new "remote" softkey CA
    let (gpg, cau2) = util::setup_one_uninit()?;
    let ca2 = cau2.init_softkey("remote.example", None)?;

    // Split softkey CA into back and front instances
    let mut front_path = tmp_path.clone();
    front_path.push("front.oca");
    let mut back_path = tmp_path;
    back_path.push("back.oca");

    ca1.ca_split_into(&front_path, &back_path)?;
    let front = Oca::open(front_path.to_str())?;
    let back = Oca::open(back_path.to_str())?;

    // Setup a new bridge
    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let ca2_file = format!("{home_path}/ca2.pubkey");
    let pub_ca2 = ca2.ca_get_pubkey_armored()?;
    std::fs::write(&ca2_file, pub_ca2).expect("Unable to write file");

    // front instance of ca1 certifies ca2
    front.add_bridge(None, &PathBuf::from(&ca2_file), None, false)?;

    // load bridges from front instance
    let bridges = front.bridges_get()?;
    assert_eq!(bridges.len(), 1);
    let bridge = &bridges[0];

    let tsig = front.check_tsig_on_bridge(bridge)?;
    assert!(!tsig); // tsig request is only queued so far

    // Ask backing ca to certify the bridged CA
    front.ca_split_export(csr_file.clone())?;
    back.ca_split_certify(csr_file, sigs_file.clone(), true)?;
    front.ca_split_import(sigs_file)?;

    // load bridges from front instance
    let bridges = front.bridges_get()?;
    assert_eq!(bridges.len(), 1);
    let bridge = &bridges[0];

    let tsig = front.check_tsig_on_bridge(bridge)?;
    assert!(tsig);

    Ok(())
}
