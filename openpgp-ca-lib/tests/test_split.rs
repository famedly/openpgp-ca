// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use std::path::PathBuf;

use anyhow::Result;
use openpgp_ca_lib::Oca;
use tempfile::TempDir;

mod util;

#[test]
fn split_certify() -> Result<()> {
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.into_path();

    let mut csr_file = tmp_path.clone();
    csr_file.push("csr.txt");

    let mut sigs_file = tmp_path.clone();
    sigs_file.push("certs.txt");

    // Make new softkey CA
    let (_gpg, cau) = util::setup_one_uninit()?;
    let ca = cau.init_softkey("example.org", None)?;

    // Split softkey CA into back and front instances
    let mut front_path = tmp_path.clone();
    front_path.push("front.oca");
    let mut back_path = tmp_path;
    back_path.push("back.oca");

    ca.ca_split_into(&front_path, &back_path)?;
    let front = Oca::open(front_path.to_str())?;
    let back = Oca::open(back_path.to_str())?;

    // Make user on online ca
    front.user_new(Some("Alice"), &["alice@example.org"], None, false, false)?;

    let certs = front.user_certs_get_all()?;
    assert_eq!(certs.len(), 1);

    let cert = &certs[0];

    let alice = front.cert_check_ca_sig(cert)?;
    assert_eq!(alice.certified.len(), 0);
    assert_eq!(alice.uncertified.len(), 1);

    // Ask backing ca to certify alice

    front.ca_split_export(csr_file.clone())?;
    back.ca_split_certify(csr_file, sigs_file.clone())?;
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
fn split_add_bridge() -> Result<()> {
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.into_path();

    let mut csr_file = tmp_path.clone();
    csr_file.push("csr.txt");

    let mut sigs_file = tmp_path.clone();
    sigs_file.push("certs.txt");

    // Make new softkey CA
    let (gpg, cau1, cau2) = util::setup_two_uninit()?;
    let ca1 = cau1.init_softkey("example.org", None)?;
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
    back.ca_split_certify(csr_file, sigs_file.clone())?;
    front.ca_split_import(sigs_file)?;

    // load bridges from front instance
    let bridges = front.bridges_get()?;
    assert_eq!(bridges.len(), 1);

    let bridge = &bridges[0];

    let tsig = front.check_tsig_on_bridge(bridge)?;
    assert!(tsig);

    Ok(())
}
