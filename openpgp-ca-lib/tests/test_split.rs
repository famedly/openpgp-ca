// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

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
    back.ca_split_process(csr_file, sigs_file.clone())?;
    front.ca_split_import(sigs_file)?;

    let certs = front.user_certs_get_all()?;
    assert_eq!(certs.len(), 1);

    let cert = &certs[0];

    let alice = front.cert_check_ca_sig(cert)?;
    assert_eq!(alice.certified.len(), 1);
    assert_eq!(alice.uncertified.len(), 0);

    Ok(())
}
