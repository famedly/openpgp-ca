// SPDX-FileCopyrightText: 2019-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use std::fs;
use std::path::Path;

use anyhow::Result;
use openpgp_ca_lib::pgp;
use openpgp_ca_lib::Uninit;
use sequoia_openpgp::{Cert, Fingerprint, KeyID};

mod util;
use util::gnupg_test_wrapper;

#[test]
/// create a CA for "example.org" and three users.
/// two of these users have emails in the "example.org" domain, the third
/// doesn't.
/// Export CA to wkd.
///
/// Expected outcome: the WKD contains three keys (CA + 2x user).
/// Check that the expected filenames exist in the WKD data.
#[cfg_attr(not(feature = "softkey"), ignore)]
fn test_ca_export_wkd() -> Result<()> {
    let gpg = gnupg_test_wrapper::make_context()?;
    // gpg.leak_tempdir();

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let db = format!("{home_path}/ca.sqlite");

    let cau = Uninit::new(Some(&db))?;
    let ca = cau.init_softkey("example.org", None, None)?;

    ca.user_new(
        Some("Alice"),
        &["alice@example.org"],
        None,
        false,
        false,
        None,
    )?;
    ca.user_new(
        Some("Bob"),
        &["bob@example.org", "bob@other.org"],
        None,
        false,
        false,
        None,
    )?;
    ca.user_new(
        Some("Carol"),
        &["carol@other.org"],
        None,
        false,
        false,
        None,
    )?;

    let wkd_dir = home_path + "/wkd/";
    let wkd_path = Path::new(&wkd_dir);

    ca.export_wkd("example.org", wkd_path)?;

    // expect 3 exported keys (carol should not be in the export)
    let test_path = wkd_path.join(".well-known/openpgpkey/example.org/hu/");
    let paths = fs::read_dir(test_path)?;
    assert_eq!(paths.count(), 3);

    // check that both user keys have been written to files
    let test_path = wkd_path.join(
        ".well-known/openpgpkey/example.org\
         /hu/jycbiujnsxs47xrkethgtj69xuunurok",
    );
    assert!(test_path.is_file());

    let test_path = wkd_path.join(
        ".well-known/openpgpkey/example.org\
         /hu/kei1q4tipxxu1yj79k9kfukdhfy631xe",
    );
    assert!(test_path.is_file());

    // check that CA key has been written to file
    let test_path = wkd_path.join(
        ".well-known/openpgpkey/example.org\
         /hu/ermf4k8pujzwtqqxmskb7355sebj5e4t",
    );
    assert!(test_path.is_file());

    // check that a policy file been created
    let test_path = wkd_path.join(
        ".well-known/openpgpkey/example.org\
         /policy",
    );
    assert!(test_path.is_file());

    Ok(())
}

#[test]
/// Create a CA and two users. "delist" one user.
/// Export to WKD. Check that only the other user has been exported.
#[cfg_attr(not(feature = "softkey"), ignore)]
fn test_wkd_delist() -> Result<()> {
    let gpg = gnupg_test_wrapper::make_context()?;

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let db = format!("{home_path}/ca.sqlite");

    let cau = Uninit::new(Some(&db))?;
    let ca = cau.init_softkey("example.org", None, None)?;

    // make CA users
    ca.user_new(
        Some("Alice"),
        &["alice@example.org"],
        None,
        true,
        false,
        None,
    )?;
    ca.user_new(Some("Bob"), &["bob@example.org"], None, true, false, None)?;

    // set bob to "delisted"
    let cert = ca.certs_by_email("bob@example.org")?;
    assert_eq!(cert.len(), 1);
    let bob = cert[0].clone();
    ca.cert_delist(&bob.fingerprint)?;

    // export to WKD
    let wkd_dir = home_path + "/wkd/";
    let wkd_path = Path::new(&wkd_dir);

    ca.export_wkd("example.org", wkd_path)?;

    // expect 3 exported keys (carol should not be in the export)
    let test_path = wkd_path.join(".well-known/openpgpkey/example.org/hu/");
    let paths = fs::read_dir(test_path)?;
    assert_eq!(paths.count(), 2);

    // check that Alice's and the CA's keys have been written to files

    // Alice
    let test_path = wkd_path.join(
        ".well-known/openpgpkey/example.org\
         /hu/kei1q4tipxxu1yj79k9kfukdhfy631xe",
    );
    assert!(test_path.is_file());

    // check that CA key has been written to file
    let test_path = wkd_path.join(
        ".well-known/openpgpkey/example.org\
         /hu/ermf4k8pujzwtqqxmskb7355sebj5e4t",
    );
    assert!(test_path.is_file());

    // check that a policy file been created
    let test_path = wkd_path.join(
        ".well-known/openpgpkey/example.org\
         /policy",
    );
    assert!(test_path.is_file());

    Ok(())
}

#[test]
#[ignore]
/// Get sequoia-pgp.org keys for Justus and Neal from Hagrid.
/// Import into a fresh CA instance, then export as WKD.
fn test_ca_export_wkd_sequoia() -> Result<()> {
    let gpg = gnupg_test_wrapper::make_context()?;
    //    gpg.leak_tempdir();

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());

    // -- get keys from hagrid

    use tokio::runtime::Runtime;
    let rt = Runtime::new()?;

    let j: Fingerprint = "CBCD8F030588653EEDD7E2659B7DD433F254904A".parse()?;
    let justus: Cert = rt.block_on(async move {
        let mut hagrid = sequoia_net::KeyServer::keys_openpgp_org(sequoia_net::Policy::Encrypted)?;
        hagrid.get(&KeyID::from(j)).await
    })?;
    let justus_key = pgp::cert_to_armored(&justus)?;

    let n: Fingerprint = "8F17777118A33DDA9BA48E62AACB3243630052D9".parse()?;
    let neal: Cert = rt.block_on(async move {
        let mut hagrid = sequoia_net::KeyServer::keys_openpgp_org(sequoia_net::Policy::Encrypted)?;
        hagrid.get(&KeyID::from(n)).await
    })?;
    let neal_key = pgp::cert_to_armored(&neal)?;

    // -- import keys into CA

    let db = format!("{home_path}/ca.sqlite");

    let cau = Uninit::new(Some(&db))?;
    let ca = cau.init_softkey("sequoia-pgp.org", None, None)?;

    ca.cert_import_new(
        justus_key.as_bytes(),
        &[],
        None,
        &["justus@sequoia-pgp.org"],
        None,
    )?;
    ca.cert_import_new(
        neal_key.as_bytes(),
        &[],
        None,
        &["neal@sequoia-pgp.org"],
        None,
    )?;

    // -- export as WKD

    let wkd_dir = home_path + "/wkd/";
    let wkd_path = Path::new(&wkd_dir);

    ca.export_wkd("sequoia-pgp.org", wkd_path)?;

    Ok(())
}
