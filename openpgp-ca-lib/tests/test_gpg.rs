// SPDX-FileCopyrightText: 2019-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use std::env;
use std::path::PathBuf;

use anyhow::{Context, Result};
use openpgp_ca_lib::{pgp, Oca};
use sequoia_openpgp::serialize::Serialize;

use crate::gnupg_test_wrapper::Ctx;

mod util;
use util::gnupg_test_wrapper;

#[test]
#[cfg_attr(not(feature = "softkey"), ignore)]
fn alice_authenticates_bob_centralized_soft() -> Result<()> {
    let (gpg, cau) = util::setup_one_uninit()?;

    // make new CA key
    let ca = cau.init_softkey("example.org", None)?;

    test_alice_authenticates_bob_centralized(gpg, ca)
}

#[test]
#[cfg_attr(not(feature = "card"), ignore)]
fn alice_authenticates_bob_centralized_card() -> Result<()> {
    let ident = env::var("IDENT").expect("IDENT is unset in environment");
    util::reset_card(&ident)?;

    let (gpg, cau) = util::setup_one_uninit()?;
    let (ca, _priv) = cau.init_card_generate_on_host(&ident, "example.org", None)?;

    test_alice_authenticates_bob_centralized(gpg, ca)
}

/// Create a new CA. Create user certs for Alice and Bob in OpenPGP CA.
///
/// Export all keys to a gnupg instance, set ownertrust for Alice to
/// "ultimate".
///
/// Check that gnupg considers Bob and the CA admin as "full"ly trusted.
fn test_alice_authenticates_bob_centralized(gpg: Ctx, ca: Oca) -> Result<()> {
    // ---- use OpenPGP CA to make a set of keys ----

    // make CA users
    ca.user_new(Some("Alice"), &["alice@example.org"], None, false, false)?;
    ca.user_new(Some("Bob"), &["bob@example.org"], None, false, false)?;

    // ---- import keys from OpenPGP CA into GnuPG ----

    // get Cert for CA
    let ca_cert = ca.ca_get_cert_pub()?;

    // import CA cert into GnuPG
    let mut buf = Vec::new();
    ca_cert.serialize(&mut buf)?;
    gpg.import(&buf);

    // import CA users into GnuPG
    let certs = ca.user_certs_get_all()?;

    assert_eq!(certs.len(), 2);

    for cert in certs {
        gpg.import(cert.pub_cert.as_bytes());
    }

    // ---- set "ultimate" ownertrust for alice ----
    gpg.edit_trust("alice", 5)?;

    // ---- read calculated "trust" per uid from GnuPG ----
    let gpg_trust = gpg.list_keys()?;

    assert_eq!(gpg_trust.len(), 3);

    assert_eq!(
        gpg_trust.get("Alice <alice@example.org>"),
        Some(&"u".to_string())
    );
    assert_eq!(
        gpg_trust.get("OpenPGP CA <openpgp-ca@example.org>"),
        Some(&"f".to_string())
    );
    assert_eq!(
        gpg_trust.get("Bob <bob@example.org>"),
        Some(&"f".to_string())
    );

    // don't delete home dir (for manual inspection)
    //    gpg.leak_tempdir();

    Ok(())
}

#[test]
#[cfg_attr(not(feature = "softkey"), ignore)]
fn test_alice_authenticates_bob_decentralized_soft() -> Result<()> {
    let (_gpg, cau) = util::setup_one_uninit()?;

    // make new CA key
    let ca = cau.init_softkey("example.org", None)?;

    test_alice_authenticates_bob_decentralized(ca)
}

#[test]
#[cfg_attr(not(feature = "card"), ignore)]
fn test_alice_authenticates_bob_decentralized_card() -> Result<()> {
    let ident = env::var("IDENT").expect("IDENT is unset in environment");
    util::reset_card(&ident)?;

    let (_gpg, cau) = util::setup_one_uninit()?;
    let (ca, _priv) = cau.init_card_generate_on_host(&ident, "example.org", None)?;

    test_alice_authenticates_bob_decentralized(ca)
}

/// A new CA instance is created. The CA Admin's public key is exported (for
/// Alice and Bob).
///
/// Alice and Bob create their own keys locally in two seperate gnupg
/// instances, and tsign the CA Admin Key, respectively.
///
/// Their keys plus the signatures on the CA Admin key get imported into the
/// CA.
///
/// Export Bob and the CA Admin's key from OpenPGP CA and import into
/// Alice's gnupg instance.
///
/// Expect gnupg in Alice's instance to consider both the CA Admin key and
/// Bob and "full"ly trusted.
fn test_alice_authenticates_bob_decentralized(ca: Oca) -> Result<()> {
    let gpg_alice = gnupg_test_wrapper::make_context()?;
    let gpg_bob = gnupg_test_wrapper::make_context()?;

    let ca_key = ca.ca_get_pubkey_armored()?;

    // ---- import CA key from OpenPGP CA into GnuPG instances ----
    gpg_alice.import(ca_key.as_bytes());
    gpg_bob.import(ca_key.as_bytes());

    // get Cert for CA
    let ca_cert = ca.ca_get_cert_pub()?;

    let ca_keyid = format!("{:X}", ca_cert.keyid());

    // create users in their respective GnuPG contexts
    gpg_alice.create_user("Alice <alice@example.org>");
    gpg_bob.create_user("Bob <bob@example.org>");

    // create tsig for ca key in user GnuPG contexts
    gpg_alice
        .tsign(&ca_keyid, 1, 2)
        .expect("tsign alice failed");
    gpg_bob.tsign(&ca_keyid, 1, 2).expect("tsign bob failed");

    // export CA key from both contexts, import to CA
    let alice_ca_key = gpg_alice.export("openpgp-ca@example.org");
    let bob_ca_key = gpg_bob.export("openpgp-ca@example.org");

    ca.ca_import_tsig(alice_ca_key.as_bytes())
        .context("import CA tsig from Alice failed")?;
    ca.ca_import_tsig(bob_ca_key.as_bytes())
        .context("import CA tsig from Bob failed")?;

    // get public keys for alice and bob from their gnupg contexts
    let alice_key = gpg_alice.export("alice@example.org");
    let bob_key = gpg_bob.export("bob@example.org");

    // import public keys for alice and bob into CA
    ca.cert_import_new(
        alice_key.as_bytes(),
        &[],
        Some("Alice"),
        &["alice@example.org"],
        None,
    )
    .context("import Alice to CA failed")?;

    ca.cert_import_new(
        bob_key.as_bytes(),
        &[],
        Some("Bob"),
        &["bob@example.org"],
        None,
    )
    .context("import Bob to CA failed")?;

    // export bob, CA-key from CA
    let ca_key = ca.ca_get_pubkey_armored()?;
    let certs = ca.certs_by_email("bob@example.org")?;
    let bob = certs.first().unwrap();

    // import bob+CA key into alice's GnuPG context
    gpg_alice.import(ca_key.as_bytes());
    gpg_alice.import(bob.pub_cert.as_bytes());

    // ---- set "ultimate" ownertrust for alice ----
    gpg_alice.edit_trust("alice", 5)?;

    // ---- read calculated "trust" per uid from GnuPG ----
    let gpg_trust = gpg_alice.list_keys()?;

    assert_eq!(gpg_trust.len(), 3);

    assert_eq!(
        gpg_trust.get("Alice <alice@example.org>"),
        Some(&"u".to_string())
    );
    assert_eq!(
        gpg_trust.get("OpenPGP CA <openpgp-ca@example.org>"),
        Some(&"f".to_string())
    );
    assert_eq!(
        gpg_trust.get("Bob <bob@example.org>"),
        Some(&"f".to_string())
    );

    Ok(())
}

#[test]
#[cfg_attr(not(feature = "softkey"), ignore)]
fn test_bridge_soft() -> Result<()> {
    let (gpg, ca1u, ca2u) = util::setup_two_uninit()?;

    // make new CA key
    let ca1 = ca1u.init_softkey("some.org", None)?;

    // make new CA key
    let ca2 = ca2u.init_softkey("other.org", None)?;

    test_bridge(gpg, ca1, ca2)
}

#[test]
#[cfg_attr(not(feature = "card"), ignore)]
fn test_bridge_card() -> Result<()> {
    let ident = env::var("IDENT").expect("IDENT is unset in environment");
    util::reset_card(&ident)?;

    let (gpg, ca1u, ca2u) = util::setup_two_uninit()?;

    // CA1 lives on the card
    let (ca1, _priv) = ca1u.init_card_generate_on_host(&ident, "some.org", None)?;

    // CA2 is a softkey instance
    let ca2 = ca2u.init_softkey("other.org", None)?;

    test_bridge(gpg, ca1, ca2)
}

/// Set up two OpenPGP CA instances for the domains "some.org" and "other.org"
///
/// Create users in each CA, set up a bridge between the two OpenPGP CA
/// instances.
///
/// Export all keys from both CA instances and import them into
/// one gnupg instance. Set ownertrust on one of the users to "ultimate".
///
/// Check that trust of all other keys is "full".
///
/// Except for the user Carol whose userid is in an external domain.
/// Users of CA2 trust Carol, because CA2 signed Carol's key.
/// However, users of CA1 will not, because their trust of keys that CA2
/// signed is scoped to the main domain of CA2's organization.
fn test_bridge(gpg: Ctx, ca1: Oca, ca2: Oca) -> Result<()> {
    // ---- populate first OpenPGP CA instance ----

    // make CA user
    assert!(ca1
        .user_new(Some("Alice"), &["alice@some.org"], None, false, false)
        .is_ok());

    // ---- populate second OpenPGP CA instance ----

    // make CA user
    ca2.user_new(Some("Bob"), &["bob@other.org"], None, false, false)?;

    // make CA user that is out of the domain scope for ca2
    ca2.user_new(Some("Carol"), &["carol@third.org"], None, false, false)?;

    // ---- setup bridges: scoped trust between one.org and two.org ---
    let home_path = String::from(gpg.get_homedir().to_str().unwrap());

    let ca_some_file = format!("{home_path}/ca1.pubkey");
    let ca_other_file = format!("{home_path}/ca2.pubkey");

    let pub_ca1 = ca1.ca_get_pubkey_armored()?;
    let pub_ca2 = ca2.ca_get_pubkey_armored()?;

    std::fs::write(&ca_some_file, pub_ca1).expect("Unable to write file");
    std::fs::write(&ca_other_file, pub_ca2).expect("Unable to write file");

    ca1.add_bridge(None, &PathBuf::from(ca_other_file), None, false)?;
    ca2.add_bridge(None, &PathBuf::from(ca_some_file), None, false)?;

    // ---- import all keys from OpenPGP CA into one GnuPG instance ----

    // get Cert for ca1 from ca2 bridge
    // (this has the signed version of the ca1 pubkey)

    let bridges2 = ca2.bridges_get()?;
    assert_eq!(bridges2.len(), 1);

    let ca1_cert = ca2.bridge_get_cert(&bridges2[0])?.pub_cert;

    // get Cert for ca2 from ca1 bridge
    // (this has the signed version of the ca2 pubkey)
    let bridges1 = ca1.bridges_get()?;
    assert_eq!(bridges1.len(), 1);

    let ca2_cert = ca1.bridge_get_cert(&bridges1[0])?.pub_cert;

    // import CA keys into GnuPG
    gpg.import(ca1_cert.as_bytes());
    gpg.import(ca2_cert.as_bytes());

    // import CA1 users into GnuPG
    let certs1 = ca1.user_certs_get_all()?;

    assert_eq!(certs1.len(), 1);

    for cert in certs1 {
        gpg.import(cert.pub_cert.as_bytes());
    }

    // import CA2 users into GnuPG
    let certs2 = ca2.user_certs_get_all()?;

    assert_eq!(certs2.len(), 2);

    for cert in certs2 {
        gpg.import(cert.pub_cert.as_bytes());
    }

    // ---- set "ultimate" ownertrust for alice ----
    gpg.edit_trust("alice", 5)?;

    // ---- read calculated "trust" per uid from GnuPG ----
    let gpg_trust = gpg.list_keys()?;

    assert_eq!(gpg_trust.len(), 5);

    assert_eq!(
        gpg_trust.get("Alice <alice@some.org>"),
        Some(&"u".to_string()),
        "alice@some.org"
    );
    assert_eq!(
        gpg_trust.get("OpenPGP CA <openpgp-ca@some.org>"),
        Some(&"f".to_string()),
        "openpgp-ca@some.org"
    );
    assert_eq!(
        gpg_trust.get("OpenPGP CA <openpgp-ca@other.org>"),
        Some(&"f".to_string()),
        "openpgp-ca@other.org"
    );
    assert_eq!(
        gpg_trust.get("Bob <bob@other.org>"),
        Some(&"f".to_string()),
        "bob@other.org"
    );
    assert_eq!(
        gpg_trust.get("Carol <carol@third.org>"),
        Some(&"-".to_string()),
        "carol@third.org"
    );

    Ok(())
}

#[test]
#[cfg_attr(not(feature = "softkey"), ignore)]
fn test_multi_bridge_soft() -> Result<()> {
    let (gpg, ca1u, ca2u, ca3u) = util::setup_three_uninit()?;

    // make new CA keys
    let ca1 = ca1u.init_softkey("alpha.org", None)?;
    let ca2 = ca2u.init_softkey("beta.org", None)?;
    let ca3 = ca3u.init_softkey("gamma.org", None)?;

    test_multi_bridge(gpg, ca1, ca2, ca3)
}

#[test]
#[cfg_attr(not(feature = "card"), ignore)]
fn test_multi_bridge_card() -> Result<()> {
    let ident = env::var("IDENT").expect("IDENT is unset in environment");
    util::reset_card(&ident)?;

    let (gpg, ca1u, ca2u, ca3u) = util::setup_three_uninit()?;

    // CA3 is card-backed, CA1 and CA2 are softkey instances
    let ca1 = ca1u.init_softkey("alpha.org", None)?;
    let ca2 = ca2u.init_softkey("beta.org", None)?;
    let (ca3, _priv) = ca3u.init_card_generate_on_host(&ident, "gamma.org", None)?;

    test_multi_bridge(gpg, ca1, ca2, ca3)
}

/// Set up three CA instances, with scoped trust between a+b, and b+c:
///
/// alice@alpha.org ---tsign---> openpgp-ca@alpha.org
///   ---tsign[scope=beta.org]---> openpgp-ca@beta.org
///     ---tsign[scope=gamma.org]---> openpgp-ca@gamma.org
///           ---sign--> carol@gamma.org
///
/// expected outcome: alice has "full" trust for openpgp-ca@alpha.org and openpgp-ca@beta.org,
/// but no trust for openpgp-ca@gamma.org and carol@gamma.org
fn test_multi_bridge(gpg: Ctx, ca1: Oca, ca2: Oca, ca3: Oca) -> Result<()> {
    // don't delete home dir (for manual inspection)
    // gpg.leak_tempdir();

    // ---- populate OpenPGP CA instances ----
    ca1.user_new(Some("Alice"), &["alice@alpha.org"], None, false, false)?;

    ca3.user_new(Some("Carol"), &["carol@gamma.org"], None, false, false)?;
    ca3.user_new(Some("Bob"), &["bob@beta.org"], None, false, false)?;

    // ---- set up bridges: scoped trust between alpha<->beta and beta<->gamma ---
    let home_path = String::from(gpg.get_homedir().to_str().unwrap());

    let ca2_file = format!("{home_path}/ca2.pubkey");
    let ca3_file = format!("{home_path}/ca3.pubkey");

    let pub_ca2 = ca2.ca_get_pubkey_armored()?;
    let pub_ca3 = ca3.ca_get_pubkey_armored()?;

    std::fs::write(&ca2_file, pub_ca2).expect("Unable to write file");
    std::fs::write(&ca3_file, pub_ca3).expect("Unable to write file");

    // ca1 certifies ca2
    ca1.add_bridge(None, &PathBuf::from(&ca2_file), None, false)?;

    // ca2 certifies ca3
    ca2.add_bridge(None, &PathBuf::from(&ca3_file), None, false)?;

    // ---- import all keys from OpenPGP CA into one GnuPG instance ----

    // get Cert for ca1
    let ca1_cert = ca1.ca_get_pubkey_armored()?;

    // get Cert for ca2 from ca1 bridge
    // (this has the signed version of the ca2 pubkey)
    let bridges1 = ca1.bridges_get()?;
    assert_eq!(bridges1.len(), 1);
    let ca2_cert = ca1.bridge_get_cert(&bridges1[0])?.pub_cert;

    // get Cert for ca3 from ca2 bridge
    // (this has the tsig from ca3)
    let bridges2 = ca2.bridges_get()?;
    assert_eq!(bridges2.len(), 1);
    let ca3_cert = ca2.bridge_get_cert(&bridges2[0])?.pub_cert;

    // import CA certs into GnuPG
    gpg.import(ca1_cert.as_bytes());
    gpg.import(ca2_cert.as_bytes());
    gpg.import(ca3_cert.as_bytes());

    // import CA1 users into GnuPG
    let certs1 = ca1.user_certs_get_all()?;
    assert_eq!(certs1.len(), 1);
    certs1
        .iter()
        .for_each(|c| gpg.import(c.pub_cert.as_bytes()));

    // import CA3 users into GnuPG
    let certs3 = ca3.user_certs_get_all()?;
    assert_eq!(certs3.len(), 2);
    certs3
        .iter()
        .for_each(|c| gpg.import(c.pub_cert.as_bytes()));

    // ---- set "ultimate" ownertrust for alice ----
    gpg.edit_trust("alice", 5)?;

    // ---- read calculated "trust" per uid from GnuPG ----
    let gpg_trust = gpg.list_keys()?;

    assert_eq!(gpg_trust.len(), 6);

    assert_eq!(
        gpg_trust.get("Alice <alice@alpha.org>"),
        Some(&"u".to_string()),
        "alice@alpha.org"
    );
    assert_eq!(
        gpg_trust.get("OpenPGP CA <openpgp-ca@alpha.org>"),
        Some(&"f".to_string()),
        "openpgp-ca@alpha.org"
    );
    assert_eq!(
        gpg_trust.get("OpenPGP CA <openpgp-ca@beta.org>"),
        Some(&"f".to_string()),
        "openpgp-ca@beta.org"
    );
    assert_eq!(
        gpg_trust.get("OpenPGP CA <openpgp-ca@gamma.org>"),
        Some(&"-".to_string()),
        "openpgp-ca@gamma.org"
    );
    assert_eq!(
        gpg_trust.get("Carol <carol@gamma.org>"),
        Some(&"-".to_string()),
        "carol@gamma.org"
    );
    assert_eq!(
        gpg_trust.get("Bob <bob@beta.org>"),
        Some(&"-".to_string()),
        "bob@beta.org"
    );

    Ok(())
}

#[test]
#[cfg_attr(not(feature = "softkey"), ignore)]
fn test_scoping_soft() -> Result<()> {
    let (gpg, ca1u, ca2u, ca3u) = util::setup_three_uninit()?;

    // make new CA keys
    let ca1 = ca1u.init_softkey("alpha.org", None)?;
    let ca2 = ca2u.init_softkey("beta.org", None)?;
    let ca3 = ca3u.init_softkey("other.org", None)?;

    test_scoping(gpg, ca1, ca2, ca3)
}

#[test]
#[cfg_attr(not(feature = "card"), ignore)]
fn test_scoping_card() -> Result<()> {
    let ident = env::var("IDENT").expect("IDENT is unset in environment");
    util::reset_card(&ident)?;

    let (gpg, ca1u, ca2u, ca3u) = util::setup_three_uninit()?;

    // CA3 is card-backed, CA1 and CA2 are softkey instances
    let ca1 = ca1u.init_softkey("alpha.org", None)?;
    let ca2 = ca2u.init_softkey("beta.org", None)?;
    let (ca3, _priv) = ca3u.init_card_generate_on_host(&ident, "other.org", None)?;

    test_scoping(gpg, ca1, ca2, ca3)
}

/// alice@alpha.org ---tsign---> openpgp-ca@alpha.org
///   ---tsign[scope=beta.org]---> openpgp-ca@beta.org
///     ---tsign---> openpgp-ca@other.org
///       ---sign--> bob@beta.org
fn test_scoping(gpg: Ctx, ca1: Oca, ca2: Oca, ca3: Oca) -> Result<()> {
    // don't delete home dir (for manual inspection)
    // gpg.leak_tempdir();

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());

    // ---- populate OpenPGP CA instances ----
    ca1.user_new(Some("Alice"), &["alice@alpha.org"], None, false, false)?;

    ca3.user_new(Some("Bob"), &["bob@beta.org"], None, false, false)?;
    let ca3_file = format!("{home_path}/ca3.pubkey");
    let pub_ca3 = ca3.ca_get_pubkey_armored()?;
    std::fs::write(&ca3_file, pub_ca3).expect("Unable to write file");

    // ---- set up bridges: scoped trust between alpha<->beta and beta<->gamma ---
    let ca2_file = format!("{home_path}/ca2.pubkey");
    let pub_ca2 = ca2.ca_get_pubkey_armored()?;
    std::fs::write(&ca2_file, pub_ca2).expect("Unable to write file");

    // ca1 certifies ca2
    ca1.add_bridge(None, &PathBuf::from(&ca2_file), None, false)?;

    // create unscoped trust signature from ca2 (beta.org) to ca3 (other.org)
    // ---- openpgp-ca@beta.org ---tsign---> openpgp-ca@other.org ----
    // let tsigned_ca3 = pgp::tsign(ca3.ca_get_priv_key()?, &ca2.ca_get_priv_key()?, None)?;
    ca2.add_bridge(None, &PathBuf::from(&ca3_file), None, true)?;
    let bridges2 = ca2.bridges_get()?;
    assert_eq!(bridges2.len(), 1);
    let tsigned_ca3 = ca2.bridge_get_cert(&bridges2[0])?.pub_cert;

    // ---- import all keys from OpenPGP CA into one GnuPG instance ----

    // get Cert for ca1
    let ca1_cert = ca1.ca_get_cert_pub().expect("failed to get CA1 cert");

    // get Cert for ca2 from ca1 bridge
    // (this has the signed version of the ca2 pubkey)
    let bridges1 = ca1.bridges_get()?;
    assert_eq!(bridges1.len(), 1);
    let ca2_cert = ca1.bridge_get_cert(&bridges1[0])?.pub_cert;

    // import CA certs into GnuPG
    gpg.import(pgp::cert_to_armored(&ca1_cert)?.as_bytes());
    gpg.import(ca2_cert.as_bytes());
    gpg.import(tsigned_ca3.as_bytes());

    // import CA1 users into GnuPG
    let certs1 = ca1.user_certs_get_all()?;
    assert_eq!(certs1.len(), 1);
    certs1
        .iter()
        .for_each(|c| gpg.import(c.pub_cert.as_bytes()));

    // import CA3 users into GnuPG
    let certs3 = ca3.user_certs_get_all()?;
    assert_eq!(certs3.len(), 1);
    certs3
        .iter()
        .for_each(|c| gpg.import(c.pub_cert.as_bytes()));

    // ---- set "ultimate" ownertrust for alice ----
    gpg.edit_trust("alice", 5)?;

    // ---- read calculated "trust" per uid from GnuPG ----
    let gpg_trust = gpg.list_keys()?;

    assert_eq!(gpg_trust.len(), 5);

    assert_eq!(
        gpg_trust.get("Alice <alice@alpha.org>"),
        Some(&"u".to_string()),
        "alice@alpha.org"
    );
    assert_eq!(
        gpg_trust.get("OpenPGP CA <openpgp-ca@alpha.org>"),
        Some(&"f".to_string()),
        "openpgp-ca@alpha.org"
    );
    assert_eq!(
        gpg_trust.get("OpenPGP CA <openpgp-ca@beta.org>"),
        Some(&"f".to_string()),
        "openpgp-ca@beta.org"
    );
    assert_eq!(
        gpg_trust.get("OpenPGP CA <openpgp-ca@other.org>"),
        Some(&"-".to_string()),
        "openpgp-ca@other.org"
    );
    assert_eq!(
        gpg_trust.get("Bob <bob@beta.org>"),
        Some(&"-".to_string()),
        "bob@beta.org"
    );

    Ok(())
}
