// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

//! PGP helper functions.

use std::convert::TryInto;
use std::str::FromStr;
use std::time::SystemTime;

use anyhow::{Context, Result};
use chbs::probability::Probability;
use sequoia_openpgp::armor;
use sequoia_openpgp::cert;
use sequoia_openpgp::cert::amalgamation::key::ValidKeyAmalgamation;
use sequoia_openpgp::cert::amalgamation::{ValidAmalgamation, ValidateAmalgamation};
use sequoia_openpgp::cert::prelude::ComponentAmalgamation;
use sequoia_openpgp::cert::{CertParser, CipherSuite as SeqCipherSuite};
use sequoia_openpgp::crypto::KeyPair;
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::packet::{signature, Signature, UserID};
use sequoia_openpgp::parse::{PacketParser, Parse};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::{Serialize, SerializeInto};
use sequoia_openpgp::types::{KeyFlags, RevocationStatus, SignatureType};
use sequoia_openpgp::{Cert, Fingerprint, KeyHandle, Packet};
use sha2::Digest;

pub(crate) const CA_KEY_NOTATION: &str = "openpgp-ca@notations.sequoia-pgp.org";

pub(crate) const SECONDS_IN_DAY: u64 = 60 * 60 * 24;

pub(crate) const SP: &StandardPolicy<'static> = &StandardPolicy::new();

// FIXME: configurable dictionaries, ... ?
fn diceware() -> String {
    use chbs::{config::BasicConfig, prelude::*};

    let config = BasicConfig {
        capitalize_first: Probability::Never,
        capitalize_words: Probability::Never,
        ..Default::default()
    };
    config.to_scheme().generate()
}

pub(crate) fn ca_user_id(email: &str, name: Option<&str>) -> UserID {
    let name = match name {
        Some(name) => Some(name),
        None => Some("OpenPGP CA"),
    };

    user_id(email, name)
}

fn user_id(email: &str, name: Option<&str>) -> UserID {
    if let Some(name) = name {
        UserID::from(format!("{name} <{email}>"))
    } else {
        UserID::from(format!("<{email}>"))
    }
}

/// notation: "openpgp-ca:domain=domain1;domain2"
pub(crate) fn add_ca_domain_notation(
    sb: SignatureBuilder,
    domain: &str,
) -> Result<SignatureBuilder> {
    sb.add_notation(
        CA_KEY_NOTATION,
        (format!("domain={domain}")).as_bytes(),
        signature::subpacket::NotationDataFlags::empty().set_human_readable(),
        false,
    )
}

/// Generate a new CA key (and a revocation).
///
/// `domain` is the domainname for the CA (such as `example.org`).
/// A UserID for the CA is generated with the localpart `openpgp-ca`
/// (so for example `openpgp-ca@example.org`).
///
/// `name` is an optional additional identifier that is added to the
/// UserID, if it is supplied.
pub(crate) fn make_ca_cert(
    domain: &str,
    name: Option<&str>,
    cipher_suite: Option<CipherSuite>,
) -> Result<(Cert, Signature)> {
    // Generate key for a new CA
    let (mut ca_key, revocation) = cert::CertBuilder::new()
        // RHEL7 [eol 2026] is shipped with GnuPG 2.0.x, which doesn't
        // support ECC
        .set_cipher_suite(cipher_suite.unwrap_or(CipherSuite::RSA4k).into())
        .add_signing_subkey()
        // FIXME: set expiration from CLI
        // .set_validity_period()
        .generate()?;

    // Get keypair for the CA primary key, as a Signer
    let mut keypair = ca_key
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()?
        .into_keypair()?;

    // Get a copy of the current DKS
    let dks = ca_key
        .with_policy(SP, None)?
        .direct_key_signature()
        .cloned();

    // Remove DKS from cert
    ca_key = ca_key
        .into_packets()
        .filter(|p| match p {
            Packet::Signature(s) => s.typ() != SignatureType::DirectKey,
            _ => true,
        })
        .collect::<Vec<_>>()
        .try_into()?;

    // Add notation to DKS
    if let Ok(sig) = dks {
        let sb = SignatureBuilder::from(sig);
        let sb = add_ca_domain_notation(sb, domain)?;

        let s = sb
            // Update the direct key signature.
            .sign_direct_key(&mut keypair, None)?;

        let p: Packet = s.into();
        (ca_key, _) = ca_key.insert_packets2(vec![p])?;
    } else {
        return Err(anyhow::anyhow!(
            "Unexpected missing DirectKey Signature in make_ca_cert()"
        ));
    }

    // Generate a userid and a binding signature
    let email = format!("openpgp-ca@{domain}");
    let userid = ca_user_id(&email, name);

    let direct_key_sig = ca_key
        .primary_key()
        .with_policy(SP, None)?
        .binding_signature();

    let builder = signature::SignatureBuilder::from(direct_key_sig.clone())
        .set_type(SignatureType::PositiveCertification)
        .set_key_flags(KeyFlags::empty().set_certification())?;

    let binding = userid.bind(&mut keypair, &ca_key, builder)?;

    // Merge the User ID and binding signature into the Cert.
    let ca = ca_key.insert_packets(vec![Packet::from(userid), binding.into()])?;

    Ok((ca, revocation))
}

/// Make a user Cert (with User IDs for each of `emails`).
///
///
/// The optional additional identifier `name` is added to each User ID,
/// if supplied.
///
/// If `password` is true, the generated private key will be password
/// protected (with a generated diceware password).
pub(crate) fn make_user_cert(
    emails: &[&str],
    name: Option<&str>,
    password: bool,
    cipher_suite: Option<CipherSuite>,
    enable_encryption_subkey: bool,
    enable_signing_subkey: bool,
    enable_authentication_subkey: bool,
) -> Result<(Cert, Signature, Option<String>)> {
    let pass = if password { Some(diceware()) } else { None };

    let mut builder = cert::CertBuilder::new()
        .set_cipher_suite(cipher_suite.unwrap_or(CipherSuite::RSA4k).into());

    if enable_encryption_subkey {
        builder = builder.add_subkey(
            KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption(),
            None,
            None,
        );
    }

    if enable_signing_subkey {
        builder = builder.add_signing_subkey();
    }

    if enable_authentication_subkey {
        builder = builder.add_authentication_subkey();
    }

    if let Some(pass) = &pass {
        builder = builder.set_password(Some(pass.to_owned().into()));
    }

    for email in emails {
        builder = builder.add_userid(user_id(email, name));
    }

    let (cert, revocation) = builder.generate()?;
    Ok((cert, revocation, pass))
}

/// make a "public key" ascii-armored representation of a Cert
pub fn cert_to_armored(cert: &Cert) -> Result<String> {
    let v = cert.armored().to_vec().context("Cert serialize failed")?;

    Ok(String::from_utf8(v)?)
}

/// Get the armored "public keyring" representation of a set of Certs.
///
/// This transformation strips non-exportable signatures, and any components bound merely by
/// non-exportable signatures.
pub fn certs_to_armored(certs: &[Cert]) -> Result<String> {
    let mut writer = armor::Writer::new(Vec::new(), armor::Kind::PublicKey)?;

    for cert in certs {
        cert.export(&mut writer)?;
    }
    let buffer = writer.finalize()?;

    Ok(String::from_utf8_lossy(&buffer).to_string())
}

/// Get "private key" armored representation of a Cert
pub fn cert_to_armored_private_key(cert: &Cert) -> Result<String> {
    let mut buffer = vec![];

    let headers: Vec<_> = cert
        .armor_headers()
        .into_iter()
        .map(|value| ("Comment", value))
        .collect();

    let mut writer = armor::Writer::with_headers(&mut buffer, armor::Kind::SecretKey, headers)?;

    cert.as_tsk().serialize(&mut writer)?;
    writer.finalize()?;

    Ok(String::from_utf8(buffer)?)
}

/// Make a Vec of Cert from an armored key(ring)
pub fn armored_keyring_to_certs<D: AsRef<[u8]> + Send + Sync>(armored: &D) -> Result<Vec<Cert>> {
    let ppr = PacketParser::from_bytes(armored)?;

    let mut res = vec![];
    for cert in CertParser::from(ppr) {
        res.push(cert?);
    }

    Ok(res)
}

/// Returns the first Cert found in 'data'.
pub fn to_cert(data: &[u8]) -> Result<Cert> {
    let cert = Cert::from_bytes(data).context("Cert::from_bytes failed")?;

    Ok(cert)
}

/// Get a Signature object from signature data (optionally armored)
pub fn to_signature(data: &[u8]) -> Result<Signature> {
    let p = Packet::from_bytes(data).context("Input could not be parsed")?;

    if let Packet::Signature(s) = p {
        Ok(s)
    } else {
        Err(anyhow::anyhow!("Couldn't convert to Signature"))
    }
}

/// Make an armored representation of a revocation signature.
///
/// Errors for non-exportable signatures.
///
/// Note:this uses `armor::Kind::PublicKey`, because GnuPG doesn't
/// seem to accept revocations with the `armor::Kind::Signature` kind.
pub fn revoc_to_armored(sig: &Signature, headers: Option<Vec<(String, String)>>) -> Result<String> {
    let mut buf = vec![];
    {
        let rev = Packet::Signature(sig.clone());

        let mut writer = armor::Writer::with_headers(
            &mut buf,
            armor::Kind::PublicKey,
            headers.unwrap_or_default(),
        )?;
        rev.export(&mut writer)?;
        writer.finalize()?;
    }

    Ok(String::from_utf8(buf)?)
}

/// Get expiration time of cert as a SystemTime
pub fn get_expiry(cert: &Cert) -> Result<Option<SystemTime>> {
    let primary = cert.primary_key().with_policy(SP, None)?;
    Ok(primary.key_expiration_time())
}

/// Is cert (possibly) revoked?
pub fn is_possibly_revoked(cert: &Cert) -> bool {
    RevocationStatus::NotAsFarAsWeKnow != cert.revocation_status(SP, None)
}

/// Normalize pretty-printed fingerprint strings (with spaces etc)
/// into a format with no spaces and uppercase characters
pub(crate) fn normalize_fp(fp: &str) -> Result<String> {
    Ok(Fingerprint::from_hex(fp)?.to_hex())
}

pub fn get_revoc_issuer_fp(revoc_cert: &Signature) -> Result<Option<Fingerprint>> {
    let issuers = revoc_cert.get_issuers();
    let sig_fingerprints: Vec<&Fingerprint> = issuers
        .iter()
        .filter_map(|keyhandle| {
            if let KeyHandle::Fingerprint(fp) = keyhandle {
                Some(fp)
            } else {
                None
            }
        })
        .collect();

    match sig_fingerprints.len() {
        0 => Ok(None),
        1 => Ok(Some(sig_fingerprints[0].clone())),
        _ => Err(anyhow::anyhow!(
            "ERROR: expected 0 or 1 issuer fingerprints in revocation"
        )),
    }
}

/// Generate a 64 bit sized hash of a revocation certificate
/// (represented as 16 character hex strings).
///
/// These hashes can be used to refer to specific revocations.
pub(crate) fn revocation_to_hash(data: &[u8]) -> Result<String> {
    let sig = to_signature(data)?;

    let p: Packet = sig.into();
    let bits = p.to_vec()?;

    use sha2::Sha256;

    let mut hasher = Sha256::new();
    hasher.update(bits);
    let hash64 = &hasher.finalize()[0..8];

    let hex = hash64
        .iter()
        .map(|d| format!("{d:02X}"))
        .collect::<Vec<_>>()
        .concat();

    Ok(hex)
}

/// `signer` tsigns the `signee` key.
/// Each User ID of signee gets certified.
pub fn tsign(signee: Cert, signer: &Cert, pass: Option<&str>) -> Result<Cert> {
    let mut cert_keys = get_cert_keys(signer, pass);

    if cert_keys.is_empty() {
        return Err(anyhow::anyhow!(
            "tsign(): signer has no valid, certification capable subkey"
        ));
    }

    let mut sigs: Vec<Signature> = Vec::new();

    // Create a tsig for each UserID
    for ca_uidb in signee.userids() {
        for signer in &mut cert_keys {
            let builder = signature::SignatureBuilder::new(SignatureType::GenericCertification)
                .set_trust_signature(255, 120)?;

            let tsig = ca_uidb.userid().bind(signer, &signee, builder)?;
            sigs.push(tsig);
        }
    }

    let signed = signee.insert_packets(sigs)?;

    Ok(signed)
}

/// Merge new CA tsigs from `import` into `ca_cert`.
/// Return merged Cert as TSK (if available).
pub(crate) fn merge_in_tsigs(ca_cert: Cert, import: Cert) -> Result<Cert> {
    // The imported cert must have the same Fingerprint as the CA cert
    if ca_cert.fingerprint() != import.fingerprint() {
        return Err(anyhow::anyhow!(
            "The imported cert has an unexpected Fingerprint",
        ));
    }

    // Get the third party tsig(s) from the imported cert
    let tsigs = get_trust_sigs(&import)?;

    // add tsig(s) to our "own" version of the CA key
    let mut packets: Vec<Packet> = Vec::new();
    tsigs.iter().for_each(|s| packets.push(s.clone().into()));

    ca_cert
        .insert_packets(packets)
        .context("Merging tsigs into CA Key failed")
}

/// Get all valid, certification capable keys (with secret key material)
pub(crate) fn get_cert_keys(cert: &Cert, password: Option<&str>) -> Vec<KeyPair> {
    let keys = cert
        .keys()
        .with_policy(SP, None)
        .alive()
        .revoked(false)
        .for_certification()
        .secret();

    keys.filter_map(|ka: ValidKeyAmalgamation<_, _, _>| {
        let mut ka = ka.key().clone();

        if let Some(password) = password {
            ka = ka.decrypt_secret(&password.into()).ok()?
        }

        ka.into_keypair().ok()
    })
    .collect()
}

// -------- helper functions

pub fn print_cert_info(data: &[u8]) -> Result<()> {
    let c = to_cert(data)?;
    for uid in c.userids() {
        println!("User ID: {}", uid.userid());
    }
    println!("Fingerprint '{c}'");
    Ok(())
}

/// Does any User ID of this cert use an email address in "domain"?
pub(crate) fn cert_has_uid_in_domain(c: &Cert, domain: &str) -> Result<bool> {
    for uid in c.userids() {
        // is any uid in domain
        let email = uid.email()?;
        if let Some(email) = email {
            let split: Vec<_> = email.split('@').collect();

            if split.len() != 2 {
                return Err(anyhow::anyhow!("unexpected email format"));
            }

            if split[1] == domain {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Get all trust sigs on User IDs in this Cert
pub(crate) fn get_trust_sigs(c: &Cert) -> Result<Vec<Signature>> {
    Ok(get_third_party_sigs(c)?
        .iter()
        .filter(|s| s.trust_signature().is_some())
        .cloned()
        .collect())
}

/// Get all third party sigs on User IDs in this Cert
fn get_third_party_sigs(c: &Cert) -> Result<Vec<Signature>> {
    let mut res = Vec::new();

    for uid in c.userids() {
        let sigs = uid.with_policy(SP, None)?.bundle().certifications();
        sigs.iter().for_each(|s| res.push(s.clone()));
    }

    Ok(res)
}

/// For User ID `uid` (which is a part of `cert`):
/// find all valid certifications that have been made by `certifier`.
pub fn valid_certifications_by(
    uid: &ComponentAmalgamation<UserID>,
    cert: &Cert,
    certifier: Cert,
) -> Vec<Signature> {
    let certifier_keys: Vec<_> = certifier
        .keys()
        .with_policy(SP, None)
        .alive()
        .revoked(false)
        .for_certification()
        .collect();

    let certifier_fp = certifier.fingerprint();

    let pk = cert.primary_key();

    uid.certifications()
        .filter(|&s| {
            // does the signature appear to be issued by `certifier`?
            s.issuer_fingerprints()
                .any(|issuer| issuer == &certifier_fp)
        })
        .filter(|&s| {
            // check if the apparent certification by `certifier` is valid
            certifier_keys
                .iter()
                .any(|signer| s.clone().verify_userid_binding(signer, &pk, uid).is_ok())
        })
        .cloned()
        .collect()
}

#[derive(Clone)]
pub enum CipherSuite {
    Cv25519,
    RSA3k,
    P256,
    P384,
    P521,
    RSA2k,
    RSA4k,
}

impl From<CipherSuite> for SeqCipherSuite {
    fn from(value: CipherSuite) -> Self {
        match value {
            CipherSuite::Cv25519 => SeqCipherSuite::Cv25519,
            CipherSuite::RSA3k => SeqCipherSuite::RSA3k,
            CipherSuite::P256 => SeqCipherSuite::P256,
            CipherSuite::P384 => SeqCipherSuite::P384,
            CipherSuite::P521 => SeqCipherSuite::P521,
            CipherSuite::RSA2k => SeqCipherSuite::RSA2k,
            CipherSuite::RSA4k => SeqCipherSuite::RSA4k,
        }
    }
}

impl FromStr for CipherSuite {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "cv25519" => CipherSuite::Cv25519,
            "rsa3k" => CipherSuite::RSA3k,
            "p256" => CipherSuite::P256,
            "p384" => CipherSuite::P384,
            "p521" => CipherSuite::P521,
            "rsa2k" => CipherSuite::RSA2k,
            "rsa4k" => CipherSuite::RSA4k,
            _ => return Err("Unknown cipher suite"),
        })
    }
}
