// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use anyhow::Result;
use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::crypto::Signer;

use crate::backend::CertificationBackend;
use crate::ca::DbCa;
use crate::ca_secret::CaSec;
use crate::db::models;
use crate::pgp::Pgp;

impl DbCa {
    /// Initialize OpenPGP CA Admin database entry.
    /// Takes a `cert` with private key material and initializes a softkey-based CA.
    ///
    /// Only one CA Admin can be configured per database.
    pub fn ca_init_softkey(&self, domainname: &str, cert: &Cert) -> Result<()> {
        if self.db().is_ca_initialized()? {
            return Err(anyhow::anyhow!("CA has already been initialized",));
        }

        let ca_key = Pgp::cert_to_armored_private_key(cert)?;

        self.db().ca_insert(
            models::NewCa {
                domainname,
                backend: None,
            },
            &ca_key,
            &cert.fingerprint().to_hex(),
        )
    }
}

/// Implementation of CaSec based on a DbCa backend that contains the
/// private key material for the CA.
impl CaSec for DbCa {
    fn get_ca_cert(&self) -> Result<Cert> {
        let (_, cacert) = self.db().get_ca()?;

        Pgp::to_cert(cacert.priv_cert.as_bytes())
    }
}

impl CertificationBackend for DbCa {
    fn certify(
        &self,
        op: &mut dyn FnMut(&mut dyn sequoia_openpgp::crypto::Signer) -> Result<()>,
    ) -> Result<()> {
        let ca_cert = self.get_ca_cert()?; // contains private key material for DbCa
        let ca_keys = Pgp::get_cert_keys(&ca_cert, None);

        for mut s in ca_keys {
            op(&mut s as &mut dyn sequoia_openpgp::crypto::Signer)?;
        }

        Ok(())
    }

    fn sign(&self, op: &mut dyn FnMut(&mut dyn Signer) -> Result<()>) -> Result<()> {
        let ca_cert = self.get_ca_cert()?; // contains private key material for DbCa

        // FIXME: this assumes there is exactly one signing capable subkey
        let mut signing_keypair = ca_cert
            .keys()
            .secret()
            .with_policy(Pgp::SP, None)
            .supported()
            .alive()
            .revoked(false)
            .for_signing()
            .next()
            .unwrap()
            .key()
            .clone()
            .into_keypair()?;

        op(&mut signing_keypair as &mut dyn sequoia_openpgp::crypto::Signer)?;

        Ok(())
    }
}