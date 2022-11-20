// SPDX-FileCopyrightText: 2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

//! Infrastructure for switchable OpenPGP CA Backends.
//!
//! The backend configuration of a CA instanceis persisted in the CA database in `ca.backend`.

use std::fmt::Formatter;

use anyhow::anyhow;

pub(crate) mod card;
pub(crate) mod softkey;

#[derive(PartialEq)]
pub(crate) enum Backend {
    Softkey,
    Card(Card),
}

impl Backend {
    pub(crate) fn from_config(backend: Option<&str>) -> anyhow::Result<Self> {
        if let Some(backend) = backend {
            if let Some((bt, conf)) = backend.split_once(';') {
                match bt {
                    BACKEND_TYPE_CARD => Ok(Backend::Card(Card::from_config(conf)?)),
                    _ => Err(anyhow!("Unsupported backend type: '{}'", bt)),
                }
            } else {
                Err(anyhow!(
                    "Unexpected backend configuration format: '{}'",
                    backend
                ))
            }
        } else {
            Ok(Backend::Softkey)
        }
    }

    pub(crate) fn to_config(&self) -> Option<String> {
        match self {
            Backend::Softkey => None,
            Backend::Card(c) => Some(format!("{};{}", BACKEND_TYPE_CARD, c.to_config())),
        }
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Backend::Softkey => write!(f, "Softkey (private key material in CA database)"),
            Backend::Card(c) => write!(f, "OpenPGP card {}", c),
        }
    }
}

const BACKEND_TYPE_CARD: &str = "card";

#[derive(PartialEq)]
pub(crate) struct Card {
    pub(crate) ident: String,
    pub(crate) user_pin: String,
}

impl Card {
    pub(crate) fn from_config(conf: &str) -> anyhow::Result<Self> {
        let c: Vec<_> = conf.split(';').collect();
        if c.len() != 2 {
            return Err(anyhow::anyhow!(
                "Unexpected DB config setting for card backend: '{}'.",
                conf
            ));
        }

        let ident = c[0].to_string();
        let user_pin = c[1].to_string();

        Ok(Card { ident, user_pin })
    }

    pub(crate) fn to_config(&self) -> String {
        format!("{};{}", self.ident, self.user_pin)
    }
}

impl std::fmt::Display for Card {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [User PIN {}]", self.ident, self.user_pin)
    }
}

/// Backend-specific implementation of certification and signing operations
pub trait CertificationBackend {
    /// Make a certification signature.
    ///
    /// `op` should only use the Signer once.
    ///
    /// Some backends (e.g. OpenPGP card) may not allow more than one signing operation in one go.
    /// (cards can be configured to require presentation of PIN before each signing operation)
    fn certify(
        &self,
        op: &mut dyn FnMut(&mut dyn sequoia_openpgp::crypto::Signer) -> anyhow::Result<()>,
    ) -> anyhow::Result<()>;

    /// Make a regular signature.
    ///
    /// `op` should only use the Signer once.
    ///
    /// Some backends (e.g. OpenPGP card) may not allow more than one signing operation in one go.
    /// (cards can be configured to require presentation of PIN before each signing operation)
    fn sign(
        &self,
        op: &mut dyn FnMut(&mut dyn sequoia_openpgp::crypto::Signer) -> anyhow::Result<()>,
    ) -> anyhow::Result<()>;
}
