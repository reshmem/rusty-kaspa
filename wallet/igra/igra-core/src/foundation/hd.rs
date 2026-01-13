use crate::foundation::ThresholdError;
use kaspa_bip32::{DerivationPath, ExtendedPublicKey, SecretKeyExt};
use kaspa_txscript::standard::multisig_redeem_script;
use kaspa_wallet_core::prelude::Secret;
use kaspa_wallet_core::storage::keydata::PrvKeyData;
use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use std::str::FromStr;
use zeroize::Zeroize;

pub struct HdInputs<'a> {
    pub key_data: &'a [PrvKeyData],
    pub xpubs: &'a [String],
    /// Optional derivation path.
    ///
    /// Default policy: no derivation. `None`, `""`, or `"m"` means "use the root key directly".
    pub derivation_path: Option<&'a str>,
    pub payment_secret: Option<&'a Secret>,
}

#[derive(Clone)]
pub struct SigningKeypair {
    pub public_key: PublicKey,
    secret_bytes: [u8; 32],
}

impl SigningKeypair {
    pub fn from_keypair(keypair: &Keypair) -> Self {
        Self { public_key: keypair.public_key(), secret_bytes: keypair.secret_bytes() }
    }

    pub fn to_secp256k1(&self) -> Result<Keypair, ThresholdError> {
        let secret = SecretKey::from_slice(&self.secret_bytes).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let secp = Secp256k1::new();
        Ok(Keypair::from_secret_key(&secp, &secret))
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }
}

impl Drop for SigningKeypair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for SigningKeypair {
    fn zeroize(&mut self) {
        self.secret_bytes.zeroize();
    }
}

pub fn derive_pubkeys(inputs: HdInputs<'_>) -> Result<Vec<PublicKey>, ThresholdError> {
    let mut pubkeys = Vec::new();
    let path = match inputs.derivation_path.map(str::trim).unwrap_or("") {
        "" | "m" => None,
        p => Some(DerivationPath::from_str(p).map_err(|err| ThresholdError::InvalidDerivationPath(err.to_string()))?),
    };

    for key_data in inputs.key_data {
        let xprv = key_data.get_xprv(inputs.payment_secret).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let derived = match &path {
            Some(path) => xprv.derive_path(path).map_err(|err| ThresholdError::InvalidDerivationPath(err.to_string()))?,
            None => xprv,
        };
        pubkeys.push(derived.private_key().get_public_key());
    }

    for xpub in inputs.xpubs {
        let xpub = ExtendedPublicKey::<PublicKey>::from_str(xpub).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let derived = match &path {
            Some(path) => xpub.derive_path(path).map_err(|err| ThresholdError::InvalidDerivationPath(err.to_string()))?,
            None => xpub,
        };
        pubkeys.push(*derived.public_key());
    }

    Ok(pubkeys)
}

pub fn derive_keypair_from_key_data(
    key_data: &PrvKeyData,
    derivation_path: Option<&str>,
    payment_secret: Option<&Secret>,
) -> Result<SigningKeypair, ThresholdError> {
    let path = match derivation_path.map(str::trim).unwrap_or("") {
        "" | "m" => None,
        p => Some(DerivationPath::from_str(p).map_err(|err| ThresholdError::InvalidDerivationPath(err.to_string()))?),
    };

    let xprv = key_data.get_xprv(payment_secret).map_err(|err| ThresholdError::Message(err.to_string()))?;
    let xprv = match &path {
        Some(path) => xprv.derive_path(path).map_err(|err| ThresholdError::InvalidDerivationPath(err.to_string()))?,
        None => xprv,
    };
    let secret = xprv.private_key();
    let secret_bytes = secret.secret_bytes();
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, secret);
    Ok(SigningKeypair { public_key, secret_bytes })
}

pub fn redeem_script_from_pubkeys(pubkeys: &[PublicKey], required_sigs: usize) -> Result<Vec<u8>, ThresholdError> {
    let xonly_keys: Vec<[u8; 32]> = pubkeys
        .iter()
        .map(|key| {
            let (xonly, _) = key.x_only_public_key();
            xonly.serialize()
        })
        .collect();
    multisig_redeem_script(xonly_keys.iter(), required_sigs).map_err(|err| ThresholdError::Message(err.to_string()))
}

pub fn derivation_path_from_index(index: u32) -> String {
    format!("m/45'/111111'/0'/0/{}", index)
}
