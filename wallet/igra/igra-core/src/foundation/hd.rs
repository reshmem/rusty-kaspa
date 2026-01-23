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
        let secret = SecretKey::from_slice(&self.secret_bytes)
            .map_err(|err| ThresholdError::CryptoError { operation: "secret_key_from_slice".to_string(), details: err.to_string() })?;
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
        let xprv = key_data
            .get_xprv(inputs.payment_secret)
            .map_err(|err| ThresholdError::CryptoError { operation: "get_xprv".to_string(), details: err.to_string() })?;
        let derived = match &path {
            Some(path) => xprv.derive_path(path).map_err(|err| ThresholdError::InvalidDerivationPath(err.to_string()))?,
            None => xprv,
        };
        pubkeys.push(derived.private_key().get_public_key());
    }

    for xpub in inputs.xpubs {
        let xpub = ExtendedPublicKey::<PublicKey>::from_str(xpub)
            .map_err(|err| ThresholdError::CryptoError { operation: "parse_xpub".to_string(), details: err.to_string() })?;
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

    let xprv = key_data
        .get_xprv(payment_secret)
        .map_err(|err| ThresholdError::CryptoError { operation: "get_xprv".to_string(), details: err.to_string() })?;
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

/// Create a signing keypair directly from a raw secp256k1 private key.
pub fn derive_keypair_from_raw_key(secret_key: SecretKey) -> Result<SigningKeypair, ThresholdError> {
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    Ok(SigningKeypair { public_key, secret_bytes: secret_key.secret_bytes() })
}

/// Parse and validate a raw secp256k1 private key (32 bytes) and return a signing keypair.
pub fn keypair_from_bytes(secret_bytes: &[u8]) -> Result<SigningKeypair, ThresholdError> {
    if secret_bytes.len() != 32 {
        return Err(ThresholdError::key_operation_failed(
            "parse_secp256k1_secret",
            "raw_private_key",
            format!("expected 32 bytes, got {}", secret_bytes.len()),
        ));
    }
    let secret_key = SecretKey::from_slice(secret_bytes).map_err(|err| {
        ThresholdError::key_operation_failed("parse_secp256k1_secret", "raw_private_key", format!("invalid secp256k1 secret: {}", err))
    })?;
    derive_keypair_from_raw_key(secret_key)
}

pub fn redeem_script_from_pubkeys(pubkeys: &[PublicKey], required_sigs: usize) -> Result<Vec<u8>, ThresholdError> {
    let xonly_keys: Vec<[u8; 32]> = pubkeys
        .iter()
        .map(|key| {
            let (xonly, _) = key.x_only_public_key();
            xonly.serialize()
        })
        .collect();
    multisig_redeem_script(xonly_keys.iter(), required_sigs)
        .map_err(|err| ThresholdError::PsktError { operation: "multisig_redeem_script".to_string(), details: err.to_string() })
}

pub fn derivation_path_from_index(index: u32) -> String {
    format!("m/45'/111111'/0'/0/{}", index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_from_bytes_rejects_wrong_length() {
        let result = keypair_from_bytes(&[1u8; 31]);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("expected 32 bytes"));

        let result = keypair_from_bytes(&[1u8; 33]);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("expected 32 bytes"));
    }

    #[test]
    fn keypair_from_bytes_rejects_invalid_key() {
        let result = keypair_from_bytes(&[0u8; 32]);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().to_lowercase().contains("invalid"));
    }

    #[test]
    fn keypair_from_bytes_matches_secp_pubkey() {
        let secret_bytes = [0x42u8; 32];
        let keypair = keypair_from_bytes(&secret_bytes).expect("valid key");
        assert_eq!(keypair.secret_bytes, secret_bytes);

        let secret_key = SecretKey::from_slice(&secret_bytes).expect("valid secp secret");
        let secp = Secp256k1::new();
        let expected = PublicKey::from_secret_key(&secp, &secret_key);
        assert_eq!(keypair.public_key, expected);
    }
}
