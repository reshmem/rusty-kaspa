use crate::foundation::ThresholdError;
use crate::infrastructure::config::types::PsktHdConfig;
use crate::infrastructure::config::HD_WALLET_SECRET_ENV;
use kaspa_bip32::{Language, Mnemonic};
use kaspa_wallet_core::encryption::{Encryptable, EncryptionKind};
use kaspa_wallet_core::prelude::Secret;
use kaspa_wallet_core::storage::keydata::PrvKeyData;
use log::{debug, info, warn};
use zeroize::Zeroize;

pub fn load_wallet_secret() -> Result<Secret, ThresholdError> {
    let value = std::env::var(HD_WALLET_SECRET_ENV).unwrap_or_default();
    if value.trim().is_empty() {
        return Err(ThresholdError::ConfigError(format!("{} is required to manage HD mnemonics", HD_WALLET_SECRET_ENV)));
    }
    debug!("wallet secret loaded from env");
    Ok(Secret::from(value))
}

pub fn encrypt_mnemonics(
    mut mnemonics: Vec<String>,
    payment_secret: Option<&Secret>,
    wallet_secret: &Secret,
) -> Result<Encryptable<Vec<PrvKeyData>>, ThresholdError> {
    info!("encrypting mnemonics mnemonic_count={} has_payment_secret={}", mnemonics.len(), payment_secret.is_some());
    let mut key_data = Vec::with_capacity(mnemonics.len());
    for mut phrase in mnemonics.drain(..) {
        let mnemonic = Mnemonic::new(phrase.trim(), Language::English)
            .map_err(|err| ThresholdError::ConfigError(format!("invalid hd.mnemonics entry: {}", err)))?;
        let prv_key_data = PrvKeyData::try_new_from_mnemonic(mnemonic, payment_secret, EncryptionKind::XChaCha20Poly1305)
            .map_err(|err| ThresholdError::ConfigError(format!("failed to encrypt hd.mnemonics entry: {}", err)))?;
        key_data.push(prv_key_data);
        phrase.zeroize();
    }
    Encryptable::from(key_data)
        .into_encrypted(wallet_secret, EncryptionKind::XChaCha20Poly1305)
        .map_err(|err| ThresholdError::ConfigError(format!("failed to store hd.mnemonics: {}", err)))
}

impl PsktHdConfig {
    pub fn decrypt_mnemonics(&self) -> Result<Vec<PrvKeyData>, ThresholdError> {
        let encrypted = match self.encrypted_mnemonics.as_ref() {
            Some(encrypted) => encrypted,
            None => return Ok(Vec::new()),
        };
        let wallet_secret = load_wallet_secret()?;
        let decrypted = encrypted.decrypt(Some(&wallet_secret)).map_err(|err| {
            warn!("failed to decrypt hd.mnemonics");
            ThresholdError::ConfigError(format!("failed to decrypt hd.mnemonics: {}", err))
        })?;
        Ok(decrypted.as_ref().clone())
    }
}
