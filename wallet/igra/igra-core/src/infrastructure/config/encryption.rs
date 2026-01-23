use crate::foundation::ThresholdError;
use kaspa_bip32::{Language, Mnemonic};
use kaspa_wallet_core::encryption::{Encryptable, EncryptionKind};
use kaspa_wallet_core::prelude::Secret;
use kaspa_wallet_core::storage::keydata::PrvKeyData;
use log::info;
use zeroize::Zeroize;

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
