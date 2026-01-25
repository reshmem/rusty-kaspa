use crate::domain::pskt::multisig as pskt_multisig;
use crate::foundation::{EventId, ThresholdError, TxTemplateHash};
use crate::infrastructure::config::{validate_signer_profile, AppConfig, KeyType, PsktHdConfig, ServiceConfig};
use crate::infrastructure::keys::{KeyManagerContext, SecretName};
use kaspa_bip32::{Language, Mnemonic};
use kaspa_wallet_core::encryption::EncryptionKind;
use kaspa_wallet_core::prelude::Secret;
use kaspa_wallet_core::storage::keydata::PrvKeyData;
use kaspa_wallet_pskt::prelude::{Signer, PSKT};
use log::{debug, info, warn};
use std::sync::OnceLock;

pub type SignPsktResult = (Vec<u8>, Vec<(u32, Vec<u8>)>);

pub const SIGNER_MNEMONIC_SECRET_PREFIX: &str = "igra.signer.mnemonic_";
pub const SIGNER_PRIVATE_KEY_SECRET_PREFIX: &str = "igra.signer.private_key_";
pub const SIGNER_PAYMENT_SECRET_PREFIX: &str = "igra.signer.payment_secret_";

/// Recommended minimum length for BIP39 payment secret (optional).
pub const MIN_PAYMENT_SECRET_LENGTH: usize = 12;
pub const RECOMMENDED_PAYMENT_SECRET_LENGTH: usize = 16;

#[derive(Clone, Debug)]
pub struct PsktSigningContext<'a> {
    pub event_id: &'a EventId,
    pub tx_template_hash: &'a TxTemplateHash,
    pub purpose: &'a str,
}

pub async fn sign_pskt_with_app_config(
    app_config: &AppConfig,
    key_context: &KeyManagerContext,
    pskt: PSKT<Signer>,
    ctx: PsktSigningContext<'_>,
) -> Result<SignPsktResult, ThresholdError> {
    let hd = app_config.service.hd.as_ref().ok_or_else(|| ThresholdError::ConfigError("missing HD config".to_string()))?;
    sign_pskt_with_hd_config(&app_config.service, hd, key_context, pskt, ctx).await
}

pub async fn sign_pskt_with_service_config(
    service: &ServiceConfig,
    key_context: &KeyManagerContext,
    pskt: PSKT<Signer>,
    ctx: PsktSigningContext<'_>,
) -> Result<SignPsktResult, ThresholdError> {
    let hd = service.hd.as_ref().ok_or_else(|| ThresholdError::ConfigError("missing HD config".to_string()))?;
    sign_pskt_with_hd_config(service, hd, key_context, pskt, ctx).await
}

async fn sign_pskt_with_hd_config(
    service: &ServiceConfig,
    hd: &PsktHdConfig,
    key_context: &KeyManagerContext,
    pskt: PSKT<Signer>,
    ctx: PsktSigningContext<'_>,
) -> Result<SignPsktResult, ThresholdError> {
    debug!("pskt_signing: start purpose={} event_id={:#x} tx_template_hash={:#x}", ctx.purpose, ctx.event_id, ctx.tx_template_hash);

    let active_profile = active_profile(service)?;

    let signing_keypair = match hd.key_type {
        KeyType::HdMnemonic => {
            let (key_data, payment_secret) =
                load_mnemonic_key_data_and_payment_secret_for_profile(key_context, active_profile).await.map_err(|err| {
                    warn!(
                        "pskt_signing: failed to load mnemonic for signing purpose={} event_id={:#x} tx_template_hash={:#x} error={}",
                        ctx.purpose, ctx.event_id, ctx.tx_template_hash, err
                    );
                    err
                })?;
            crate::foundation::hd::derive_keypair_from_key_data(&key_data, hd.derivation_path.as_deref(), payment_secret.as_ref())?
        }
        KeyType::RawPrivateKey => {
            let secret_name = signer_secret_name(key_context, SIGNER_PRIVATE_KEY_SECRET_PREFIX, active_profile)?;
            let secret_bytes = key_context.get_secret_with_audit(&secret_name).await?;
            crate::foundation::hd::keypair_from_bytes(secret_bytes.expose_secret()).map_err(|err| {
                warn!(
                    "pskt_signing: failed to parse raw private key purpose={} event_id={:#x} tx_template_hash={:#x} secret_name={} error={}",
                    ctx.purpose, ctx.event_id, ctx.tx_template_hash, secret_name, err
                );
                err
            })?
        }
    };
    let keypair = signing_keypair.to_secp256k1()?;

    let signed = pskt_multisig::sign_pskt(pskt, &keypair)?.pskt;
    let canonical_pubkey = pskt_multisig::canonical_schnorr_pubkey_for_keypair(&keypair);
    let pubkey = canonical_pubkey.serialize().to_vec();
    let sigs = pskt_multisig::partial_sigs_for_pubkey(&signed, &canonical_pubkey);

    if sigs.is_empty() {
        return Err(ThresholdError::SigningFailed("no signatures produced".to_string()));
    }

    info!(
        "pskt_signing: produced signatures purpose={} key_type={} event_id={:#x} tx_template_hash={:#x} input_sig_count={}",
        ctx.purpose,
        hd.key_type,
        ctx.event_id,
        ctx.tx_template_hash,
        sigs.len()
    );

    Ok((pubkey, sigs))
}

pub fn active_profile(service: &ServiceConfig) -> Result<&str, ThresholdError> {
    let profile = service
        .active_profile
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ThresholdError::ConfigError("missing service.active_profile".to_string()))?;
    validate_signer_profile(profile)?;
    Ok(profile)
}

fn profile_suffix_for_secret_backend(key_context: &KeyManagerContext, profile: &str) -> Result<String, ThresholdError> {
    let store = key_context
        .key_manager()
        .secret_store()
        .ok_or_else(|| ThresholdError::secret_store_unavailable("none", "KeyManager has no SecretStore"))?;
    if store.backend() == "env" {
        Ok(profile.replace('-', "_"))
    } else {
        Ok(profile.to_string())
    }
}

fn signer_secret_name(key_context: &KeyManagerContext, prefix: &str, profile: &str) -> Result<SecretName, ThresholdError> {
    let suffix = profile_suffix_for_secret_backend(key_context, profile)?;
    Ok(SecretName::new(format!("{prefix}{suffix}")))
}

pub async fn load_mnemonic_phrase_for_profile(key_context: &KeyManagerContext, profile: &str) -> Result<String, ThresholdError> {
    let name = signer_secret_name(key_context, SIGNER_MNEMONIC_SECRET_PREFIX, profile)?;
    let secret_bytes = key_context.get_secret_with_audit(&name).await?;
    let phrase = String::from_utf8(secret_bytes.expose_owned())
        .map_err(|err| ThresholdError::secret_decode_failed(name.to_string(), "utf8", format!("invalid UTF-8: {}", err)))?;
    Ok(phrase)
}

pub async fn load_mnemonic_key_data_for_profile(key_context: &KeyManagerContext, profile: &str) -> Result<PrvKeyData, ThresholdError> {
    let (key_data, _payment_secret) = load_mnemonic_key_data_and_payment_secret_for_profile(key_context, profile).await?;
    Ok(key_data)
}

pub async fn load_mnemonic_key_data_and_payment_secret_for_profile(
    key_context: &KeyManagerContext,
    profile: &str,
) -> Result<(PrvKeyData, Option<Secret>), ThresholdError> {
    let phrase = load_mnemonic_phrase_for_profile(key_context, profile).await?;
    let mnemonic = Mnemonic::new(phrase.trim(), Language::English)
        .map_err(|err| ThresholdError::ConfigError(format!("invalid mnemonic for profile '{profile}': {err}")))?;
    let payment_secret = load_payment_secret_optional_for_profile(key_context, profile).await?;
    let key_data =
        PrvKeyData::try_from_mnemonic(mnemonic, payment_secret.as_ref(), EncryptionKind::XChaCha20Poly1305, None).map_err(|err| {
            ThresholdError::ConfigError(format!("failed to create key data from mnemonic for profile '{profile}': {err}"))
        })?;
    Ok((key_data, payment_secret))
}

pub async fn load_payment_secret_optional_for_profile(
    key_context: &KeyManagerContext,
    profile: &str,
) -> Result<Option<Secret>, ThresholdError> {
    let name = signer_secret_name(key_context, SIGNER_PAYMENT_SECRET_PREFIX, profile)?;
    let secret_bytes = match key_context.get_secret_with_audit(&name).await {
        Ok(bytes) => bytes,
        Err(ThresholdError::SecretNotFound { .. }) => return Ok(None),
        Err(err) => return Err(err),
    };
    if secret_bytes.expose_secret().is_empty() {
        return Ok(None);
    }
    let value = String::from_utf8(secret_bytes.expose_owned())
        .map_err(|err| ThresholdError::secret_decode_failed(name.to_string(), "utf8", format!("invalid UTF-8: {}", err)))?;
    let secret = Secret::from(value);
    if let Some(weakness) = validate_payment_secret_strength(&secret) {
        warn_weak_payment_secret(&weakness);
    }
    Ok(Some(secret))
}

pub fn validate_payment_secret_strength(secret: &Secret) -> Option<String> {
    let secret_bytes: &[u8] = secret.as_ref();
    let length = secret_bytes.len();

    if length == 0 {
        return Some("payment_secret is empty".to_string());
    }

    let secret_str = match std::str::from_utf8(secret_bytes) {
        Ok(s) => s,
        Err(_) => return Some("payment_secret is not valid UTF-8".to_string()),
    };
    let lowercase = secret_str.to_ascii_lowercase();
    const WEAK_PATTERNS: &[&str] = &["password", "123456", "qwerty", "admin", "letmein", "welcome", "monkey", "dragon"];
    for pattern in WEAK_PATTERNS {
        if lowercase.contains(pattern) {
            return Some(format!("payment_secret contains common weak pattern: {}", pattern));
        }
    }

    if length < MIN_PAYMENT_SECRET_LENGTH {
        return Some(format!(
            "payment_secret too short: {} chars (min: {}, recommended: {})",
            length, MIN_PAYMENT_SECRET_LENGTH, RECOMMENDED_PAYMENT_SECRET_LENGTH
        ));
    }

    if length < RECOMMENDED_PAYMENT_SECRET_LENGTH {
        return Some(format!(
            "payment_secret shorter than recommended: {} chars (recommended: {})",
            length, RECOMMENDED_PAYMENT_SECRET_LENGTH
        ));
    }

    None
}

fn warn_weak_payment_secret(weakness: &str) {
    static WARNED: OnceLock<()> = OnceLock::new();
    if WARNED.set(()).is_err() {
        return;
    }

    warn!("SECURITY NOTE: payment_secret is weak: {} (recommended: {}+ chars)", weakness, RECOMMENDED_PAYMENT_SECRET_LENGTH);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::pskt::multisig::{build_pskt, canonical_schnorr_pubkey_for_keypair, MultisigInput, MultisigOutput};
    use crate::infrastructure::keys::{LocalKeyManager, NoopAuditLogger, SecretBytes, SecretName, SecretStore};
    use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionId, TransactionOutpoint, UtxoEntry};
    use kaspa_txscript::standard::{multisig_redeem_script, pay_to_script_hash_script};
    use secp256k1::{Keypair, Secp256k1, SecretKey};
    use std::collections::HashMap;
    use std::sync::Arc;

    struct MapSecretStore {
        secrets: HashMap<SecretName, SecretBytes>,
    }

    impl SecretStore for MapSecretStore {
        fn backend(&self) -> &'static str {
            "map"
        }

        fn get<'a>(
            &'a self,
            name: &'a SecretName,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<SecretBytes, ThresholdError>> + Send + 'a>> {
            Box::pin(
                async move { self.secrets.get(name).cloned().ok_or_else(|| ThresholdError::secret_not_found(name.as_str(), "map")) },
            )
        }

        fn list_secrets<'a>(
            &'a self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<SecretName>, ThresholdError>> + Send + 'a>> {
            Box::pin(async move { Ok(self.secrets.keys().cloned().collect()) })
        }
    }

    fn build_test_pskt(redeem_script: &[u8]) -> PSKT<Signer> {
        let spk = pay_to_script_hash_script(redeem_script);
        let entry = UtxoEntry::new(10_000, spk, 0, false);
        let tx_id = TransactionId::from_slice(&[3u8; 32]);
        let input = MultisigInput {
            utxo_entry: entry,
            previous_outpoint: TransactionOutpoint::new(tx_id, 0),
            redeem_script: redeem_script.to_vec(),
            sig_op_count: 1,
        };
        let outputs = vec![MultisigOutput { amount: 9_000, script_public_key: ScriptPublicKey::from_vec(0, vec![1, 2, 3]) }];
        build_pskt(&[input], &outputs).expect("test setup: build pskt").pskt.signer()
    }

    #[tokio::test]
    async fn test_sign_pskt_with_service_config_when_key_type_raw_private_key_then_produces_sigs() {
        let secret_bytes = [1u8; 32];
        let secret_name = SecretName::new("igra.signer.private_key_signer-01");
        let secret_store =
            Arc::new(MapSecretStore { secrets: HashMap::from([(secret_name, SecretBytes::new(secret_bytes.to_vec()))]) });
        let key_audit_log = Arc::new(NoopAuditLogger);
        let key_manager = Arc::new(LocalKeyManager::new(secret_store, key_audit_log.clone()));

        let secret = SecretKey::from_slice(&secret_bytes).expect("test setup: valid secp256k1 secret key");
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = keypair.public_key().x_only_public_key();
        let redeem_script = multisig_redeem_script([xonly.serialize()].iter(), 1).expect("test setup: redeem script");

        let pskt = build_test_pskt(&redeem_script);
        let tx_template_hash = pskt_multisig::tx_template_hash(&pskt).expect("test setup: tx_template_hash");
        let event_id = EventId::from([9u8; 32]);
        let ctx = PsktSigningContext { event_id: &event_id, tx_template_hash: &tx_template_hash, purpose: "test_raw_key" };

        let key_context = KeyManagerContext::with_new_request_id(key_manager, key_audit_log);

        let service = ServiceConfig {
            active_profile: Some("signer-01".to_string()),
            pskt: crate::infrastructure::config::PsktBuildConfig {
                redeem_script_hex: hex::encode(&redeem_script),
                ..Default::default()
            },
            hd: Some(PsktHdConfig { key_type: KeyType::RawPrivateKey, ..Default::default() }),
            ..Default::default()
        };

        let (pubkey, sigs) = sign_pskt_with_service_config(&service, &key_context, pskt, ctx).await.expect("raw key signing succeeds");

        let expected_pubkey = canonical_schnorr_pubkey_for_keypair(&keypair).serialize().to_vec();
        assert_eq!(pubkey, expected_pubkey);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].0, 0);
        assert_eq!(sigs[0].1.len(), 64);
    }
}
