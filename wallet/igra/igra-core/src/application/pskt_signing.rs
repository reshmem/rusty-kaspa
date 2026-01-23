use crate::domain::pskt::multisig as pskt_multisig;
use crate::foundation::{EventId, ThresholdError, TxTemplateHash};
use crate::infrastructure::config::KeyType;
use crate::infrastructure::config::{AppConfig, PsktHdConfig, ServiceConfig};
use crate::infrastructure::keys::{KeyManagerContext, SecretName};
use kaspa_wallet_core::prelude::Secret;
use kaspa_wallet_core::storage::keydata::PrvKeyData;
use kaspa_wallet_pskt::prelude::{Signer, PSKT};
use log::{debug, info, warn};

pub type SignPsktResult = (Vec<u8>, Vec<(u32, Vec<u8>)>);

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
    sign_pskt_with_hd_config(hd, key_context, pskt, ctx).await
}

pub async fn sign_pskt_with_service_config(
    service: &ServiceConfig,
    key_context: &KeyManagerContext,
    pskt: PSKT<Signer>,
    ctx: PsktSigningContext<'_>,
) -> Result<SignPsktResult, ThresholdError> {
    let hd = service.hd.as_ref().ok_or_else(|| ThresholdError::ConfigError("missing HD config".to_string()))?;
    sign_pskt_with_hd_config(hd, key_context, pskt, ctx).await
}

async fn sign_pskt_with_hd_config(
    hd: &PsktHdConfig,
    key_context: &KeyManagerContext,
    pskt: PSKT<Signer>,
    ctx: PsktSigningContext<'_>,
) -> Result<SignPsktResult, ThresholdError> {
    debug!("pskt_signing: start purpose={} event_id={:#x} tx_template_hash={:#x}", ctx.purpose, ctx.event_id, ctx.tx_template_hash);

    let signing_keypair = match hd.key_type {
        KeyType::HdMnemonic => {
            let wallet_secret = load_wallet_secret(key_context).await?;
            let key_data = decrypt_mnemonics(hd, &wallet_secret).map_err(|err| {
                warn!(
                    "pskt_signing: failed to decrypt mnemonics purpose={} event_id={:#x} tx_template_hash={:#x} error={}",
                    ctx.purpose, ctx.event_id, ctx.tx_template_hash, err
                );
                err
            })?;
            let signing_key_data = key_data.first().ok_or_else(|| ThresholdError::ConfigError("missing mnemonic".to_string()))?;
            let payment_secret = load_payment_secret_optional(key_context).await?;
            crate::foundation::hd::derive_keypair_from_key_data(
                signing_key_data,
                hd.derivation_path.as_deref(),
                payment_secret.as_ref(),
            )?
        }
        KeyType::RawPrivateKey => {
            let profile_suffix = std::env::var("KASPA_IGRA_PROFILE")
                .ok()
                .map(|s| s.trim().replace('-', "_"))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "default".to_string());
            let secret_name = SecretName::new(format!("igra.signer.private_key_{}", profile_suffix));
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

pub fn decrypt_mnemonics(hd: &PsktHdConfig, wallet_secret: &Secret) -> Result<Vec<PrvKeyData>, ThresholdError> {
    let encrypted = match hd.encrypted_mnemonics.as_ref() {
        Some(encrypted) => encrypted,
        None => return Ok(Vec::new()),
    };
    let decrypted = encrypted
        .decrypt(Some(wallet_secret))
        .map_err(|err| ThresholdError::ConfigError(format!("failed to decrypt hd.mnemonics: {}", err)))?;
    Ok(decrypted.as_ref().clone())
}

pub async fn load_wallet_secret(key_context: &KeyManagerContext) -> Result<Secret, ThresholdError> {
    let name = SecretName::new("igra.hd.wallet_secret");
    let secret_bytes = key_context.get_secret_with_audit(&name).await?;
    let value = String::from_utf8(secret_bytes.expose_owned())
        .map_err(|err| ThresholdError::secret_decode_failed(name.to_string(), "utf8", format!("invalid UTF-8: {}", err)))?;
    Ok(Secret::from(value))
}

pub async fn load_payment_secret_optional(key_context: &KeyManagerContext) -> Result<Option<Secret>, ThresholdError> {
    let name = SecretName::new("igra.hd.payment_secret");
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
    Ok(Some(Secret::from(value)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::pskt::multisig::{build_pskt, canonical_schnorr_pubkey_for_keypair, MultisigInput, MultisigOutput};
    use crate::infrastructure::keys::{EnvSecretStore, LocalKeyManager, NoopAuditLogger};
    use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionId, TransactionOutpoint, UtxoEntry};
    use kaspa_txscript::standard::{multisig_redeem_script, pay_to_script_hash_script};
    use secp256k1::{Keypair, Secp256k1, SecretKey};
    use std::env;
    use std::sync::{Arc, Mutex, OnceLock};

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|err| err.into_inner())
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
        let _guard = lock_env();

        let secret_bytes = [1u8; 32];
        let secret_hex = hex::encode(secret_bytes);
        env::set_var("KASPA_IGRA_PROFILE", "signer-1");
        env::set_var("IGRA_SECRET__igra_signer__private_key_signer_1", format!("hex:{secret_hex}"));

        let secret = SecretKey::from_slice(&secret_bytes).expect("test setup: valid secp256k1 secret key");
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = keypair.public_key().x_only_public_key();
        let redeem_script = multisig_redeem_script([xonly.serialize()].iter(), 1).expect("test setup: redeem script");

        let pskt = build_test_pskt(&redeem_script);
        let tx_template_hash = pskt_multisig::tx_template_hash(&pskt).expect("test setup: tx_template_hash");
        let event_id = EventId::from([9u8; 32]);
        let ctx = PsktSigningContext { event_id: &event_id, tx_template_hash: &tx_template_hash, purpose: "test_raw_key" };

        let key_context = KeyManagerContext::with_new_request_id(
            Arc::new(LocalKeyManager::new(Arc::new(EnvSecretStore::new()), Arc::new(NoopAuditLogger))),
            Arc::new(NoopAuditLogger),
        );

        let service = ServiceConfig {
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

        env::remove_var("IGRA_SECRET__igra_signer__private_key_signer_1");
        env::remove_var("KASPA_IGRA_PROFILE");
    }
}
