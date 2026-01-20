use crate::domain::pskt::multisig as pskt_multisig;
use crate::foundation::{EventId, ThresholdError, TxTemplateHash};
use crate::infrastructure::config::{AppConfig, PsktHdConfig, ServiceConfig};
use kaspa_wallet_core::prelude::Secret;
use kaspa_wallet_pskt::prelude::{Signer, PSKT};
use log::{debug, info, warn};

pub type SignPsktResult = (Vec<u8>, Vec<(u32, Vec<u8>)>);

#[derive(Clone, Debug)]
pub struct PsktSigningContext<'a> {
    pub event_id: &'a EventId,
    pub tx_template_hash: &'a TxTemplateHash,
    pub purpose: &'a str,
}

pub fn sign_pskt_with_app_config(
    app_config: &AppConfig,
    pskt: PSKT<Signer>,
    ctx: PsktSigningContext<'_>,
) -> Result<SignPsktResult, ThresholdError> {
    let hd = app_config.service.hd.as_ref().ok_or_else(|| ThresholdError::ConfigError("missing HD config".to_string()))?;
    sign_pskt_with_hd_config(hd, pskt, ctx)
}

pub fn sign_pskt_with_service_config(
    service: &ServiceConfig,
    pskt: PSKT<Signer>,
    ctx: PsktSigningContext<'_>,
) -> Result<SignPsktResult, ThresholdError> {
    let hd = service.hd.as_ref().ok_or_else(|| ThresholdError::ConfigError("missing HD config".to_string()))?;
    sign_pskt_with_hd_config(hd, pskt, ctx)
}

fn sign_pskt_with_hd_config(
    hd: &PsktHdConfig,
    pskt: PSKT<Signer>,
    ctx: PsktSigningContext<'_>,
) -> Result<SignPsktResult, ThresholdError> {
    debug!("pskt_signing: start purpose={} event_id={:#x} tx_template_hash={:#x}", ctx.purpose, ctx.event_id, ctx.tx_template_hash);

    let key_data = match hd.decrypt_mnemonics() {
        Ok(data) => data,
        Err(err) => {
            warn!(
                "pskt_signing: failed to decrypt mnemonics purpose={} event_id={:#x} tx_template_hash={:#x} error={}",
                ctx.purpose, ctx.event_id, ctx.tx_template_hash, err
            );
            return Err(err);
        }
    };
    let signing_key_data = key_data.first().ok_or_else(|| ThresholdError::ConfigError("missing mnemonic".to_string()))?;
    let payment_secret = hd.passphrase.as_deref().map(Secret::from);

    let signing_keypair =
        crate::foundation::hd::derive_keypair_from_key_data(signing_key_data, hd.derivation_path.as_deref(), payment_secret.as_ref())?;
    let keypair = signing_keypair.to_secp256k1()?;

    let signed = pskt_multisig::sign_pskt(pskt, &keypair)?.pskt;
    let canonical_pubkey = pskt_multisig::canonical_schnorr_pubkey_for_keypair(&keypair);
    let pubkey = canonical_pubkey.serialize().to_vec();
    let sigs = pskt_multisig::partial_sigs_for_pubkey(&signed, &canonical_pubkey);

    if sigs.is_empty() {
        return Err(ThresholdError::SigningFailed("no signatures produced".to_string()));
    }

    info!(
        "pskt_signing: produced signatures purpose={} event_id={:#x} tx_template_hash={:#x} input_sig_count={}",
        ctx.purpose,
        ctx.event_id,
        ctx.tx_template_hash,
        sigs.len()
    );

    Ok((pubkey, sigs))
}
