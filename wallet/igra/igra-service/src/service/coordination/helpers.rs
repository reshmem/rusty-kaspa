use igra_core::application::pskt_multisig::ordered_pubkeys_from_redeem_script;
use igra_core::foundation::ThresholdError;
use kaspa_consensus_core::config::params::{DEVNET_PARAMS, MAINNET_PARAMS, SIMNET_PARAMS, TESTNET_PARAMS};
use secp256k1::PublicKey;

pub fn derive_ordered_pubkeys(config: &igra_core::infrastructure::config::ServiceConfig) -> Result<Vec<PublicKey>, ThresholdError> {
    if config.pskt.redeem_script_hex.trim().is_empty() {
        return Err(ThresholdError::ConfigError("missing pskt.redeem_script_hex".to_string()));
    }
    let redeem = hex::decode(&config.pskt.redeem_script_hex)?;
    let pubkeys = ordered_pubkeys_from_redeem_script(&redeem)?;
    Ok(pubkeys)
}

pub fn params_for_network_id(network_id: u8) -> &'static kaspa_consensus_core::config::params::Params {
    match network_id {
        0 => &MAINNET_PARAMS,
        2 => &DEVNET_PARAMS,
        3 => &SIMNET_PARAMS,
        _ => &TESTNET_PARAMS,
    }
}
