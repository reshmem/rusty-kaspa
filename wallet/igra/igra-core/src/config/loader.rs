use crate::config::encryption::{encrypt_mnemonics, load_wallet_secret};
use crate::config::types::{
    default_ism_mode, AppConfig, HyperlaneConfig, HyperlaneDomainConfig, HyperlaneIsmMode, IrohRuntimeConfig, LayerZeroConfig,
    PsktBuildConfig, PsktHdConfig, PsktOutput, RpcConfig, RuntimeConfig, ServiceConfig, SigningConfig,
};
use crate::error::ThresholdError;
use crate::model::{GroupConfig, GroupMetadata, GroupPolicy};
use configparser::ini::Ini;
use kaspa_wallet_core::prelude::Secret;
use std::fs;
use std::path::Path;

const DEFAULT_NODE_RPC_URL: &str = "grpc://127.0.0.1:16110";
const DEFAULT_RPC_ADDR: &str = "127.0.0.1:8088";
const DEFAULT_POLL_SECS: u64 = 5;
const DEFAULT_SIG_OP_COUNT: u8 = 2;
const DEFAULT_SESSION_TIMEOUT_SECS: u64 = 60;

pub fn load_from_ini(path: &Path, data_dir: &Path) -> Result<AppConfig, ThresholdError> {
    let mut ini = Ini::new();
    ini.load(path.to_string_lossy().as_ref())
        .map_err(|err| ThresholdError::Message(format!("failed to load config from {}: {}", path.display(), err)))?;

    let mut config = default_app_config(data_dir);
    let view = IniView::new(&ini, None);
    apply_ini(&mut config, &view)?;

    apply_defaults(&mut config, data_dir);
    Ok(config)
}

pub fn load_from_ini_profile(path: &Path, data_dir: &Path, profile: &str) -> Result<AppConfig, ThresholdError> {
    let mut ini = Ini::new();
    ini.load(path.to_string_lossy().as_ref())
        .map_err(|err| ThresholdError::Message(format!("failed to load config from {}: {}", path.display(), err)))?;

    let mut config = default_app_config(data_dir);
    let view = IniView::new(&ini, Some(profile));
    apply_ini(&mut config, &view)?;

    apply_defaults(&mut config, data_dir);
    Ok(config)
}

pub fn load_from_toml(path: &Path, data_dir: &Path) -> Result<AppConfig, ThresholdError> {
    let contents = fs::read_to_string(path)
        .map_err(|err| ThresholdError::Message(format!("failed to read config {}: {}", path.display(), err)))?;
    let mut config: AppConfig = toml::from_str(&contents)
        .map_err(|err| ThresholdError::Message(format!("failed to parse TOML {}: {}", path.display(), err)))?;
    apply_defaults(&mut config, data_dir);
    Ok(config)
}

/// Returns default configuration seeded with data_dir.
pub fn load_default(data_dir: &Path) -> Result<AppConfig, ThresholdError> {
    Ok(default_app_config(data_dir))
}

fn apply_defaults(config: &mut AppConfig, data_dir: &Path) {
    if config.service.data_dir.trim().is_empty() {
        config.service.data_dir = data_dir.to_string_lossy().to_string();
    }
    if config.service.node_rpc_url.trim().is_empty() {
        config.service.node_rpc_url = DEFAULT_NODE_RPC_URL.to_string();
    }
    if config.service.pskt.node_rpc_url.trim().is_empty() {
        config.service.pskt.node_rpc_url = config.service.node_rpc_url.clone();
    }
    if config.service.pskt.sig_op_count == 0 {
        config.service.pskt.sig_op_count = DEFAULT_SIG_OP_COUNT;
    }
    if config.rpc.addr.trim().is_empty() {
        config.rpc.addr = DEFAULT_RPC_ADDR.to_string();
    }
    if config.hyperlane.poll_secs == 0 {
        config.hyperlane.poll_secs = DEFAULT_POLL_SECS;
    }
    if config.runtime.session_timeout_seconds == 0 {
        config.runtime.session_timeout_seconds = DEFAULT_SESSION_TIMEOUT_SECS;
    }
}

fn default_app_config(data_dir: &Path) -> AppConfig {
    AppConfig {
        service: ServiceConfig {
            node_rpc_url: DEFAULT_NODE_RPC_URL.to_string(),
            data_dir: data_dir.to_string_lossy().to_string(),
            pskt: PsktBuildConfig {
                node_rpc_url: DEFAULT_NODE_RPC_URL.to_string(),
                source_addresses: Vec::new(),
                redeem_script_hex: String::new(),
                sig_op_count: DEFAULT_SIG_OP_COUNT,
                outputs: Vec::new(),
                fee_payment_mode: crate::model::FeePaymentMode::RecipientPays,
                fee_sompi: None,
                change_address: None,
            },
            hd: None,
        },
        runtime: RuntimeConfig {
            test_mode: false,
            test_recipient: None,
            test_amount_sompi: None,
            hd_test_derivation_path: None,
            session_timeout_seconds: DEFAULT_SESSION_TIMEOUT_SECS,
        },
        rpc: RpcConfig { addr: DEFAULT_RPC_ADDR.to_string(), token: None, enabled: true },
        policy: GroupPolicy::default(),
        group: None,
        signing: SigningConfig { backend: "threshold".to_string() },
        hyperlane: HyperlaneConfig {
            validators: Vec::new(),
            threshold: None,
            events_dir: None,
            poll_secs: DEFAULT_POLL_SECS,
            domains: Vec::new(),
        },
        layerzero: LayerZeroConfig { endpoint_pubkeys: Vec::new() },
        iroh: IrohRuntimeConfig {
            peer_id: None,
            signer_seed_hex: None,
            verifier_keys: Vec::new(),
            group_id: None,
            network_id: 0,
            bootstrap: Vec::new(),
            bootstrap_addrs: Vec::new(),
            bind_port: None,
        },
    }
}

fn apply_ini(config: &mut AppConfig, ini: &IniView<'_>) -> Result<(), ThresholdError> {
    apply_service_section(config, ini);
    apply_pskt_section(config, ini)?;
    apply_hd_section(config, ini)?;
    apply_runtime_section(config, ini);
    apply_signing_section(config, ini);
    apply_rpc_section(config, ini);
    apply_policy_section(config, ini)?;
    apply_group_section(config, ini)?;
    apply_hyperlane_section(config, ini)?;
    apply_layerzero_section(config, ini);
    apply_iroh_section(config, ini)?;
    Ok(())
}

fn apply_service_section(config: &mut AppConfig, ini: &IniView<'_>) {
    if let Some(value) = ini_value(ini, "service", "node_rpc_url") {
        config.service.node_rpc_url = value;
    }
    if let Some(value) = ini_value(ini, "service", "data_dir") {
        config.service.data_dir = value;
    }
}

fn apply_pskt_section(config: &mut AppConfig, ini: &IniView<'_>) -> Result<(), ThresholdError> {
    if let Some(value) = ini_value(ini, "pskt", "node_rpc_url") {
        config.service.pskt.node_rpc_url = value;
    }
    if let Some(value) = ini_value(ini, "pskt", "multisig_address") {
        config.service.pskt.source_addresses = vec![value];
    }
    if let Some(value) = ini_value(ini, "pskt", "source_addresses") {
        config.service.pskt.source_addresses = split_csv(&value);
    }
    if let Some(value) = ini_value(ini, "pskt", "redeem_script_hex") {
        config.service.pskt.redeem_script_hex = value;
    }
    if let Some(value) = ini_value(ini, "pskt", "sig_op_count") {
        config.service.pskt.sig_op_count =
            value.trim().parse::<u8>().map_err(|_| ThresholdError::Message("invalid pskt.sig_op_count".to_string()))?;
    }
    if let Some(value) = ini_value(ini, "pskt", "outputs") {
        config.service.pskt.outputs = parse_outputs(&value)?;
    }
    if let Some(value) = ini_value(ini, "pskt", "fee_sompi") {
        config.service.pskt.fee_sompi = value.trim().parse::<u64>().ok();
    }
    if let Some(value) = ini_value(ini, "pskt", "change_address") {
        config.service.pskt.change_address = non_empty(&value);
    }
    if let Some(value) = ini_value(ini, "pskt", "fee_payment_mode") {
        config.service.pskt.fee_payment_mode = parse_fee_payment_mode(&value)?;
    }
    Ok(())
}

fn apply_hd_section(config: &mut AppConfig, ini: &IniView<'_>) -> Result<(), ThresholdError> {
    let mnemonics = ini_value(ini, "hd", "mnemonics").map(|value| split_csv(&value)).unwrap_or_default();
    let xpubs = ini_value(ini, "hd", "xpubs").map(|value| split_csv(&value)).unwrap_or_default();
    let required_sigs = ini_value(ini, "hd", "required_sigs").and_then(|value| value.trim().parse::<usize>().ok()).unwrap_or(0);
    let passphrase = ini_value(ini, "hd", "passphrase").and_then(|value| non_empty(&value));

    if mnemonics.is_empty() && xpubs.is_empty() {
        return Ok(());
    }
    if required_sigs == 0 {
        return Err(ThresholdError::Message("hd.required_sigs must be > 0".to_string()));
    }
    let encrypted_mnemonics = if mnemonics.is_empty() {
        None
    } else {
        let wallet_secret = load_wallet_secret()?;
        let payment_secret = passphrase.as_deref().map(Secret::from);
        Some(encrypt_mnemonics(mnemonics, payment_secret.as_ref(), &wallet_secret)?)
    };
    config.service.hd = Some(PsktHdConfig { encrypted_mnemonics, xpubs, required_sigs, passphrase });
    Ok(())
}

fn apply_runtime_section(config: &mut AppConfig, ini: &IniView<'_>) {
    if let Some(value) = ini_value(ini, "runtime", "test_mode") {
        config.runtime.test_mode = parse_bool(&value);
    }
    if let Some(value) = ini_value(ini, "runtime", "test_recipient") {
        config.runtime.test_recipient = non_empty(&value);
    }
    if let Some(value) = ini_value(ini, "runtime", "test_amount_sompi") {
        config.runtime.test_amount_sompi = value.trim().parse::<u64>().ok();
    }
    if let Some(value) = ini_value(ini, "runtime", "hd_test_derivation_path") {
        config.runtime.hd_test_derivation_path = non_empty(&value);
    }
    if let Some(value) = ini_value(ini, "runtime", "session_timeout_seconds") {
        config.runtime.session_timeout_seconds = value.trim().parse::<u64>().unwrap_or(0);
    }
}

fn apply_signing_section(config: &mut AppConfig, ini: &IniView<'_>) {
    if let Some(value) = ini_value(ini, "signing", "backend") {
        config.signing.backend = value;
    }
}

fn apply_rpc_section(config: &mut AppConfig, ini: &IniView<'_>) {
    if let Some(value) = ini_value(ini, "rpc", "addr") {
        config.rpc.addr = value;
    }
    if let Some(value) = ini_value(ini, "rpc", "token") {
        config.rpc.token = non_empty(&value);
    }
    if let Some(value) = ini_value(ini, "rpc", "enabled") {
        config.rpc.enabled = parse_bool(&value);
    }
}

fn apply_policy_section(config: &mut AppConfig, ini: &IniView<'_>) -> Result<(), ThresholdError> {
    if let Some(value) = ini_value(ini, "policy", "allowed_destinations") {
        config.policy.allowed_destinations = split_csv(&value);
    }
    if let Some(value) = ini_value(ini, "policy", "min_amount_sompi") {
        config.policy.min_amount_sompi = value.trim().parse::<u64>().ok();
    }
    if let Some(value) = ini_value(ini, "policy", "max_amount_sompi") {
        config.policy.max_amount_sompi = value.trim().parse::<u64>().ok();
    }
    if let Some(value) = ini_value(ini, "policy", "max_daily_volume_sompi") {
        config.policy.max_daily_volume_sompi = value.trim().parse::<u64>().ok();
    }
    if let Some(value) = ini_value(ini, "policy", "require_reason") {
        config.policy.require_reason = parse_bool(&value);
    }
    Ok(())
}

fn apply_group_section(config: &mut AppConfig, ini: &IniView<'_>) -> Result<(), ThresholdError> {
    let threshold_m = ini_value(ini, "group", "threshold_m").and_then(|v| v.parse::<u16>().ok());
    let threshold_n = ini_value(ini, "group", "threshold_n").and_then(|v| v.parse::<u16>().ok());
    let member_pubkeys = ini_value(ini, "group", "member_pubkeys").map(|value| split_csv(&value)).unwrap_or_default();

    if threshold_m.is_none() && threshold_n.is_none() && member_pubkeys.is_empty() {
        return Ok(());
    }

    let threshold_m = threshold_m.ok_or_else(|| ThresholdError::Message("group.threshold_m required".to_string()))?;
    let threshold_n = threshold_n.ok_or_else(|| ThresholdError::Message("group.threshold_n required".to_string()))?;
    if member_pubkeys.is_empty() {
        return Err(ThresholdError::Message("group.member_pubkeys required".to_string()));
    }

    let mut pubkeys = Vec::new();
    for hex_key in member_pubkeys {
        let bytes = hex::decode(hex_key.trim())?;
        pubkeys.push(bytes);
    }

    let network_id = ini_value(ini, "group", "network_id").and_then(|v| v.parse::<u8>().ok()).unwrap_or(config.iroh.network_id);

    let fee_rate_sompi_per_gram = ini_value(ini, "group", "fee_rate_sompi_per_gram").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let finality_blue_score_threshold =
        ini_value(ini, "group", "finality_blue_score_threshold").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let dust_threshold_sompi = ini_value(ini, "group", "dust_threshold_sompi").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let min_recipient_amount_sompi =
        ini_value(ini, "group", "min_recipient_amount_sompi").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let session_timeout_seconds = ini_value(ini, "group", "session_timeout_seconds")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(config.runtime.session_timeout_seconds);

    let group_metadata = GroupMetadata {
        creation_timestamp_nanos: ini_value(ini, "group", "creation_timestamp_nanos").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0),
        group_name: ini_value(ini, "group", "group_name").and_then(|v| non_empty(&v)),
        policy_version: ini_value(ini, "group", "policy_version").and_then(|v| v.parse::<u32>().ok()).unwrap_or(1),
        extra: Default::default(),
    };

    config.group = Some(GroupConfig {
        network_id,
        threshold_m,
        threshold_n,
        member_pubkeys: pubkeys,
        fee_rate_sompi_per_gram,
        finality_blue_score_threshold,
        dust_threshold_sompi,
        min_recipient_amount_sompi,
        session_timeout_seconds,
        group_metadata,
        policy: config.policy.clone(),
    });
    Ok(())
}

fn apply_hyperlane_section(config: &mut AppConfig, ini: &IniView<'_>) -> Result<(), ThresholdError> {
    if let Some(value) = ini_value(ini, "hyperlane", "validators") {
        config.hyperlane.validators = split_csv(&value);
    }
    if let Some(value) = ini_value(ini, "hyperlane", "events_dir") {
        config.hyperlane.events_dir = non_empty(&value);
    }
    if let Some(value) = ini_value(ini, "hyperlane", "threshold") {
        config.hyperlane.threshold =
            Some(value.trim().parse::<u8>().map_err(|_| ThresholdError::Message("invalid hyperlane.threshold".to_string()))?);
    }
    if let Some(value) = ini_value(ini, "hyperlane", "poll_secs") {
        config.hyperlane.poll_secs =
            value.trim().parse::<u64>().map_err(|_| ThresholdError::Message("invalid hyperlane.poll_secs".to_string()))?;
    }
    // Per-domain ISM config: sections like [hyperlane.domain.<u32>]
    for (section_name, values) in ini.ini.get_map_ref() {
        if let Some(domain_str) = section_name.strip_prefix("hyperlane.domain.") {
            let domain: u32 =
                domain_str.trim().parse().map_err(|_| ThresholdError::Message(format!("invalid hyperlane domain {domain_str}")))?;
            let mut domain_cfg = HyperlaneDomainConfig { domain, validators: Vec::new(), threshold: 0, mode: default_ism_mode() };
            if let Some(vals) = values.get("validators").and_then(|v| v.as_ref()) {
                domain_cfg.validators = split_csv(vals);
            }
            if let Some(thr) = values.get("threshold").and_then(|v| v.as_ref()) {
                domain_cfg.threshold = thr
                    .trim()
                    .parse::<u8>()
                    .map_err(|_| ThresholdError::Message(format!("invalid hyperlane threshold for domain {domain}")))?;
            }
            if let Some(mode) = values.get("mode").and_then(|v| v.as_ref()) {
                domain_cfg.mode = match mode.trim().to_lowercase().as_str() {
                    "message_id_multisig" | "message-id-multisig" => HyperlaneIsmMode::MessageIdMultisig,
                    "merkle_root_multisig" | "merkle-root-multisig" => HyperlaneIsmMode::MerkleRootMultisig,
                    other => return Err(ThresholdError::Message(format!("invalid hyperlane mode '{other}' for domain {domain}"))),
                };
            }
            config.hyperlane.domains.push(domain_cfg);
        }
    }

    // Backward compatibility: if domains not provided but flat validators exist, create a default domain 0 entry using the legacy threshold.
    if config.hyperlane.domains.is_empty() && !config.hyperlane.validators.is_empty() {
        let legacy_threshold = config.hyperlane.threshold.ok_or_else(|| {
            ThresholdError::ConfigError("hyperlane.threshold is required when using legacy flat validators".to_string())
        })?;
        if legacy_threshold == 0 {
            return Err(ThresholdError::ConfigError("hyperlane.threshold must be > 0".to_string()));
        }
        if legacy_threshold as usize > config.hyperlane.validators.len() {
            return Err(ThresholdError::ConfigError(format!(
                "hyperlane.threshold ({legacy_threshold}) exceeds validator count ({})",
                config.hyperlane.validators.len()
            )));
        }
        config.hyperlane.domains.push(HyperlaneDomainConfig {
            domain: 0,
            validators: config.hyperlane.validators.clone(),
            threshold: legacy_threshold,
            mode: default_ism_mode(),
        });
    }
    Ok(())
}

fn apply_layerzero_section(config: &mut AppConfig, ini: &IniView<'_>) {
    if let Some(value) = ini_value(ini, "layerzero", "endpoint_pubkeys") {
        config.layerzero.endpoint_pubkeys = split_csv(&value);
    }
}

fn apply_iroh_section(config: &mut AppConfig, ini: &IniView<'_>) -> Result<(), ThresholdError> {
    if let Some(value) = ini_value(ini, "iroh", "peer_id") {
        config.iroh.peer_id = non_empty(&value);
    }
    if let Some(value) = ini_value(ini, "iroh", "signer_seed_hex") {
        config.iroh.signer_seed_hex = non_empty(&value);
    }
    if let Some(value) = ini_value(ini, "iroh", "verifier_keys") {
        config.iroh.verifier_keys = split_csv(&value);
    }
    if let Some(value) = ini_value(ini, "iroh", "group_id") {
        config.iroh.group_id = non_empty(&value);
    }
    if let Some(value) = ini_value(ini, "iroh", "network_id") {
        config.iroh.network_id =
            value.trim().parse::<u8>().map_err(|_| ThresholdError::Message("invalid iroh.network_id".to_string()))?;
    }
    if let Some(value) = ini_value(ini, "iroh", "bootstrap") {
        config.iroh.bootstrap = split_csv(&value);
    }
    if let Some(value) = ini_value(ini, "iroh", "bootstrap_addrs") {
        config.iroh.bootstrap_addrs = split_csv(&value);
    }
    if let Some(value) = ini_value(ini, "iroh", "bind_port") {
        config.iroh.bind_port = value.trim().parse::<u16>().ok();
    }
    Ok(())
}

struct IniView<'a> {
    ini: &'a Ini,
    profile: Option<&'a str>,
}

impl<'a> IniView<'a> {
    fn new(ini: &'a Ini, profile: Option<&'a str>) -> Self {
        Self { ini, profile }
    }
}

fn ini_value(ini: &IniView<'_>, section: &str, key: &str) -> Option<String> {
    if let Some(profile) = ini.profile {
        let profiled = format!("{}.{}", profile, section);
        if let Some(value) = ini.ini.get(&profiled, key) {
            let trimmed = value.trim().to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    ini.ini.get(section, key).map(|value| value.trim().to_string()).filter(|v| !v.is_empty())
}

fn split_csv(value: &str) -> Vec<String> {
    value.split(|c| c == ',' || c == '|').filter(|s| !s.trim().is_empty()).map(|s| s.trim().to_string()).collect()
}

fn parse_outputs(value: &str) -> Result<Vec<PsktOutput>, ThresholdError> {
    let mut outputs = Vec::new();
    for entry in value.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.splitn(2, ':');
        let address = parts.next().unwrap_or_default().trim();
        let amount = parts.next().unwrap_or_default().trim();
        if address.is_empty() || amount.is_empty() {
            return Err(ThresholdError::Message("pskt.outputs must be address:amount pairs".to_string()));
        }
        let amount_sompi =
            amount.parse::<u64>().map_err(|_| ThresholdError::Message("pskt.outputs amount must be u64".to_string()))?;
        outputs.push(PsktOutput { address: address.to_string(), amount_sompi });
    }
    Ok(outputs)
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn parse_bool(value: &str) -> bool {
    matches!(value.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

fn parse_fee_payment_mode(value: &str) -> Result<crate::model::FeePaymentMode, ThresholdError> {
    let trimmed = value.trim().to_lowercase();
    if let Some(rest) = trimmed.strip_prefix("split:") {
        let tokens: Vec<&str> = rest.split(':').collect();
        if tokens.len() == 2 {
            let recipient_parts = tokens[0].parse::<u32>().map_err(|_| ThresholdError::Message("invalid split parts".to_string()))?;
            let signer_parts = tokens[1].parse::<u32>().map_err(|_| ThresholdError::Message("invalid split parts".to_string()))?;
            return Ok(crate::model::FeePaymentMode::Split { recipient_parts, signer_parts });
        }
        // backward compatibility: split:<fraction>
        let portion = rest
            .parse::<f64>()
            .map_err(|_| ThresholdError::Message("invalid pskt.fee_payment_mode split".to_string()))?;
        if !(0.0..=1.0).contains(&portion) {
            return Err(ThresholdError::Message("recipient_portion must be 0.0 to 1.0".to_string()));
        }
        let scale: u32 = 1_000;
        let recipient_parts = ((portion * scale as f64).round() as u32).min(scale);
        let signer_parts = scale.saturating_sub(recipient_parts);
        return Ok(crate::model::FeePaymentMode::Split { recipient_parts, signer_parts });
    }
    match trimmed.as_str() {
        "recipient_pays" => Ok(crate::model::FeePaymentMode::RecipientPays),
        "signers_pay" => Ok(crate::model::FeePaymentMode::SignersPay),
        _ => Err(ThresholdError::Message("invalid pskt.fee_payment_mode".to_string())),
    }
}
