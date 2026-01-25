#[path = "kaspa-threshold-service/cli.rs"]
mod cli;
#[path = "kaspa-threshold-service/modes/mod.rs"]
mod modes;
#[path = "kaspa-threshold-service/setup.rs"]
mod setup;

use crate::cli::Cli;
use igra_core::application::validation::{parse_validator_pubkeys, CompositeVerifier};
use igra_core::application::EventContext;
use igra_core::application::TwoPhaseConfig;
use igra_core::foundation::ThresholdError;
use igra_core::infrastructure::config::{derive_redeem_script_hex, pskt_source_address_from_redeem_script_hex, AppConfig, PsktOutput};
use igra_core::infrastructure::hyperlane::ConfiguredIsm;
use igra_core::infrastructure::keys::backends::file_format::SecretFile;
use igra_core::infrastructure::network_mode::{NetworkMode, SecurityValidator, ValidationContext};
use igra_core::infrastructure::rpc::KaspaGrpcQueryClient;
use igra_core::infrastructure::storage::phase::PhaseStorage;
use igra_core::infrastructure::storage::Storage;
use igra_service::api::json_rpc::{run_hyperlane_watcher, run_json_rpc_server, RpcState};
use igra_service::service::coordination::run_coordination_loop;
use igra_service::service::flow::ServiceFlow;
use igra_service::service::metrics::Metrics;
use igra_service::transport::iroh::IrohConfig;
use log::{debug, info, warn};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse_args();
    let network_mode: NetworkMode = args.network.parse()?;
    setup::init_logging(&args.log_level)?;
    args.apply_to_env();
    info!("kaspa-threshold-service starting log_level={}", args.log_level);

    let data_dir = igra_core::infrastructure::config::resolve_data_dir()?;
    let config_path = igra_core::infrastructure::config::resolve_config_path(&data_dir)?;

    let active_profile = match args.profile.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(profile) => profile.to_string(),
        None => {
            let base = setup::load_app_config()?;
            base.service
                .active_profile
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    ThresholdError::ConfigError(
                        "missing active profile: set CLI --profile signer-XX or service.active_profile in config".to_string(),
                    )
                })?
                .to_string()
        }
    };
    igra_core::infrastructure::config::validate_signer_profile(&active_profile)?;
    info!("loading config profile profile={}", active_profile);

    let loaded = setup::load_app_config_profile(&config_path, &active_profile)?;
    let mut app_config: AppConfig = (*loaded).clone();
    app_config.service.active_profile = Some(active_profile);
    apply_pskt_source_address_config(&mut app_config, network_mode)?;
    let app_config = Arc::new(app_config);

    // Network-mode security validation (static checks).
    let validation_config_path = args.config.clone().or(Some(config_path.clone()));
    let log_dir = match std::env::var("KASPA_IGRA_LOG_DIR") {
        Ok(v) => {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(PathBuf::from(trimmed))
            }
        }
        Err(std::env::VarError::NotPresent) => None,
        Err(err) => {
            warn!("failed to read KASPA_IGRA_LOG_DIR env var; continuing error={}", err);
            None
        }
    };
    let allow_remote_rpc = args.allow_remote_rpc || app_config.service.allow_remote_rpc;
    let validation_ctx = ValidationContext {
        config_path: validation_config_path,
        allow_remote_rpc,
        log_filters: Some(args.log_level.clone()),
        log_dir,
    };
    let validator = SecurityValidator::new(network_mode);
    let report = validator.validate_static(&app_config, &validation_ctx);
    if report.has_errors() || report.has_warnings() {
        println!("{}", report);
    }
    if network_mode.is_production() && report.has_errors() {
        std::process::exit(1);
    }

    if args.validate_only {
        let (key_manager, key_audit_log) = setup::setup_key_manager(&app_config.service, network_mode).await?;
        let key_ctx = igra_core::infrastructure::keys::KeyManagerContext::with_new_request_id(key_manager, key_audit_log);
        let kaspa_query = match network_mode {
            NetworkMode::Mainnet => KaspaGrpcQueryClient::connect(app_config.service.node_rpc_url.clone()).await?,
            NetworkMode::Testnet | NetworkMode::Devnet => {
                match KaspaGrpcQueryClient::connect(app_config.service.node_rpc_url.clone()).await {
                    Ok(client) => client,
                    Err(err) => {
                        warn!("validate-only: kaspa query client unavailable (non-mainnet); continuing error={}", err);
                        KaspaGrpcQueryClient::unimplemented()
                    }
                }
            }
        };
        match validator.validate_startup(&app_config, &kaspa_query, &key_ctx).await {
            Ok(startup_report) => {
                if startup_report.has_errors() || startup_report.has_warnings() {
                    println!("{}", startup_report);
                }
                if network_mode.is_production() && startup_report.has_errors() {
                    std::process::exit(1);
                }
            }
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        info!("validate-only complete");
        return Ok(());
    }

    info!(
        "config loaded rpc_enabled={} network_id={} has_group_config={}",
        app_config.rpc.enabled,
        app_config.iroh.network_id,
        app_config.group.is_some()
    );
    if !setup::validate_startup_config(&app_config) {
        return Ok(());
    }
    setup::warn_test_mode(&app_config);

    let storage = setup::init_storage(&app_config.service.data_dir, app_config.service.allow_schema_wipe)?;
    info!("storage initialized data_dir={}", app_config.service.data_dir);

    let required_sigs_fallback = app_config.service.hd.as_ref().map(|hd| hd.required_sigs as u16);
    let two_phase: TwoPhaseConfig = app_config.two_phase.effective(app_config.group.as_ref(), required_sigs_fallback)?;
    let phase_storage: Arc<dyn PhaseStorage> = storage.clone();

    let audit_id = args.audit.clone().or_else(igra_core::infrastructure::config::get_audit_request_id);
    if let Some(request_id) = audit_id {
        info!("audit mode requested request_id={}", request_id);
        modes::audit::dump_audit_trail(&request_id, &storage)?;
        return Ok(());
    }

    let finalize_path = args.finalize.clone().or_else(igra_core::infrastructure::config::get_finalize_pskt_json_path);
    if let Some(path) = finalize_path {
        info!("finalize mode requested path={}", path.display());
        modes::finalize::finalize_from_json(&path, &storage, &app_config).await?;
        return Ok(());
    }

    let (key_manager, key_audit_log) = setup::setup_key_manager(&app_config.service, network_mode).await?;

    info!("initializing iroh identity");
    let identity = setup::init_signer_identity(&app_config, &key_manager, &key_audit_log).await?;
    let group_id = setup::resolve_group_id(&app_config)?;
    setup::log_startup_banner(&app_config, &identity.peer_id, &group_id);
    let static_addrs = setup::parse_bootstrap_addrs(&app_config.iroh.bootstrap_addrs)?;
    let iroh_secret = setup::derive_iroh_secret(identity.seed);
    let iroh_static_enabled = !static_addrs.is_empty();
    let iroh_pkarr_enabled = app_config.iroh.discovery.enable_pkarr;
    let iroh_dns_enabled = app_config.iroh.discovery.enable_dns;
    let iroh_relay_enabled = app_config.iroh.relay.enable;
    let iroh_provider_count = (iroh_static_enabled as usize) + (iroh_pkarr_enabled as usize) + (iroh_dns_enabled as usize);

    info!(
        "iroh identity ready peer_id={} group_id={:#x} bootstrap_addrs={} pkarr={} dns={} relay={}",
        identity.peer_id,
        group_id,
        static_addrs.len(),
        app_config.iroh.discovery.enable_pkarr,
        app_config.iroh.discovery.enable_dns,
        app_config.iroh.relay.enable
    );
    let (gossip, _iroh_router) = setup::init_iroh_gossip(
        app_config.iroh.bind_port,
        static_addrs,
        iroh_secret,
        &app_config.iroh.discovery,
        &app_config.iroh.relay,
    )
    .await?;

    let iroh_config =
        IrohConfig { network_id: app_config.iroh.network_id, group_id, bootstrap_nodes: app_config.iroh.bootstrap.clone() };

    let hyperlane_validators = parse_validator_pubkeys("hyperlane.validators", &app_config.hyperlane.validators)?;
    let layerzero_validators = parse_validator_pubkeys("layerzero.endpoint_pubkeys", &app_config.layerzero.endpoint_pubkeys)?;
    let hyperlane_threshold = app_config.hyperlane.threshold.unwrap_or(1) as usize;
    let message_verifier = Arc::new(CompositeVerifier::new(hyperlane_validators, hyperlane_threshold, layerzero_validators));
    let flow = ServiceFlow::new_with_iroh(
        key_manager.clone(),
        key_audit_log.clone(),
        &app_config.service,
        storage.clone(),
        gossip,
        identity.signer,
        identity.verifier,
        iroh_config,
        message_verifier.clone(),
    )
    .await?;
    let flow = Arc::new(flow);
    let metrics = flow.metrics();
    metrics.set_iroh_discovery_config(
        iroh_provider_count,
        iroh_static_enabled,
        iroh_pkarr_enabled,
        iroh_dns_enabled,
        iroh_relay_enabled,
    );
    set_passphrase_rotation_metrics(metrics.as_ref(), &app_config.service, network_mode);

    // Network-mode security validation (startup checks).
    let startup_report = validator.validate_startup(&app_config, &flow.kaspa_query(), &flow.key_context()).await?;
    if startup_report.has_errors() || startup_report.has_warnings() {
        println!("{}", startup_report);
    }

    spawn_status_reporter(metrics.clone(), storage.clone());
    let transport = flow.transport();
    let peer_id = identity.peer_id;
    let peer_id_for_state = peer_id.clone();
    let group_id_hex = Some(group_id.to_string());

    let app_config_for_loop = app_config.clone();
    let two_phase_for_loop = two_phase.clone();
    let flow_for_loop = flow.clone();
    let transport_for_loop = transport.clone();
    let storage_for_loop = storage.clone();
    let phase_storage_for_loop = phase_storage.clone();
    let group_id_for_loop = group_id;
    tokio::spawn(async move {
        info!("starting coordination loop peer_id={} group_id={:#x}", peer_id, group_id_for_loop);
        if let Err(err) = run_coordination_loop(
            app_config_for_loop,
            two_phase_for_loop,
            flow_for_loop,
            transport_for_loop,
            storage_for_loop,
            phase_storage_for_loop,
            peer_id,
            group_id_for_loop,
        )
        .await
        {
            warn!("coordination loop error: {}", err);
        }
    });

    if app_config.rpc.enabled {
        let rpc_addr: SocketAddr = app_config.rpc.addr.parse().map_err(|err| format!("invalid KASPA_IGRA_RPC_ADDR: {}", err))?;
        info!(
            "starting json-rpc server rpc_addr={} rate_limit_rps={} rate_limit_burst={}",
            rpc_addr,
            app_config.rpc.rate_limit_rps.unwrap_or(30),
            app_config.rpc.rate_limit_burst.unwrap_or(60)
        );
        let hyperlane_ism =
            if app_config.hyperlane.domains.is_empty() { None } else { Some(ConfiguredIsm::from_config(&app_config.hyperlane)?) };
        let metrics = flow.metrics();
        let event_ctx = EventContext {
            config: app_config.service.clone(),
            policy: app_config.policy.clone(),
            two_phase: two_phase.clone(),
            local_peer_id: peer_id_for_state.clone(),
            message_verifier: message_verifier.clone(),
            storage: storage.clone(),
            phase_storage: phase_storage.clone(),
            transport: flow.transport(),
            rpc: flow.rpc(),
            key_manager: flow.key_manager(),
            key_audit_log: flow.key_audit_log(),
        };
        let rpc_state = Arc::new(RpcState {
            event_ctx,
            rpc_token: app_config.rpc.token.clone(),
            node_rpc_url: app_config.service.node_rpc_url.clone(),
            kaspa_query: flow.kaspa_query(),
            metrics,
            rate_limiter: Arc::new(igra_service::api::RateLimiter::new()),
            hyperlane_ism,
            group_id_hex,
            coordinator_peer_id: peer_id_for_state.to_string(),
            rate_limit_rps: app_config.rpc.rate_limit_rps.unwrap_or(30),
            rate_limit_burst: app_config.rpc.rate_limit_burst.unwrap_or(60),
            session_expiry_seconds: app_config.runtime.session_expiry_seconds.unwrap_or(600),
            hyperlane_mailbox_wait_seconds: app_config.rpc.hyperlane_mailbox_wait_seconds.unwrap_or(10),
        });

        let rpc_state_for_server = rpc_state.clone();
        tokio::spawn(async move {
            debug!("json-rpc server task spawned");
            if let Err(err) = run_json_rpc_server(rpc_addr, rpc_state_for_server).await {
                warn!("json-rpc server error: {}", err);
            }
        });

        if let Some(dir) = app_config.hyperlane.events_dir.clone() {
            let poll_secs = app_config.hyperlane.poll_secs;
            let state = rpc_state.clone();
            tokio::spawn(async move {
                info!("starting hyperlane watcher dir={} poll_secs={}", dir, poll_secs);
                if let Err(err) = run_hyperlane_watcher(state, PathBuf::from(dir), std::time::Duration::from_secs(poll_secs)).await {
                    warn!("hyperlane watcher error: {}", err);
                }
            });
        }
    }

    run_test_pskt_mode(&app_config, flow.as_ref(), network_mode).await?;

    Ok(())
}

fn set_passphrase_rotation_metrics(metrics: &Metrics, service: &igra_core::infrastructure::config::ServiceConfig, mode: NetworkMode) {
    let enabled = service.passphrase_rotation_enabled.unwrap_or(match mode {
        NetworkMode::Mainnet => true,
        NetworkMode::Testnet => true,
        NetworkMode::Devnet => false,
    });
    let warn_days = service.passphrase_rotation_warn_days.unwrap_or(match mode {
        NetworkMode::Mainnet => 60,
        NetworkMode::Testnet => 90,
        NetworkMode::Devnet => 0,
    });
    let error_days = service.passphrase_rotation_error_days.unwrap_or(match mode {
        NetworkMode::Mainnet => 90,
        NetworkMode::Testnet => 0,
        NetworkMode::Devnet => 0,
    });

    let mut age_days: Option<u64> = None;
    let mut created_at_secs: Option<u64> = None;
    let mut last_rotated_at_secs: Option<u64> = None;

    if service.use_encrypted_secrets {
        let secrets_path = match service.secrets_file.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(path) => PathBuf::from(path),
            None => PathBuf::from(&service.data_dir).join("secrets.bin"),
        };
        if let Ok(data) = std::fs::read(&secrets_path) {
            match SecretFile::from_bytes(&data) {
                Ok(file) => {
                    let now = igra_core::foundation::now_nanos();
                    let rotation = file.rotation_metadata();
                    age_days = Some(rotation.age_days(now));
                    created_at_secs = Some(rotation.created_at_nanos / 1_000_000_000);
                    last_rotated_at_secs = Some(rotation.last_rotated_at_nanos / 1_000_000_000);
                }
                Err(err) => {
                    warn!(
                        "failed to parse secrets file for passphrase rotation metrics secrets_file={} error={}",
                        secrets_path.display(),
                        err
                    );
                }
            }
        }
    }

    metrics.set_passphrase_rotation_metrics(enabled, warn_days, error_days, age_days, created_at_secs, last_rotated_at_secs);
}

fn spawn_status_reporter(metrics: Arc<Metrics>, storage: Arc<dyn Storage>) {
    tokio::spawn(async move {
        let interval_seconds = 300u64;
        info!("status reporter started interval_seconds={}", interval_seconds);
        let mut interval = tokio::time::interval(Duration::from_secs(interval_seconds));
        loop {
            interval.tick().await;
            if let Ok(stats) = storage.crdt_storage_stats() {
                metrics.set_crdt_storage_stats(stats);
            }
            metrics.refresh_passphrase_age();
            let snapshot = metrics.snapshot();
            info!(
                "periodic status report uptime_minutes={} sessions_total={} sessions_finalized={} sessions_timed_out={} signer_acks_accepted={} signer_acks_rejected={} partial_sigs_total={} rpc_ok={} rpc_error={} crdt_total={} crdt_pending={} crdt_completed={} crdt_cf_estimated_live_data_size_bytes={} crdt_gc_deleted_total={} tx_template_hash_mismatches_total={}",
                snapshot.uptime.as_secs() / 60,
                snapshot.sessions_proposal_received,
                snapshot.sessions_finalized,
                snapshot.sessions_timed_out,
                snapshot.signer_acks_accepted,
                snapshot.signer_acks_rejected,
                snapshot.partial_sigs_total,
                snapshot.rpc_ok,
                snapshot.rpc_error,
                snapshot.crdt_total,
                snapshot.crdt_pending,
                snapshot.crdt_completed,
                snapshot.crdt_cf_estimated_live_data_size_bytes,
                snapshot.crdt_gc_deleted_total,
                snapshot.tx_template_hash_mismatches_total
            );
        }
    });
}

fn apply_pskt_source_address_config(app_config: &mut AppConfig, mode: NetworkMode) -> Result<(), ThresholdError> {
    let redeem_hex = app_config.service.pskt.redeem_script_hex.trim();
    if redeem_hex.is_empty() {
        return Ok(());
    }

    let expected = pskt_source_address_from_redeem_script_hex(mode, redeem_hex)?;
    let provided = app_config.service.pskt.source_addresses.iter().map(|s| s.trim()).filter(|s| !s.is_empty()).collect::<Vec<_>>();

    if !provided.is_empty() {
        for addr in &provided {
            if *addr != expected {
                return Err(ThresholdError::ConfigError(format!(
                    "service.pskt.source_addresses must match the address derived from service.pskt.redeem_script_hex; expected='{expected}' got='{addr}'"
                )));
            }
        }
    }

    app_config.service.pskt.source_addresses = vec![expected.clone()];
    if app_config.service.pskt.change_address.as_deref().map(str::trim).unwrap_or("").is_empty() {
        app_config.service.pskt.change_address = Some(expected);
    }

    Ok(())
}

async fn run_test_pskt_mode(
    app_config: &igra_core::infrastructure::config::AppConfig,
    flow: &ServiceFlow,
    network_mode: NetworkMode,
) -> Result<(), ThresholdError> {
    let runtime = &app_config.runtime;
    let recipient = runtime.test_recipient.as_deref().map(str::trim).unwrap_or_default();
    let amount_sompi = runtime.test_amount_sompi.unwrap_or(0);
    let is_test_mode = runtime.test_mode;

    let test_outputs = if is_test_mode && !recipient.is_empty() && amount_sompi > 0 {
        vec![PsktOutput { address: recipient.to_string(), amount_sompi }]
    } else {
        Vec::new()
    };

    if test_outputs.is_empty() {
        if !is_test_mode {
            info!("test mode disabled; waiting for ctrl-c");
            tokio::signal::ctrl_c().await.map_err(|err| ThresholdError::Message(err.to_string()))?;
            info!("shutdown signal received");
            return Ok(());
        }
        warn!("no outputs configured; nothing to build");
        return Ok(());
    }

    info!("building test PSKT output_count={}", test_outputs.len());
    let mut test_pskt_config = app_config.service.pskt.clone();
    if test_pskt_config.redeem_script_hex.trim().is_empty() {
        if let (Some(hd), Some(path)) = (app_config.service.hd.as_ref(), runtime.hd_test_derivation_path.as_deref()) {
            match hd.key_type {
                igra_core::infrastructure::config::KeyType::HdMnemonic => {
                    let key_ctx = flow.key_context();
                    let profile = igra_core::application::pskt_signing::active_profile(&app_config.service)?;
                    let (key_data, payment_secret) =
                        igra_core::application::pskt_signing::load_mnemonic_key_data_and_payment_secret_for_profile(&key_ctx, profile)
                            .await?;
                    test_pskt_config.redeem_script_hex =
                        derive_redeem_script_hex(hd, std::slice::from_ref(&key_data), Some(path), payment_secret.as_ref())?;
                }
                igra_core::infrastructure::config::KeyType::RawPrivateKey => {
                    return Err(ThresholdError::ConfigError(
                        "service.pskt.redeem_script_hex is required when service.hd.key_type=raw_private_key".to_string(),
                    ));
                }
            }
        }
    }
    test_pskt_config.outputs = test_outputs;
    if !test_pskt_config.redeem_script_hex.trim().is_empty() {
        let expected = pskt_source_address_from_redeem_script_hex(network_mode, &test_pskt_config.redeem_script_hex)?;
        test_pskt_config.source_addresses = vec![expected.clone()];
        if test_pskt_config.change_address.as_deref().map(str::trim).unwrap_or("").is_empty() {
            test_pskt_config.change_address = Some(expected);
        }
    }

    let (_selection, build) = igra_service::service::build_pskt_via_rpc(&test_pskt_config).await?;
    let json = serde_json::to_string_pretty(&build.pskt)?;
    info!("test PSKT built; printing json");
    println!("{}", json);
    Ok(())
}
