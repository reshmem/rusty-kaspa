#[path = "kaspa-threshold-service/cli.rs"]
mod cli;
#[path = "kaspa-threshold-service/modes/mod.rs"]
mod modes;
#[path = "kaspa-threshold-service/setup.rs"]
mod setup;

use crate::cli::Cli;
use igra_core::infrastructure::config::{derive_redeem_script_hex, PsktOutput};
use igra_core::foundation::ThresholdError;
use igra_core::application::EventContext;
use igra_core::infrastructure::hyperlane::ConfiguredIsm;
use igra_core::domain::validation::{parse_validator_pubkeys, CompositeVerifier};
use igra_service::api::json_rpc::{run_hyperlane_watcher, run_json_rpc_server, RpcState};
use igra_service::service::coordination::run_coordination_loop;
use igra_service::service::flow::ServiceFlow;
use igra_service::transport::iroh::IrohConfig;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::warn;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse_args();
    setup::init_logging(&args.log_level)?;
    args.apply_to_env();

    // If a profile is provided (via KASPA_IGRA_PROFILE), load the profiled section of the INI.
    let app_config = if let Ok(profile) = std::env::var("KASPA_IGRA_PROFILE") {
        let data_dir = igra_core::infrastructure::config::resolve_data_dir()?;
        let config_path = igra_core::infrastructure::config::resolve_config_path(&data_dir)?;
        setup::load_app_config_profile(&config_path, profile.trim())?
    } else {
        setup::load_app_config()?
    };
    if !setup::validate_startup_config(&app_config) {
        return Ok(());
    }
    setup::warn_test_mode(&app_config);

    let storage = setup::init_storage(&app_config.service.data_dir)?;

    let audit_id = args.audit.clone().or_else(igra_core::infrastructure::config::get_audit_request_id);
    if let Some(request_id) = audit_id {
        modes::audit::dump_audit_trail(&request_id, &storage)?;
        return Ok(());
    }

    let finalize_path = args.finalize.clone().or_else(igra_core::infrastructure::config::get_finalize_pskt_json_path);
    if let Some(path) = finalize_path {
        modes::finalize::finalize_from_json(&path, &storage, &app_config).await?;
        return Ok(());
    }

    let identity = setup::init_signer_identity(&app_config)?;
    let group_id = setup::resolve_group_id(&app_config)?;
    let static_addrs = setup::parse_bootstrap_addrs(&app_config.iroh.bootstrap_addrs)?;
    let iroh_secret = setup::derive_iroh_secret(&app_config.iroh.signer_seed_hex.clone().unwrap_or_else(|| "".to_string()))?;

    let (gossip, _iroh_router) = setup::init_iroh_gossip(app_config.iroh.bind_port, static_addrs, iroh_secret).await?;

    let iroh_config =
        IrohConfig { network_id: app_config.iroh.network_id, group_id, bootstrap_nodes: app_config.iroh.bootstrap.clone() };
    let flow =
        ServiceFlow::new_with_iroh(&app_config.service, storage.clone(), gossip, identity.signer, identity.verifier, iroh_config)
            .await?;
    let flow = Arc::new(flow);
    let transport = flow.transport();
    let peer_id = identity.peer_id;
    let peer_id_for_state = peer_id.clone();
    let group_id_hex = Some(hex::encode(group_id));

    let app_config_for_loop = app_config.clone();
    let flow_for_loop = flow.clone();
    let transport_for_loop = transport.clone();
    let storage_for_loop = storage.clone();
    let group_id_for_loop = group_id;
    tokio::spawn(async move {
        if let Err(err) =
            run_coordination_loop(app_config_for_loop, flow_for_loop, transport_for_loop, storage_for_loop, peer_id, group_id_for_loop)
                .await
        {
            warn!("coordination loop error: {}", err);
        }
    });

    if app_config.rpc.enabled {
        let rpc_addr: SocketAddr = app_config.rpc.addr.parse().map_err(|err| format!("invalid KASPA_IGRA_RPC_ADDR: {}", err))?;
        let hyperlane_ism =
            if app_config.hyperlane.domains.is_empty() { None } else { Some(ConfiguredIsm::from_config(&app_config.hyperlane)?) };
        let hyperlane_validators = parse_validator_pubkeys("hyperlane.validators", &app_config.hyperlane.validators)?;
        let layerzero_validators = parse_validator_pubkeys("layerzero.endpoint_pubkeys", &app_config.layerzero.endpoint_pubkeys)?;
        let message_verifier = Arc::new(CompositeVerifier::new(hyperlane_validators, layerzero_validators));
        let metrics = flow.metrics();
        let event_ctx =
            EventContext { processor: flow.clone(), config: app_config.service.clone(), message_verifier, storage: storage.clone() };
        let rpc_state = Arc::new(RpcState {
            event_ctx,
            rpc_token: app_config.rpc.token.clone(),
            node_rpc_url: app_config.service.node_rpc_url.clone(),
            metrics,
            rate_limiter: Arc::new(igra_service::api::RateLimiter::new()),
            hyperlane_ism,
            group_id_hex,
            coordinator_peer_id: peer_id_for_state.to_string(),
            hyperlane_default_derivation_path: app_config
                .hyperlane
                .default_derivation_path
                .clone()
                .unwrap_or_else(|| "m/45h/111111h/0h/0/0".to_string()),
            rate_limit_rps: app_config.rpc.rate_limit_rps.unwrap_or(30),
            rate_limit_burst: app_config.rpc.rate_limit_burst.unwrap_or(60),
            session_expiry_seconds: app_config.runtime.session_expiry_seconds.unwrap_or(600),
        });

        let rpc_state_for_server = rpc_state.clone();
        tokio::spawn(async move {
            if let Err(err) = run_json_rpc_server(rpc_addr, rpc_state_for_server).await {
                warn!("json-rpc server error: {}", err);
            }
        });

        if let Some(dir) = app_config.hyperlane.events_dir.clone() {
            let poll_secs = app_config.hyperlane.poll_secs;
            let state = rpc_state.clone();
            tokio::spawn(async move {
                if let Err(err) = run_hyperlane_watcher(state, PathBuf::from(dir), std::time::Duration::from_secs(poll_secs)).await {
                    warn!("hyperlane watcher error: {}", err);
                }
            });
        }
    }

    run_test_pskt_mode(&app_config, flow.as_ref()).await?;

    Ok(())
}

async fn run_test_pskt_mode(
    app_config: &igra_core::infrastructure::config::AppConfig,
    _flow: &ServiceFlow,
) -> Result<(), ThresholdError> {
    let runtime = &app_config.runtime;
    let recipient = runtime.test_recipient.clone().unwrap_or_default();
    let amount_sompi = runtime.test_amount_sompi.unwrap_or(0);
    let is_test_mode = runtime.test_mode;

    let test_outputs = if is_test_mode && !recipient.is_empty() && amount_sompi > 0 {
        vec![PsktOutput { address: recipient.clone(), amount_sompi }]
    } else {
        Vec::new()
    };

    if test_outputs.is_empty() {
        if !is_test_mode {
            tokio::signal::ctrl_c().await.map_err(|err| ThresholdError::Message(err.to_string()))?;
            return Ok(());
        }
        warn!("no outputs configured; nothing to build");
        return Ok(());
    }

    let mut test_pskt_config = app_config.service.pskt.clone();
    if test_pskt_config.redeem_script_hex.trim().is_empty() {
        if let (Some(hd), Some(path)) = (app_config.service.hd.as_ref(), runtime.hd_test_derivation_path.as_deref()) {
            test_pskt_config.redeem_script_hex = derive_redeem_script_hex(hd, path)?;
        }
    }
    test_pskt_config.outputs = test_outputs;

    let pskt = igra_service::service::build_pskt_via_rpc(&test_pskt_config).await?;
    let json = serde_json::to_string_pretty(&pskt)?;
    println!("{}", json);
    Ok(())
}
