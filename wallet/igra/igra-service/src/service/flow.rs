use crate::service::metrics::Metrics;
use crate::transport::iroh::{IrohConfig, IrohTransport};
use async_trait::async_trait;
use igra_core::application::Coordinator;
use igra_core::application::EventProcessor;
use igra_core::application::{LifecycleObserver, NoopObserver};
use igra_core::domain::SigningEvent;
use igra_core::foundation::Hash32;
use igra_core::foundation::ThresholdError;
use igra_core::foundation::{PeerId, RequestId, SessionId};
use igra_core::infrastructure::config::{derive_redeem_script_hex, PsktBuildConfig, PsktOutput, ServiceConfig};
use igra_core::infrastructure::rpc::GrpcNodeRpc;
use igra_core::infrastructure::rpc::NodeRpc;
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::transport::iroh::traits::{SignatureSigner, SignatureVerifier, Transport};
use std::sync::Arc;
use tracing::{debug, info};

pub struct ServiceFlow {
    coordinator: Coordinator,
    storage: Arc<dyn Storage>,
    transport: Arc<dyn Transport>,
    rpc: Arc<dyn NodeRpc>,
    metrics: Arc<Metrics>,
    lifecycle: Arc<dyn LifecycleObserver>,
}

impl ServiceFlow {
    pub async fn new(
        config: &ServiceConfig,
        storage: Arc<dyn Storage>,
        transport: Arc<dyn Transport>,
    ) -> Result<Self, ThresholdError> {
        info!(rpc_url = %redact_url(&config.node_rpc_url), "initializing service flow");
        let rpc = Arc::new(GrpcNodeRpc::connect(config.node_rpc_url.clone()).await?);
        debug!("grpc rpc connected");
        let metrics = Arc::new(Metrics::new()?);
        debug!("metrics initialized");
        let lifecycle = Arc::new(NoopObserver);
        Ok(Self {
            coordinator: Coordinator::with_observer(transport.clone(), storage.clone(), lifecycle.clone()),
            storage,
            transport,
            rpc,
            metrics,
            lifecycle,
        })
    }

    pub fn new_with_rpc(
        rpc: Arc<dyn NodeRpc>,
        storage: Arc<dyn Storage>,
        transport: Arc<dyn Transport>,
    ) -> Result<Self, ThresholdError> {
        info!("initializing service flow with injected rpc");
        let metrics = Arc::new(Metrics::new()?);
        let lifecycle = Arc::new(NoopObserver);
        Ok(Self {
            coordinator: Coordinator::with_observer(transport.clone(), storage.clone(), lifecycle.clone()),
            storage,
            transport,
            rpc,
            metrics,
            lifecycle,
        })
    }

    pub async fn new_with_iroh(
        config: &ServiceConfig,
        storage: Arc<dyn Storage>,
        gossip: iroh_gossip::net::Gossip,
        signer: Arc<dyn SignatureSigner>,
        verifier: Arc<dyn SignatureVerifier>,
        iroh_config: IrohConfig,
    ) -> Result<Self, ThresholdError> {
        info!(
            network_id = iroh_config.network_id,
            group_id = %hex::encode(iroh_config.group_id),
            bootstrap_nodes = iroh_config.bootstrap_nodes.len(),
            "initializing iroh transport"
        );
        let transport = Arc::new(IrohTransport::new(gossip, signer, verifier, storage.clone(), iroh_config)?);
        Self::new(config, storage, transport).await
    }

    pub async fn propose_from_rpc(
        &self,
        config: &ServiceConfig,
        session_id: SessionId,
        request_id: RequestId,
        signing_event: SigningEvent,
        expires_at_nanos: u64,
        coordinator_peer_id: PeerId,
    ) -> Result<Hash32, ThresholdError> {
        let span = tracing::info_span!(
            "propose_from_rpc",
            session_id = %hex::encode(session_id.as_hash()),
            request_id = %request_id,
            event_id = %signing_event.event_id,
            expires_at_nanos,
            coordinator_peer_id = %coordinator_peer_id,
        );
        let _entered = span.enter();
        let pskt_config = resolve_pskt_config(config, &signing_event)?;
        debug!(
            sig_op_count = pskt_config.sig_op_count,
            source_addresses = pskt_config.source_addresses.len(),
            outputs = pskt_config.outputs.len(),
            has_redeem_script = !pskt_config.redeem_script_hex.trim().is_empty(),
            "resolved pskt config"
        );
        self.coordinator
            .propose_session_from_rpc(
                self.rpc.as_ref(),
                &pskt_config,
                session_id,
                request_id,
                signing_event,
                expires_at_nanos,
                coordinator_peer_id,
            )
            .await
    }

    pub async fn finalize_and_submit(
        &self,
        request_id: &RequestId,
        pskt: kaspa_wallet_pskt::prelude::PSKT<kaspa_wallet_pskt::prelude::Combiner>,
        required_signatures: usize,
        ordered_pubkeys: &[secp256k1::PublicKey],
        params: &kaspa_consensus_core::config::params::Params,
    ) -> Result<kaspa_consensus_core::tx::TransactionId, ThresholdError> {
        info!(
            request_id = %request_id,
            required_signatures,
            pubkey_count = ordered_pubkeys.len(),
            "finalizing and submitting transaction"
        );
        self.coordinator
            .finalize_and_submit_multisig(self.rpc.as_ref(), request_id, pskt, required_signatures, ordered_pubkeys, params)
            .await
    }

    pub fn storage(&self) -> Arc<dyn Storage> {
        self.storage.clone()
    }

    pub fn transport(&self) -> Arc<dyn Transport> {
        self.transport.clone()
    }

    pub fn rpc(&self) -> Arc<dyn NodeRpc> {
        self.rpc.clone()
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        self.metrics.clone()
    }

    pub fn lifecycle(&self) -> Arc<dyn LifecycleObserver> {
        self.lifecycle.clone()
    }

    pub fn set_lifecycle_observer(&mut self, observer: Arc<dyn LifecycleObserver>) {
        self.lifecycle = observer.clone();
        self.coordinator.set_lifecycle_observer(observer);
    }
}

#[async_trait]
impl EventProcessor for ServiceFlow {
    async fn handle_signing_event(
        &self,
        config: &ServiceConfig,
        session_id: SessionId,
        request_id: RequestId,
        signing_event: SigningEvent,
        expires_at_nanos: u64,
        coordinator_peer_id: PeerId,
    ) -> Result<Hash32, ThresholdError> {
        self.propose_from_rpc(config, session_id, request_id, signing_event, expires_at_nanos, coordinator_peer_id).await
    }
}

fn resolve_pskt_config(config: &ServiceConfig, signing_event: &SigningEvent) -> Result<PsktBuildConfig, ThresholdError> {
    if signing_event.destination_address.trim().is_empty() || signing_event.amount_sompi == 0 {
        return Err(ThresholdError::Message("signing_event missing destination_address or amount".to_string()));
    }
    if !config.pskt.redeem_script_hex.trim().is_empty() {
        debug!("using configured redeem script");
        let mut pskt = config.pskt.clone();
        pskt.outputs =
            vec![PsktOutput { address: signing_event.destination_address.clone(), amount_sompi: signing_event.amount_sompi }];
        return Ok(pskt);
    }
    debug!("deriving redeem script via HD config");
    let hd = config.hd.as_ref().ok_or_else(|| ThresholdError::Message("missing redeem script or HD config".to_string()))?;
    let redeem_script_hex = derive_redeem_script_hex(hd, &signing_event.derivation_path)?;
    let mut pskt = config.pskt.clone();
    pskt.outputs = vec![PsktOutput { address: signing_event.destination_address.clone(), amount_sompi: signing_event.amount_sompi }];
    pskt.redeem_script_hex = redeem_script_hex;
    Ok(pskt)
}

fn redact_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let (scheme, rest) = url.split_at(scheme_end + 3);
    let Some(at) = rest.find('@') else {
        return url.to_string();
    };
    format!("{scheme}<redacted>@{}", &rest[at + 1..])
}
