use igra_core::config::{derive_redeem_script_hex, PsktBuildConfig, PsktOutput, ServiceConfig};
use igra_core::coordination::coordinator::Coordinator;
use igra_core::error::ThresholdError;
use igra_core::event::EventProcessor;
use igra_core::lifecycle::{LifecycleObserver, NoopObserver};
use igra_core::model::{Hash32, SigningEvent};
use igra_core::types::{PeerId, RequestId, SessionId};
use igra_core::rpc::grpc::GrpcNodeRpc;
use igra_core::rpc::NodeRpc;
use igra_core::storage::Storage;
use igra_core::transport::Transport;
use crate::service::metrics::Metrics;
use crate::transport::iroh::{IrohConfig, IrohTransport};
use igra_core::transport::{SignatureSigner, SignatureVerifier};
use async_trait::async_trait;
use std::sync::Arc;

pub struct ServiceFlow {
    coordinator: Coordinator,
    storage: Arc<dyn Storage>,
    transport: Arc<dyn Transport>,
    rpc: Arc<dyn NodeRpc>,
    metrics: Arc<Metrics>,
    lifecycle: Arc<dyn LifecycleObserver>,
}

impl ServiceFlow {
    pub async fn new(config: &ServiceConfig, storage: Arc<dyn Storage>, transport: Arc<dyn Transport>) -> Result<Self, ThresholdError> {
        let rpc = Arc::new(GrpcNodeRpc::connect(config.node_rpc_url.clone()).await?);
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

    pub fn new_with_rpc(
        rpc: Arc<dyn NodeRpc>,
        storage: Arc<dyn Storage>,
        transport: Arc<dyn Transport>,
    ) -> Result<Self, ThresholdError> {
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
        let pskt_config = resolve_pskt_config(config, &signing_event)?;
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
        self.propose_from_rpc(
            config,
            session_id,
            request_id,
            signing_event,
            expires_at_nanos,
            coordinator_peer_id,
        )
        .await
    }
}

fn resolve_pskt_config(config: &ServiceConfig, signing_event: &SigningEvent) -> Result<PsktBuildConfig, ThresholdError> {
    if signing_event.destination_address.trim().is_empty() || signing_event.amount_sompi == 0 {
        return Err(ThresholdError::Message("signing_event missing destination_address or amount".to_string()));
    }
    if !config.pskt.redeem_script_hex.trim().is_empty() {
        let mut pskt = config.pskt.clone();
        pskt.outputs = vec![PsktOutput {
            address: signing_event.destination_address.clone(),
            amount_sompi: signing_event.amount_sompi,
        }];
        return Ok(pskt);
    }
    let hd = config
        .hd
        .as_ref()
        .ok_or_else(|| ThresholdError::Message("missing redeem script or HD config".to_string()))?;
    let redeem_script_hex = derive_redeem_script_hex(hd, &signing_event.derivation_path)?;
    let mut pskt = config.pskt.clone();
    pskt.outputs = vec![PsktOutput {
        address: signing_event.destination_address.clone(),
        amount_sompi: signing_event.amount_sompi,
    }];
    pskt.redeem_script_hex = redeem_script_hex;
    Ok(pskt)
}
