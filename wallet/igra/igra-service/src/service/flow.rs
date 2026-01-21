use crate::service::metrics::Metrics;
use crate::transport::iroh::{IrohConfig, IrohTransport};
use igra_core::application::{LifecycleObserver, NoopObserver};
use igra_core::domain::pskt::multisig as pskt_multisig;
use igra_core::domain::signing::aggregation;
use igra_core::domain::validation::MessageVerifier;
use igra_core::foundation::{EventId, ThresholdError};
use igra_core::infrastructure::config::ServiceConfig;
use igra_core::infrastructure::rpc::GrpcNodeRpc;
use igra_core::infrastructure::rpc::KaspaGrpcQueryClient;
use igra_core::infrastructure::rpc::NodeRpc;
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::transport::iroh::traits::{SignatureSigner, SignatureVerifier, Transport};
use log::{debug, info, warn};
use std::sync::Arc;
use std::time::Duration;

const MAX_SUBMIT_TX_ATTEMPTS: u32 = 4;
const TX_RETRY_BASE_BACKOFF_MS: u64 = 100;
const TX_RETRY_BACKOFF_MULTIPLIER: u64 = 2;

pub struct ServiceFlow {
    storage: Arc<dyn Storage>,
    transport: Arc<dyn Transport>,
    rpc: Arc<dyn NodeRpc>,
    kaspa_query: Arc<KaspaGrpcQueryClient>,
    message_verifier: Arc<dyn MessageVerifier>,
    metrics: Arc<Metrics>,
    lifecycle: Arc<dyn LifecycleObserver>,
}

impl ServiceFlow {
    pub async fn new(
        config: &ServiceConfig,
        storage: Arc<dyn Storage>,
        transport: Arc<dyn Transport>,
        message_verifier: Arc<dyn MessageVerifier>,
    ) -> Result<Self, ThresholdError> {
        info!("initializing service flow rpc_url={}", redact_url(&config.node_rpc_url));
        let rpc = Arc::new(GrpcNodeRpc::connect_with_config(config.node_rpc_url.clone(), config.node_rpc_circuit_breaker).await?);
        let kaspa_query = Arc::new(KaspaGrpcQueryClient::connect(config.node_rpc_url.clone()).await?);
        debug!("grpc rpc connected");
        let metrics = Arc::new(Metrics::new()?);
        debug!("metrics initialized");
        let lifecycle = Arc::new(NoopObserver);
        Ok(Self { storage, transport, rpc, kaspa_query, message_verifier, metrics, lifecycle })
    }

    pub fn new_with_rpc(
        rpc: Arc<dyn NodeRpc>,
        kaspa_query: Arc<KaspaGrpcQueryClient>,
        storage: Arc<dyn Storage>,
        transport: Arc<dyn Transport>,
        message_verifier: Arc<dyn MessageVerifier>,
    ) -> Result<Self, ThresholdError> {
        info!("initializing service flow with injected rpc");
        let metrics = Arc::new(Metrics::new()?);
        let lifecycle = Arc::new(NoopObserver);
        Ok(Self { storage, transport, rpc, kaspa_query, message_verifier, metrics, lifecycle })
    }

    pub async fn new_with_iroh(
        config: &ServiceConfig,
        storage: Arc<dyn Storage>,
        gossip: iroh_gossip::net::Gossip,
        signer: Arc<dyn SignatureSigner>,
        verifier: Arc<dyn SignatureVerifier>,
        iroh_config: IrohConfig,
        message_verifier: Arc<dyn MessageVerifier>,
    ) -> Result<Self, ThresholdError> {
        info!(
            "initializing iroh transport network_id={} group_id={:#x} bootstrap_nodes={}",
            iroh_config.network_id,
            iroh_config.group_id,
            iroh_config.bootstrap_nodes.len()
        );
        let transport = Arc::new(IrohTransport::new(gossip, signer, verifier, storage.clone(), iroh_config)?);
        Self::new(config, storage, transport, message_verifier).await
    }

    pub fn message_verifier_ref(&self) -> &dyn MessageVerifier {
        self.message_verifier.as_ref()
    }

    pub async fn finalize_and_submit(
        &self,
        event_id: EventId,
        pskt: kaspa_wallet_pskt::prelude::PSKT<kaspa_wallet_pskt::prelude::Combiner>,
        required_signatures: usize,
        ordered_pubkeys: &[secp256k1::PublicKey],
        params: &kaspa_consensus_core::config::params::Params,
    ) -> Result<kaspa_consensus_core::tx::TransactionId, ThresholdError> {
        info!(
            "finalizing and submitting transaction event_id={:#x} required_signatures={} pubkey_count={}",
            event_id,
            required_signatures,
            ordered_pubkeys.len()
        );

        let finalize_result = aggregation::finalize_pskt(pskt, required_signatures, ordered_pubkeys)?;
        let tx_result = pskt_multisig::extract_tx(finalize_result.pskt, params)?;
        let final_tx = tx_result.tx.clone();
        let expected_tx_id = final_tx.id();

        fn is_duplicate_submission(err: &ThresholdError) -> bool {
            let msg = err.to_string().to_lowercase();
            msg.contains("already")
                && (msg.contains("mempool")
                    || msg.contains("known")
                    || msg.contains("exists")
                    || msg.contains("duplicate")
                    || msg.contains("accepted by the consensus"))
        }

        fn is_non_retryable_submission(err: &ThresholdError) -> bool {
            let msg = err.to_string().to_lowercase();
            msg.contains("not standard") && msg.contains("storage mass") && msg.contains("max allowed")
                || msg.contains("sig op count exceeds passed limit")
                || (msg.contains("not standard") && msg.contains("under the required amount"))
                || (msg.contains("not standard") && msg.contains("has 0 fees"))
        }

        let mut attempt = 0u32;
        let tx_id = loop {
            attempt += 1;
            match self.rpc.submit_transaction(final_tx.clone()).await {
                Ok(id) => {
                    self.metrics.inc_tx_submission("ok");
                    info!("submit_transaction ok event_id={:#x} tx_id={} mass={}", event_id, id, tx_result.mass);
                    break id;
                }
                Err(err) if is_duplicate_submission(&err) => {
                    self.metrics.inc_tx_submission("duplicate");
                    info!(
                        "submit_transaction already accepted; treating as success event_id={:#x} tx_id={} error={}",
                        event_id, expected_tx_id, err
                    );
                    break expected_tx_id;
                }
                Err(err) if is_non_retryable_submission(&err) => {
                    self.metrics.inc_tx_submission("error");
                    warn!(
                        "submit_transaction rejected as non-retryable; not retrying event_id={:#x} tx_id={} mass={} error={}",
                        event_id, expected_tx_id, tx_result.mass, err
                    );
                    return Err(err);
                }
                Err(err) if attempt < MAX_SUBMIT_TX_ATTEMPTS => {
                    let backoff_ms = TX_RETRY_BASE_BACKOFF_MS.saturating_mul(TX_RETRY_BACKOFF_MULTIPLIER.saturating_pow(attempt - 1));
                    warn!(
                        "submit_transaction failed; retrying event_id={:#x} attempt={} backoff_ms={} error={}",
                        event_id, attempt, backoff_ms, err
                    );
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                }
                Err(err) => {
                    self.metrics.inc_tx_submission("error");
                    return Err(err);
                }
            }
        };
        Ok(tx_id)
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

    pub fn kaspa_query(&self) -> Arc<KaspaGrpcQueryClient> {
        self.kaspa_query.clone()
    }

    pub fn message_verifier(&self) -> Arc<dyn MessageVerifier> {
        self.message_verifier.clone()
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        self.metrics.clone()
    }

    pub fn lifecycle(&self) -> Arc<dyn LifecycleObserver> {
        self.lifecycle.clone()
    }

    pub fn set_lifecycle_observer(&mut self, observer: Arc<dyn LifecycleObserver>) {
        self.lifecycle = observer.clone();
    }
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
