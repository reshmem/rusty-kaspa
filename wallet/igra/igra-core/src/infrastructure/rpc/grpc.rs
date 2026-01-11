use crate::foundation::ThresholdError;
use crate::infrastructure::rpc::{NodeRpc, UtxoWithOutpoint};
use async_trait::async_trait;
use kaspa_addresses::Address;
use kaspa_consensus_core::tx::{Transaction, TransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::notify::mode::NotificationMode;
use kaspa_rpc_core::RpcTransaction;
use std::time::Instant;
use log::{debug, error, info, trace, warn};

pub struct GrpcNodeRpc {
    client: GrpcClient,
}

impl GrpcNodeRpc {
    pub async fn connect(url: String) -> Result<Self, ThresholdError> {
        let redacted_url = redact_url(&url);
        info!("connecting grpc rpc url={}", redacted_url);
        let client =
            GrpcClient::connect_with_args(NotificationMode::Direct, url, None, false, None, false, Some(500_000), Default::default())
                .await
                .map_err(|err| {
                    error!("grpc rpc connect failed error={}", err);
                    ThresholdError::Message(err.to_string())
                })?;
        info!("grpc rpc connected");
        Ok(Self { client })
    }

    fn to_rpc_transaction(tx: Transaction) -> RpcTransaction {
        let mass = tx.mass();
        let Transaction { version, inputs, outputs, lock_time, subnetwork_id, gas, payload, .. } = tx;
        RpcTransaction {
            version,
            inputs: inputs.into_iter().map(Into::into).collect(),
            outputs: outputs.into_iter().map(Into::into).collect(),
            lock_time,
            subnetwork_id,
            gas,
            payload,
            mass,
            verbose_data: None,
        }
    }
}

#[async_trait]
impl NodeRpc for GrpcNodeRpc {
    async fn get_utxos_by_addresses(&self, addresses: &[Address]) -> Result<Vec<UtxoWithOutpoint>, ThresholdError> {
        let started = Instant::now();
        trace!("grpc get_utxos_by_addresses request addresses={:?}", addresses);
        let entries = match self.client.get_utxos_by_addresses(addresses.to_vec()).await {
            Ok(entries) => entries,
            Err(err) => {
                warn!(
                    "grpc get_utxos_by_addresses failed address_count={} error={}",
                    addresses.len(),
                    err
                );
                return Err(ThresholdError::Message(err.to_string()));
            }
        };
        debug!(
            "grpc get_utxos_by_addresses address_count={} utxo_count={} elapsed_ms={}",
            addresses.len(),
            entries.len(),
            started.elapsed().as_millis()
        );

        Ok(entries
            .into_iter()
            .map(|entry| UtxoWithOutpoint {
                address: entry.address,
                outpoint: TransactionOutpoint::from(entry.outpoint),
                entry: UtxoEntry::from(entry.utxo_entry),
            })
            .collect())
    }

    async fn submit_transaction(&self, tx: Transaction) -> Result<TransactionId, ThresholdError> {
        let started = Instant::now();
        let mass = tx.mass();
        info!("grpc submit_transaction start mass={}", mass);
        let rpc_tx = Self::to_rpc_transaction(tx);
        let id = self.client.submit_transaction(rpc_tx, false).await.map_err(|err| {
            error!("grpc submit_transaction failed mass={} error={}", mass, err);
            ThresholdError::Message(err.to_string())
        })?;
        debug!(
            "grpc submit_transaction tx_id={} elapsed_ms={}",
            id,
            started.elapsed().as_millis()
        );
        Ok(id)
    }

    async fn get_virtual_selected_parent_blue_score(&self) -> Result<u64, ThresholdError> {
        let started = Instant::now();
        trace!("grpc get_sink_blue_score request");
        let score = self.client.get_sink_blue_score().await.map_err(|err| ThresholdError::Message(err.to_string()))?;
        debug!(
            "grpc get_sink_blue_score blue_score={} elapsed_ms={}",
            score,
            started.elapsed().as_millis()
        );
        Ok(score)
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
