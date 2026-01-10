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
use tracing::debug;

pub struct GrpcNodeRpc {
    client: GrpcClient,
}

impl GrpcNodeRpc {
    pub async fn connect(url: String) -> Result<Self, ThresholdError> {
        let client =
            GrpcClient::connect_with_args(NotificationMode::Direct, url, None, false, None, false, Some(500_000), Default::default())
                .await
                .map_err(|err| ThresholdError::Message(err.to_string()))?;
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
        let entries = self
            .client
            .get_utxos_by_addresses(addresses.to_vec())
            .await
            .map_err(|err| ThresholdError::Message(err.to_string()))?;
        debug!(
            address_count = addresses.len(),
            utxo_count = entries.len(),
            elapsed_ms = started.elapsed().as_millis(),
            "grpc get_utxos_by_addresses"
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
        let rpc_tx = Self::to_rpc_transaction(tx);
        let id = self
            .client
            .submit_transaction(rpc_tx, false)
            .await
            .map_err(|err| ThresholdError::Message(err.to_string()))?;
        debug!(elapsed_ms = started.elapsed().as_millis(), tx_id = %id, "grpc submit_transaction");
        Ok(id)
    }

    async fn get_virtual_selected_parent_blue_score(&self) -> Result<u64, ThresholdError> {
        let started = Instant::now();
        let score =
            self.client.get_sink_blue_score().await.map_err(|err| ThresholdError::Message(err.to_string()))?;
        debug!(elapsed_ms = started.elapsed().as_millis(), blue_score = score, "grpc get_sink_blue_score");
        Ok(score)
    }
}
