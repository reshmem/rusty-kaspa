use crate::foundation::{ThresholdError, GRPC_MAX_MESSAGE_SIZE_BYTES};
use kaspa_addresses::Address;
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::notify::mode::NotificationMode;
use kaspa_rpc_core::{GetBlockDagInfoResponse, GetServerInfoResponse, RpcBlock, RpcHash, RpcMempoolEntry, RpcTransactionId};
use log::{debug, error, info};
use std::sync::Arc;

#[derive(Clone)]
pub struct KaspaGrpcQueryClient {
    client: Option<Arc<GrpcClient>>,
    redacted_url: String,
}

impl KaspaGrpcQueryClient {
    pub async fn connect(url: String) -> Result<Self, ThresholdError> {
        let redacted_url = redact_url(&url);
        info!("connecting kaspa query client url={}", redacted_url);
        let client = GrpcClient::connect_with_args(
            NotificationMode::Direct,
            url,
            None,
            false,
            None,
            false,
            Some(GRPC_MAX_MESSAGE_SIZE_BYTES),
            Default::default(),
        )
        .await
        .map_err(|err| {
            error!("kaspa query client connect failed url={} error={}", redacted_url, err);
            ThresholdError::NodeRpcError(err.to_string())
        })?;
        debug!("kaspa query client connected url={}", redacted_url);
        Ok(Self { client: Some(Arc::new(client)), redacted_url })
    }

    pub fn unimplemented() -> Self {
        Self { client: None, redacted_url: "<unconfigured>".to_string() }
    }

    pub async fn get_server_info(&self) -> Result<GetServerInfoResponse, ThresholdError> {
        let client = self.require_client("get_server_info")?;
        client
            .get_server_info()
            .await
            .map_err(|err| ThresholdError::NodeRpcError(format!("get_server_info failed url={} error={}", self.redacted_url, err)))
    }

    pub async fn get_block_dag_info(&self) -> Result<GetBlockDagInfoResponse, ThresholdError> {
        let client = self.require_client("get_block_dag_info")?;
        client
            .get_block_dag_info()
            .await
            .map_err(|err| ThresholdError::NodeRpcError(format!("get_block_dag_info failed url={} error={}", self.redacted_url, err)))
    }

    pub async fn get_virtual_daa_score(&self) -> Result<u64, ThresholdError> {
        Ok(self.get_block_dag_info().await?.virtual_daa_score)
    }

    pub async fn get_balance_by_address(&self, address: Address) -> Result<u64, ThresholdError> {
        let client = self.require_client("get_balance_by_address")?;
        client.get_balance_by_address(address).await.map_err(|err| {
            ThresholdError::NodeRpcError(format!("get_balance_by_address failed url={} error={}", self.redacted_url, err))
        })
    }

    pub async fn get_block(&self, hash: RpcHash) -> Result<RpcBlock, ThresholdError> {
        let client = self.require_client("get_block")?;
        client
            .get_block(hash, false)
            .await
            .map_err(|err| ThresholdError::NodeRpcError(format!("get_block failed url={} error={}", self.redacted_url, err)))
    }

    pub async fn get_mempool_entry(&self, tx_id: RpcTransactionId) -> Result<RpcMempoolEntry, ThresholdError> {
        let client = self.require_client("get_mempool_entry")?;
        client
            .get_mempool_entry(tx_id, true, false)
            .await
            .map_err(|err| ThresholdError::NodeRpcError(format!("get_mempool_entry failed url={} error={}", self.redacted_url, err)))
    }

    fn require_client(&self, operation: &'static str) -> Result<&GrpcClient, ThresholdError> {
        let Some(client) = self.client.as_deref() else {
            return Err(ThresholdError::Unimplemented(format!("kaspa query client not configured operation={}", operation)));
        };
        Ok(client)
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
