use super::types::{json_err, json_ok, RpcErrorCode};
use crate::api::state::RpcState;
use igra_core::application::{submit_signing_event, SigningEventParams};
use igra_core::foundation::ThresholdError;
use log::{debug, info, warn};

pub async fn handle_signing_event_submit(
    state: &RpcState,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
) -> serde_json::Value {
    info!("rpc signing_event.submit called");
    let params = match params {
        Some(params) => params,
        None => {
            state.metrics.inc_rpc_request("signing_event.submit", "error");
            warn!("rpc signing_event.submit missing params");
            return json_err(id, RpcErrorCode::InvalidParams, "missing params");
        }
    };

    let params: SigningEventParams = match serde_json::from_value(params) {
        Ok(params) => params,
        Err(err) => {
            state.metrics.inc_rpc_request("signing_event.submit", "error");
            warn!("rpc signing_event.submit invalid params error={}", err);
            return json_err(id, RpcErrorCode::InvalidParams, err.to_string());
        }
    };

    debug!(
        "rpc signing_event.submit parsed session_id={} external_request_id={:?} coordinator_peer_id={} expires_at_nanos={}",
        params.session_id_hex, params.external_request_id, params.coordinator_peer_id, params.expires_at_nanos
    );

    match submit_signing_event(&state.event_ctx, params).await {
        Ok(result) => {
            state.metrics.inc_rpc_request("signing_event.submit", "ok");
            state.metrics.inc_submitted_event("signing_event");
            info!(
                "rpc signing_event.submit ok session_id={} event_id={} tx_template_hash={}",
                result.session_id_hex, result.event_id_hex, result.tx_template_hash_hex
            );
            json_ok(id, result)
        }
        Err(err) => {
            state.metrics.inc_rpc_request("signing_event.submit", "error");
            let code = match err {
                ThresholdError::EventReplayed(_) => RpcErrorCode::EventReplayed,
                ThresholdError::InsufficientUTXOs => RpcErrorCode::InsufficientFunds,
                ThresholdError::AmountTooLow { .. }
                | ThresholdError::AmountTooHigh { .. }
                | ThresholdError::VelocityLimitExceeded { .. }
                | ThresholdError::DestinationNotAllowed(_)
                | ThresholdError::MemoRequired => RpcErrorCode::PolicyViolation,
                _ => RpcErrorCode::SigningFailed,
            };
            warn!("rpc signing_event.submit failed code={} error={}", code as i64, err);
            json_err(id, code, err.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::metrics::Metrics;
    use async_trait::async_trait;
    use futures_util::stream;
    use igra_core::application::validation::NoopVerifier;
    use igra_core::application::EventContext;
    use igra_core::application::{GroupPolicy, TwoPhaseConfig};
    use igra_core::foundation::{GroupId, PeerId, ThresholdError};
    use igra_core::infrastructure::config::ServiceConfig;
    use igra_core::infrastructure::keys::{LocalKeyManager, NoopAuditLogger, SecretBytes, SecretName, SecretStore};
    use igra_core::infrastructure::rpc::KaspaGrpcQueryClient;
    use igra_core::infrastructure::rpc::UnimplementedRpc;
    use igra_core::infrastructure::storage::phase::PhaseStorage;
    use igra_core::infrastructure::storage::RocksStorage;
    use igra_core::infrastructure::transport::iroh::traits::{StateSyncRequest, StateSyncResponse, Transport, TransportSubscription};
    use std::sync::Arc;
    use tempfile::TempDir;

    struct NoopTransport;
    struct EmptySecretStore;

    impl SecretStore for EmptySecretStore {
        fn backend(&self) -> &'static str {
            "empty"
        }

        fn get<'a>(
            &'a self,
            name: &'a SecretName,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<SecretBytes, ThresholdError>> + Send + 'a>> {
            Box::pin(async move { Err(ThresholdError::secret_not_found(name.as_str(), "empty")) })
        }

        fn list_secrets<'a>(
            &'a self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<SecretName>, ThresholdError>> + Send + 'a>> {
            Box::pin(async move { Ok(Vec::new()) })
        }
    }

    #[async_trait]
    impl Transport for NoopTransport {
        async fn publish_event_state(
            &self,
            _broadcast: igra_core::infrastructure::transport::iroh::traits::EventStateBroadcast,
        ) -> Result<(), ThresholdError> {
            Ok(())
        }

        async fn publish_proposal(&self, _proposal: igra_core::application::ProposalBroadcast) -> Result<(), ThresholdError> {
            Ok(())
        }

        async fn publish_state_sync_request(&self, _request: StateSyncRequest) -> Result<(), ThresholdError> {
            Ok(())
        }

        async fn publish_state_sync_response(&self, _response: StateSyncResponse) -> Result<(), ThresholdError> {
            Ok(())
        }

        async fn subscribe_group(&self, _group_id: GroupId) -> Result<TransportSubscription, ThresholdError> {
            Ok(TransportSubscription::new(Box::pin(stream::empty())))
        }
    }

    fn dummy_state() -> RpcState {
        let temp_dir = TempDir::new().expect("temp dir");
        let dir_path = temp_dir.into_path();
        let storage = Arc::new(RocksStorage::open_in_dir(&dir_path).expect("storage"));
        let phase_storage: Arc<dyn PhaseStorage> = storage.clone();
        let key_audit_log = Arc::new(NoopAuditLogger);
        let key_manager = Arc::new(LocalKeyManager::new(Arc::new(EmptySecretStore), key_audit_log.clone()));
        let ctx = EventContext {
            config: ServiceConfig::default(),
            policy: GroupPolicy::default(),
            two_phase: TwoPhaseConfig::default(),
            local_peer_id: PeerId::from("test-peer"),
            message_verifier: Arc::new(NoopVerifier),
            storage,
            phase_storage,
            transport: Arc::new(NoopTransport),
            rpc: Arc::new(UnimplementedRpc::new()),
            key_manager,
            key_audit_log,
        };
        RpcState {
            event_ctx: ctx,
            rpc_token: None,
            node_rpc_url: "grpc://127.0.0.1:16110".to_string(),
            kaspa_query: Arc::new(KaspaGrpcQueryClient::unimplemented()),
            metrics: Arc::new(Metrics::new().expect("metrics")),
            rate_limiter: Arc::new(crate::api::RateLimiter::new()),
            hyperlane_ism: None,
            group_id_hex: None,
            coordinator_peer_id: "test-peer".to_string(),
            rate_limit_rps: 30,
            rate_limit_burst: 60,
            session_expiry_seconds: 600,
            hyperlane_mailbox_wait_seconds: 10,
        }
    }

    #[tokio::test]
    async fn signing_event_submit_missing_params_returns_invalid_params() {
        let state = dummy_state();
        let value = handle_signing_event_submit(&state, serde_json::json!(1), None).await;
        assert_eq!(value["error"]["code"], RpcErrorCode::InvalidParams as i64);
    }
}
