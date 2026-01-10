use super::types::{json_err, json_ok, RpcErrorCode};
use crate::api::state::RpcState;
use igra_core::application::{submit_signing_event, SigningEventParams};
use igra_core::foundation::ThresholdError;
use tracing::{debug, info, warn};

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
            warn!(error = %err, "rpc signing_event.submit invalid params");
            return json_err(id, RpcErrorCode::InvalidParams, err.to_string());
        }
    };

    debug!(
        request_id = %params.request_id,
        session_id = %params.session_id_hex,
        event_id = %params.signing_event.event_id,
        expires_at_nanos = params.expires_at_nanos,
        "rpc signing_event.submit parsed"
    );

    match submit_signing_event(&state.event_ctx, params).await {
        Ok(result) => {
            state.metrics.inc_rpc_request("signing_event.submit", "ok");
            info!(
                session_id = %result.session_id_hex,
                event_hash = %result.event_hash_hex,
                validation_hash = %result.validation_hash_hex,
                "rpc signing_event.submit ok"
            );
            json_ok(id, result)
        }
        Err(err) => {
            state.metrics.inc_rpc_request("signing_event.submit", "error");
            let code = match err {
                ThresholdError::EventReplayed(_) => RpcErrorCode::EventReplayed,
                ThresholdError::AmountTooLow { .. }
                | ThresholdError::AmountTooHigh { .. }
                | ThresholdError::VelocityLimitExceeded { .. }
                | ThresholdError::DestinationNotAllowed(_)
                | ThresholdError::MemoRequired => RpcErrorCode::PolicyViolation,
                _ => RpcErrorCode::SigningFailed,
            };
            warn!(code = code as i64, error = %err, "rpc signing_event.submit failed");
            json_err(id, code, err.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::metrics::Metrics;
    use async_trait::async_trait;
    use igra_core::application::{EventContext, EventProcessor};
    use igra_core::domain::validation::NoopVerifier;
    use igra_core::domain::SigningEvent;
    use igra_core::foundation::{Hash32, PeerId, RequestId, SessionId};
    use igra_core::infrastructure::config::ServiceConfig;
    use igra_core::infrastructure::storage::RocksStorage;
    use igra_core::ThresholdError;
    use std::sync::Arc;
    use tempfile::TempDir;

    struct NoopProcessor;

    #[async_trait]
    impl EventProcessor for NoopProcessor {
        async fn handle_signing_event(
            &self,
            _config: &ServiceConfig,
            _session_id: SessionId,
            _request_id: RequestId,
            _signing_event: SigningEvent,
            _expires_at_nanos: u64,
            _coordinator_peer_id: PeerId,
        ) -> Result<Hash32, ThresholdError> {
            Ok([0u8; 32])
        }
    }

    fn dummy_state() -> RpcState {
        let temp_dir = TempDir::new().expect("temp dir");
        let dir_path = temp_dir.into_path();
        let storage = Arc::new(RocksStorage::open_in_dir(&dir_path).expect("storage"));
        let ctx = EventContext {
            processor: Arc::new(NoopProcessor),
            config: ServiceConfig::default(),
            message_verifier: Arc::new(NoopVerifier),
            storage,
        };
        RpcState {
            event_ctx: ctx,
            rpc_token: None,
            node_rpc_url: "grpc://127.0.0.1:16110".to_string(),
            metrics: Arc::new(Metrics::new().expect("metrics")),
            rate_limiter: Arc::new(crate::api::RateLimiter::new()),
            hyperlane_ism: None,
            group_id_hex: None,
            coordinator_peer_id: "test-peer".to_string(),
            hyperlane_default_derivation_path: "m/45h/111111h/0h/0/0".to_string(),
            rate_limit_rps: 30,
            rate_limit_burst: 60,
            session_expiry_seconds: 600,
        }
    }

    #[tokio::test]
    async fn signing_event_submit_missing_params_returns_invalid_params() {
        let state = dummy_state();
        let value = handle_signing_event_submit(&state, serde_json::json!(1), None).await;
        assert_eq!(value["error"]["code"], RpcErrorCode::InvalidParams as i64);
    }
}
