use super::hyperlane::{handle_mailbox_process, handle_validators_and_threshold};
use super::events::handle_events_status;
use super::signing_event::handle_signing_event_submit;
use super::types::{json_err, JsonRpcRequest, RpcErrorCode};
use crate::api::middleware::auth::authorize_rpc;
use crate::api::state::RpcState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use log::{debug, warn};
use std::sync::Arc;
use std::time::Instant;

pub async fn handle_rpc(State(state): State<Arc<RpcState>>, headers: HeaderMap, body: String) -> Response {
    let started = Instant::now();
    let parsed = serde_json::from_str::<serde_json::Value>(&body);
    let Ok(value) = parsed else {
        debug!("rpc parse error body_len={}", body.len());
        return axum::Json(json_err(serde_json::Value::Null, RpcErrorCode::ParseError, "parse error")).into_response();
    };

    let outcome = match value {
        serde_json::Value::Array(batch) => {
            if batch.is_empty() {
                axum::Json(json_err(serde_json::Value::Null, RpcErrorCode::InvalidRequest, "empty batch")).into_response()
            } else {
                debug!("rpc batch request batch_size={}", batch.len());
                let mut out = Vec::with_capacity(batch.len());
                for item in batch {
                    let req: Result<JsonRpcRequest, _> = serde_json::from_value(item);
                    match req {
                        Ok(req) => out.push(handle_single(&state, &headers, req).await),
                        Err(err) => out.push(json_err(serde_json::Value::Null, RpcErrorCode::InvalidRequest, err.to_string())),
                    }
                }
                axum::Json(serde_json::Value::Array(out)).into_response()
            }
        }
        other => {
            let req: Result<JsonRpcRequest, _> = serde_json::from_value(other);
            match req {
                Ok(req) => axum::Json(handle_single(&state, &headers, req).await).into_response(),
                Err(err) => {
                    axum::Json(json_err(serde_json::Value::Null, RpcErrorCode::InvalidRequest, err.to_string())).into_response()
                }
            }
        }
    };

    debug!("rpc handled elapsed_ms={}", started.elapsed().as_millis());
    outcome
}

async fn handle_single(state: &RpcState, headers: &HeaderMap, req: JsonRpcRequest) -> serde_json::Value {
    let id = req.id.clone();
    let started = Instant::now();

    if let Some(version) = req.jsonrpc.as_deref() {
        if version != "2.0" {
            state.metrics.inc_rpc_request(req.method.as_str(), "invalid_request");
            debug!("invalid jsonrpc version method={}", req.method);
            return json_err(id, RpcErrorCode::InvalidRequest, "jsonrpc must be '2.0'");
        }
    }

    if let Err(err) = authorize_rpc(headers, state.rpc_token.as_deref()) {
        state.metrics.inc_rpc_request(req.method.as_str(), "unauthorized");
        warn!("unauthorized method={} error={}", req.method, err);
        return json_err(id, RpcErrorCode::Unauthorized, err);
    }

    let response = match req.method.as_str() {
        "signing_event.submit" => handle_signing_event_submit(state, id, req.params).await,
        "hyperlane.validators_and_threshold" => handle_validators_and_threshold(state, id, req.params).await,
        "hyperlane.mailbox_process" => handle_mailbox_process(state, id, req.params).await,
        "events.status" => handle_events_status(state, id, headers, req.params).await,
        _ => {
            state.metrics.inc_rpc_request(req.method.as_str(), "not_found");
            debug!("method not found method={}", req.method);
            json_err(id, RpcErrorCode::MethodNotFound, "method not found")
        }
    };

    let duration_ms = started.elapsed().as_millis();
    // Only log summary at debug level - handlers log important events at info/warn
    if response.get("error").is_some() {
        debug!("rpc error method={} duration_ms={}", req.method, duration_ms);
    } else {
        debug!("rpc ok method={} duration_ms={}", req.method, duration_ms);
    }
    response
}
