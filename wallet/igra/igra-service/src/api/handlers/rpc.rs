use super::hyperlane::{handle_mailbox_process, handle_validators_and_threshold};
use super::signing_event::handle_signing_event_submit;
use super::types::{json_err, RpcErrorCode, JsonRpcRequest};
use crate::api::middleware::auth::authorize_rpc;
use crate::api::state::RpcState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

pub async fn handle_rpc(State(state): State<Arc<RpcState>>, headers: HeaderMap, body: String) -> Response {
    let parsed = serde_json::from_str::<serde_json::Value>(&body);
    let Ok(value) = parsed else {
        return axum::Json(json_err(serde_json::Value::Null, RpcErrorCode::ParseError, "parse error")).into_response();
    };

    let outcome = match value {
        serde_json::Value::Array(batch) => {
            if batch.is_empty() {
                axum::Json(json_err(serde_json::Value::Null, RpcErrorCode::InvalidRequest, "empty batch")).into_response()
            } else {
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
                Err(err) => axum::Json(json_err(serde_json::Value::Null, RpcErrorCode::InvalidRequest, err.to_string())).into_response(),
            }
        }
    };

    outcome
}

async fn handle_single(state: &RpcState, headers: &HeaderMap, req: JsonRpcRequest) -> serde_json::Value {
    let id = req.id.clone();

    if let Some(version) = req.jsonrpc.as_deref() {
        if version != "2.0" {
            state.metrics.inc_rpc_request(req.method.as_str(), "invalid_request");
            return json_err(id, RpcErrorCode::InvalidRequest, "jsonrpc must be '2.0'");
        }
    }

    if let Err(err) = authorize_rpc(headers, state.rpc_token.as_deref()) {
        state.metrics.inc_rpc_request(req.method.as_str(), "unauthorized");
        return json_err(id, RpcErrorCode::Unauthorized, err);
    }

    match req.method.as_str() {
        "signing_event.submit" => handle_signing_event_submit(state, id, req.params).await,
        "hyperlane.validators_and_threshold" => handle_validators_and_threshold(state, id, req.params).await,
        "hyperlane.mailbox_process" => handle_mailbox_process(state, id, req.params).await,
        _ => {
            state.metrics.inc_rpc_request(req.method.as_str(), "not_found");
            json_err(id, RpcErrorCode::MethodNotFound, "method not found")
        }
    }
}
