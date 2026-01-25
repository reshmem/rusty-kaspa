use crate::api::middleware::auth::authorize_rpc;
use crate::api::state::RpcState;
use crate::api::util::serde_helpers::{serialize_bytes_with_0x_prefix, serialize_opt_bytes_with_0x_prefix, serialize_with_0x_prefix};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use kaspa_addresses::Address;
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_consensus_core::tx::TransactionId as KaspaTransactionId;
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Serialize)]
pub struct ChainInfoResponse {
    pub virtual_daa_score: u64,
    pub past_median_time: u64,
    #[serde(serialize_with = "serialize_bytes_with_0x_prefix")]
    pub pruning_point_hash: [u8; 32],
    pub network_name: String,
    pub is_synced: bool,
}

#[derive(Debug, Serialize)]
pub struct BlockInfoResponse {
    #[serde(serialize_with = "serialize_bytes_with_0x_prefix")]
    pub hash: [u8; 32],
    pub daa_score: u64,
    pub timestamp: u64,
    pub blue_score: u64,
}

#[derive(Debug, Serialize)]
pub struct BalanceResponse {
    pub balance: String,
}

#[derive(Debug, Serialize)]
pub struct TransactionInfoResponse {
    #[serde(serialize_with = "serialize_with_0x_prefix")]
    pub tx_id: igra_core::foundation::TransactionId,
    #[serde(serialize_with = "serialize_with_0x_prefix")]
    pub hash: igra_core::foundation::TransactionId,
    #[serde(serialize_with = "serialize_opt_bytes_with_0x_prefix")]
    pub block_hash: Option<[u8; 32]>,
    pub daa_score: Option<u64>,
    pub timestamp: Option<u64>,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

#[derive(Debug, Serialize)]
pub struct TxInput {
    #[serde(serialize_with = "serialize_with_0x_prefix")]
    pub previous_outpoint_hash: igra_core::foundation::TransactionId,
    pub previous_outpoint_index: u32,
    #[serde(serialize_with = "serialize_bytes_with_0x_prefix")]
    pub signature_script: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct TxOutput {
    pub value: u64,
    #[serde(serialize_with = "serialize_bytes_with_0x_prefix")]
    pub script_public_key: Vec<u8>,
}

pub async fn get_chain_info(State(state): State<Arc<RpcState>>, headers: HeaderMap) -> Response {
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        return (StatusCode::UNAUTHORIZED, err).into_response();
    }

    let server_info = match state.kaspa_query.get_server_info().await {
        Ok(info) => info,
        Err(err) => return (StatusCode::SERVICE_UNAVAILABLE, err.to_string()).into_response(),
    };
    let dag = match state.kaspa_query.get_block_dag_info().await {
        Ok(info) => info,
        Err(err) => return (StatusCode::SERVICE_UNAVAILABLE, err.to_string()).into_response(),
    };

    Json(ChainInfoResponse {
        virtual_daa_score: dag.virtual_daa_score,
        past_median_time: dag.past_median_time,
        pruning_point_hash: dag.pruning_point_hash.as_bytes(),
        network_name: server_info.network_id.to_string(),
        is_synced: server_info.is_synced,
    })
    .into_response()
}

pub async fn get_block_by_daa(State(state): State<Arc<RpcState>>, headers: HeaderMap, Path(daa_score): Path<u64>) -> Response {
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        return (StatusCode::UNAUTHORIZED, err).into_response();
    }

    let dag = match state.kaspa_query.get_block_dag_info().await {
        Ok(info) => info,
        Err(err) => return (StatusCode::SERVICE_UNAVAILABLE, err.to_string()).into_response(),
    };
    if dag.virtual_daa_score != daa_score {
        return (StatusCode::NOT_FOUND, "block lookup by historical DAA score is not supported").into_response();
    }
    let block = match state.kaspa_query.get_block(dag.sink).await {
        Ok(block) => block,
        Err(err) => return (StatusCode::SERVICE_UNAVAILABLE, err.to_string()).into_response(),
    };

    Json(BlockInfoResponse {
        hash: block.header.hash.as_bytes(),
        daa_score: block.header.daa_score,
        timestamp: block.header.timestamp,
        blue_score: block.header.blue_score,
    })
    .into_response()
}

pub async fn get_balance(State(state): State<Arc<RpcState>>, headers: HeaderMap, Path(address): Path<String>) -> Response {
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        return (StatusCode::UNAUTHORIZED, err).into_response();
    }
    let address = match Address::try_from(address.as_str()) {
        Ok(addr) => addr,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid address").into_response(),
    };
    match state.kaspa_query.get_balance_by_address(address).await {
        Ok(balance) => Json(BalanceResponse { balance: balance.to_string() }).into_response(),
        Err(err) => (StatusCode::SERVICE_UNAVAILABLE, err.to_string()).into_response(),
    }
}

pub async fn get_transaction(State(state): State<Arc<RpcState>>, headers: HeaderMap, Path(hash_hex): Path<String>) -> Response {
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        return (StatusCode::UNAUTHORIZED, err).into_response();
    }

    let tx_id_bytes = match igra_core::foundation::parse_hex_32bytes_allow_64bytes(&hash_hex) {
        Ok(bytes) => bytes,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };
    let tx_id = KaspaTransactionId::from_bytes(tx_id_bytes);

    let entry = match state.kaspa_query.get_mempool_entry(tx_id).await {
        Ok(entry) => entry,
        Err(err) => return (StatusCode::NOT_FOUND, err.to_string()).into_response(),
    };

    let inputs = entry
        .transaction
        .inputs
        .iter()
        .map(|input| TxInput {
            previous_outpoint_hash: igra_core::foundation::TransactionId::from(input.previous_outpoint.transaction_id),
            previous_outpoint_index: input.previous_outpoint.index,
            signature_script: input.signature_script.clone(),
        })
        .collect::<Vec<_>>();
    let outputs = entry
        .transaction
        .outputs
        .iter()
        .map(|output| TxOutput { value: output.value, script_public_key: script_public_key_bytes(&output.script_public_key) })
        .collect::<Vec<_>>();

    let tx_id = igra_core::foundation::TransactionId::from(tx_id);
    Json(TransactionInfoResponse { tx_id, hash: tx_id, block_hash: None, daa_score: None, timestamp: None, inputs, outputs })
        .into_response()
}

fn script_public_key_bytes(spk: &ScriptPublicKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(spk.script().len().saturating_add(2));
    out.extend_from_slice(&spk.version().to_be_bytes());
    out.extend_from_slice(spk.script());
    out
}
