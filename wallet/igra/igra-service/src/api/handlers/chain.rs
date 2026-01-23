use crate::api::middleware::auth::authorize_rpc;
use crate::api::state::RpcState;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use kaspa_addresses::Address;
use kaspa_consensus_core::tx::ScriptPublicKey;
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Serialize)]
pub struct ChainInfoResponse {
    pub virtual_daa_score: u64,
    pub past_median_time: u64,
    pub pruning_point_hash: String,
    pub network_name: String,
    pub is_synced: bool,
}

#[derive(Debug, Serialize)]
pub struct BlockInfoResponse {
    pub hash: String,
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
    pub tx_id: String,
    pub hash: String,
    pub block_hash: Option<String>,
    pub daa_score: Option<u64>,
    pub timestamp: Option<u64>,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

#[derive(Debug, Serialize)]
pub struct TxInput {
    pub previous_outpoint_hash: String,
    pub previous_outpoint_index: u32,
    pub signature_script: String,
}

#[derive(Debug, Serialize)]
pub struct TxOutput {
    pub value: u64,
    pub script_public_key: String,
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
        pruning_point_hash: format!("0x{}", hex::encode(dag.pruning_point_hash.as_bytes())),
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
        hash: format!("0x{}", hex::encode(block.header.hash.as_bytes())),
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

    let tx_id = match crate::util::hex::parse_kaspa_tx_id_hex(&hash_hex) {
        Ok(id) => id,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };

    let entry = match state.kaspa_query.get_mempool_entry(tx_id).await {
        Ok(entry) => entry,
        Err(err) => return (StatusCode::NOT_FOUND, err.to_string()).into_response(),
    };

    let inputs = entry
        .transaction
        .inputs
        .iter()
        .map(|input| TxInput {
            previous_outpoint_hash: format!("0x{}", hex::encode(input.previous_outpoint.transaction_id.as_bytes())),
            previous_outpoint_index: input.previous_outpoint.index,
            signature_script: format!("0x{}", hex::encode(&input.signature_script)),
        })
        .collect::<Vec<_>>();
    let outputs = entry
        .transaction
        .outputs
        .iter()
        .map(|output| TxOutput {
            value: output.value,
            script_public_key: format!("0x{}", format_script_public_key(&output.script_public_key)),
        })
        .collect::<Vec<_>>();

    Json(TransactionInfoResponse {
        tx_id: format!("0x{}", hex::encode(tx_id.as_bytes())),
        hash: format!("0x{}", hex::encode(tx_id.as_bytes())),
        block_hash: None,
        daa_score: None,
        timestamp: None,
        inputs,
        outputs,
    })
    .into_response()
}

fn format_script_public_key(spk: &ScriptPublicKey) -> String {
    let ver = hex::encode(spk.version().to_be_bytes());
    let script = hex::encode(spk.script());
    format!("{ver}{script}")
}
