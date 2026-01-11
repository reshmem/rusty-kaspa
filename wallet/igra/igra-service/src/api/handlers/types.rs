use serde::{Deserialize, Serialize};

#[repr(i64)]
#[derive(Clone, Copy, Debug)]
pub enum RpcErrorCode {
    ParseError = -32700,
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    InvalidParams = -32602,
    InternalError = -32603,
    Unauthorized = -32001,
    MissingGroupId = -32002,
    HyperlaneNotConfigured = -32003,
    UnknownDomain = -32004,
    SigningFailed = -32005,
    EventReplayed = -32006,
    PolicyViolation = -32007,
    InsufficientFunds = -32008,
}

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: Option<String>,
    pub id: serde_json::Value,
    pub method: String,
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse<T> {
    pub jsonrpc: &'static str,
    pub id: serde_json::Value,
    pub result: T,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub jsonrpc: &'static str,
    pub id: serde_json::Value,
    pub error: JsonRpcErrorBody,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcErrorBody {
    pub code: i64,
    pub message: String,
}

pub fn json_ok<T: Serialize>(id: serde_json::Value, result: T) -> serde_json::Value {
    serde_json::to_value(JsonRpcResponse { jsonrpc: "2.0", id, result }).unwrap_or(serde_json::Value::Null)
}

pub fn json_err(id: serde_json::Value, code: RpcErrorCode, message: impl Into<String>) -> serde_json::Value {
    serde_json::to_value(JsonRpcError { jsonrpc: "2.0", id, error: JsonRpcErrorBody { code: code as i64, message: message.into() } })
        .unwrap_or(serde_json::Value::Null)
}
