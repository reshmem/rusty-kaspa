//! Public facade for the JSON-RPC server implementation.
//! `igra_service::api::json_rpc::*` is the supported entrypoint; internals are split into modules.

pub use super::hyperlane::watcher::run_hyperlane_watcher;
pub use super::router::build_router;
pub use super::router::run_json_rpc_server;
pub use super::state::RpcState;
