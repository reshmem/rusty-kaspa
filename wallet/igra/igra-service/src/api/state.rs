use crate::api::RateLimiter;
use crate::service::metrics::Metrics;
use igra_core::application::EventContext;
use igra_core::infrastructure::hyperlane::ConfiguredIsm;
use igra_core::infrastructure::rpc::KaspaGrpcQueryClient;
use std::sync::Arc;

#[derive(Clone)]
pub struct RpcState {
    pub event_ctx: EventContext,
    pub rpc_token: Option<String>,
    pub node_rpc_url: String,
    pub kaspa_query: Arc<KaspaGrpcQueryClient>,
    pub metrics: Arc<Metrics>,
    pub rate_limiter: Arc<RateLimiter>,
    pub hyperlane_ism: Option<ConfiguredIsm>,
    pub group_id_hex: Option<String>,
    pub coordinator_peer_id: String,
    pub rate_limit_rps: u32,
    pub rate_limit_burst: u32,
    pub session_expiry_seconds: u64,
    pub hyperlane_mailbox_wait_seconds: u64,
}
