use crate::integration_harness::mock_node::MockKaspaNode;
use crate::integration_harness::test_data::TestDataFactory;
use igra_core::error::ThresholdError;
use igra_core::storage::rocks::RocksStorage;
use igra_core::storage::Storage;
use igra_core::transport::mock::{MockHub, MockTransport};
use igra_core::types::{PeerId, RequestId};
use igra_service::service::flow::ServiceFlow;
use iroh::discovery::static_provider::StaticProvider;
use iroh::protocol::Router;
use iroh::Endpoint;
use iroh_gossip::net::Gossip;
use iroh_gossip::proto::TopicId;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

pub struct TestIrohNetwork {
    pub endpoints: Vec<Endpoint>,
    pub gossips: Vec<Gossip>,
    _routers: Vec<Router>,
}

impl TestIrohNetwork {
    pub async fn new(count: usize) -> Result<Self, ThresholdError> {
        let discovery = StaticProvider::new();
        let mut endpoints = Vec::with_capacity(count);
        let mut gossips = Vec::with_capacity(count);
        let mut routers = Vec::with_capacity(count);

        for _ in 0..count {
            let endpoint = Endpoint::builder()
                .discovery(discovery.clone())
                .relay_mode(iroh::RelayMode::Disabled)
                .bind()
                .await
                .map_err(|err| ThresholdError::Message(err.to_string()))?;
            let gossip = Gossip::builder().spawn(endpoint.clone());
            let router =
                iroh::protocol::Router::builder(endpoint.clone()).accept(iroh_gossip::net::GOSSIP_ALPN, gossip.clone()).spawn();
            discovery.add_endpoint_info(endpoint.addr());
            endpoints.push(endpoint);
            gossips.push(gossip);
            routers.push(router);
        }

        Ok(Self { endpoints, gossips, _routers: routers })
    }

    pub async fn connect_all(&self, timeout: Duration) {
        for from in &self.endpoints {
            for to in &self.endpoints {
                if from.id() == to.id() {
                    continue;
                }
                let _ = tokio::time::timeout(timeout, from.connect(to.addr(), iroh_gossip::net::GOSSIP_ALPN)).await;
            }
        }
    }

    pub async fn join_group(&self, topic_id: TopicId, timeout: Duration) -> bool {
        for (idx, gossip) in self.gossips.iter().enumerate() {
            let peers = self
                .endpoints
                .iter()
                .enumerate()
                .filter(|(peer_idx, _)| *peer_idx != idx)
                .map(|(_, endpoint)| endpoint.id())
                .collect::<Vec<_>>();
            let joined = tokio::time::timeout(timeout, gossip.subscribe_and_join(topic_id, peers)).await;
            if joined.is_err() {
                return false;
            }
        }
        true
    }
}

pub struct TestNode {
    pub peer_id: PeerId,
    pub storage: Arc<RocksStorage>,
    pub transport: Arc<MockTransport>,
    pub flow: Arc<ServiceFlow>,
    pub config: Arc<igra_core::config::AppConfig>,
    pub is_connected: bool,
}

pub struct TestNetwork {
    pub nodes: Vec<TestNode>,
    pub rpc: Arc<MockKaspaNode>,
    pub hub: Arc<MockHub>,
    pub threshold_m: usize,
    pub threshold_n: usize,
    pub group_id: [u8; 32],
    _temp_dir: TempDir,
}

impl TestNetwork {
    pub fn new(threshold_m: usize, threshold_n: usize) -> Result<Self, ThresholdError> {
        let hub = Arc::new(MockHub::new());
        let rpc = Arc::new(MockKaspaNode::new());
        let seed = format!("test-network-{threshold_m}-{threshold_n}");
        let group_id = *blake3::hash(seed.as_bytes()).as_bytes();
        let temp_dir = TempDir::new().map_err(|err| ThresholdError::Message(err.to_string()))?;

        let mut nodes = Vec::with_capacity(threshold_n);
        for idx in 0..threshold_n {
            let peer_id = PeerId::from(format!("signer-{}", idx + 1));
            let storage = Arc::new(
                RocksStorage::open_in_dir(temp_dir.path().join(peer_id.as_str()))
                    .map_err(|err| ThresholdError::Message(err.to_string()))?,
            );
            let transport = Arc::new(MockTransport::new(hub.clone(), peer_id.clone(), group_id, 0));
            let flow = Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storage.clone(), transport.clone())?);
            let config = Arc::new(TestDataFactory::create_config_m_of_n(temp_dir.path(), threshold_m, threshold_n));
            nodes.push(TestNode { peer_id, storage, transport, flow, config, is_connected: true });
        }

        Ok(Self { nodes, rpc, hub, threshold_m, threshold_n, group_id, _temp_dir: temp_dir })
    }

    pub async fn wait_for_proposal(&self, request_id: &str, timeout: Duration) -> Result<(), ThresholdError> {
        let deadline = std::time::Instant::now() + timeout;
        let request_id = RequestId::from(request_id);
        loop {
            let mut all_have = true;
            for node in &self.nodes {
                if node.storage.get_proposal(&request_id)?.is_none() {
                    all_have = false;
                    break;
                }
            }
            if all_have {
                return Ok(());
            }
            if std::time::Instant::now() > deadline {
                return Err(ThresholdError::Message("timeout waiting for proposal".to_string()));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn wait_for_threshold(&self, request_id: &str, timeout: Duration) -> Result<(), ThresholdError> {
        let deadline = std::time::Instant::now() + timeout;
        let request_id = RequestId::from(request_id);
        loop {
            let sigs = self.nodes[0].storage.list_partial_sigs(&request_id)?;
            if sigs.len() >= self.threshold_m {
                return Ok(());
            }
            if std::time::Instant::now() > deadline {
                return Err(ThresholdError::Message(format!(
                    "timeout waiting for threshold (have {} of {})",
                    sigs.len(),
                    self.threshold_m
                )));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn wait_for_finalization(&self, request_id: &str, timeout: Duration) -> Result<(), ThresholdError> {
        let deadline = std::time::Instant::now() + timeout;
        let request_id = RequestId::from(request_id);
        loop {
            if let Some(req) = self.nodes[0].storage.get_request(&request_id)? {
                if req.final_tx_id.is_some() {
                    return Ok(());
                }
            }
            if std::time::Instant::now() > deadline {
                return Err(ThresholdError::Message("timeout waiting for finalization".to_string()));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn assert_all_nodes_have_proposal(&self, request_id: &str) {
        let request_id = RequestId::from(request_id);
        for (idx, node) in self.nodes.iter().enumerate() {
            let proposal = node.storage.get_proposal(&request_id).expect("proposal read");
            assert!(proposal.is_some(), "node {} missing proposal", idx);
        }
    }

    pub async fn assert_signatures_collected(&self, request_id: &str, expected: usize) {
        let request_id = RequestId::from(request_id);
        let sigs = self.nodes[0].storage.list_partial_sigs(&request_id).expect("partial sigs");
        assert_eq!(sigs.len(), expected, "expected {} signatures, got {}", expected, sigs.len());
    }

    pub async fn assert_transaction_finalized(&self, request_id: &str) {
        let request_id = RequestId::from(request_id);
        let req = self.nodes[0].storage.get_request(&request_id).expect("request read").expect("request missing");
        assert!(req.final_tx_id.is_some(), "transaction not finalized");
    }

    pub async fn disconnect_node(&mut self, index: usize) {
        if let Some(node) = self.nodes.get_mut(index) {
            node.is_connected = false;
        }
    }

    pub async fn reconnect_node(&mut self, index: usize) -> Result<(), ThresholdError> {
        if let Some(node) = self.nodes.get_mut(index) {
            node.is_connected = true;
        } else {
            return Err(ThresholdError::Message("node index out of bounds".to_string()));
        }
        Ok(())
    }
}
