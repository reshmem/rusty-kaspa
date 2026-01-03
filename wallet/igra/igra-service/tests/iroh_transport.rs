mod iroh_tests {
    use igra_core::model::{EventSource, Hash32, SigningEvent};
    use igra_core::storage::rocks::RocksStorage;
    use igra_core::transport::identity::{Ed25519Signer, StaticEd25519Verifier};
    use igra_core::transport::{ProposedSigningSession, Transport};
    use igra_core::types::{PeerId, RequestId, SessionId};
    use igra_service::transport::iroh::{IrohConfig, IrohTransport};
    use iroh::discovery::static_provider::StaticProvider;
    use iroh::RelayMode;
    use iroh_gossip::proto::TopicId;
    use std::collections::BTreeMap;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::time::{timeout, Duration};

    fn group_topic_id(group_id: &Hash32, network_id: u8) -> Hash32 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kaspa-sign/v1");
        hasher.update(&[network_id]);
        hasher.update(group_id);
        *hasher.finalize().as_bytes()
    }

    #[tokio::test]
    async fn iroh_transport_receives_published_proposal() {
        let discovery = StaticProvider::new();
        let endpoint_a = iroh::Endpoint::builder()
            .discovery(discovery.clone())
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .expect("bind endpoint A");
        let endpoint_b = iroh::Endpoint::builder()
            .discovery(discovery.clone())
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .expect("bind endpoint B");
        discovery.add_endpoint_info(endpoint_a.addr());
        discovery.add_endpoint_info(endpoint_b.addr());
        let gossip_a = iroh_gossip::net::Gossip::builder().spawn(endpoint_a.clone());
        let gossip_b = iroh_gossip::net::Gossip::builder().spawn(endpoint_b.clone());
        let _router_a = iroh::protocol::Router::builder(endpoint_a.clone())
            .accept(iroh_gossip::net::GOSSIP_ALPN, gossip_a.clone())
            .spawn();
        let _router_b = iroh::protocol::Router::builder(endpoint_b.clone())
            .accept(iroh_gossip::net::GOSSIP_ALPN, gossip_b.clone())
            .spawn();
        let _conn_a = match endpoint_a.connect(endpoint_b.addr(), iroh_gossip::net::GOSSIP_ALPN).await {
            Ok(conn) => conn,
            Err(err) => {
                eprintln!("skipping: connect A->B failed: {err}");
                return;
            }
        };
        let _conn_b = match endpoint_b.connect(endpoint_a.addr(), iroh_gossip::net::GOSSIP_ALPN).await {
            Ok(conn) => conn,
            Err(err) => {
                eprintln!("skipping: connect B->A failed: {err}");
                return;
            }
        };
        let group_id = [9u8; 32];
        let topic_id = TopicId::from(group_topic_id(&group_id, 0));
        let _warm_a = match timeout(Duration::from_secs(5), gossip_a.subscribe_and_join(topic_id, vec![endpoint_b.id()])).await
        {
            Ok(Ok(topic)) => topic,
            Ok(Err(err)) => {
                eprintln!("skipping: join A failed: {err}");
                return;
            }
            Err(_) => {
                eprintln!("skipping: join A timed out");
                return;
            }
        };
        let _warm_b = match timeout(Duration::from_secs(5), gossip_b.subscribe_and_join(topic_id, vec![endpoint_a.id()])).await
        {
            Ok(Ok(topic)) => topic,
            Ok(Err(err)) => {
                eprintln!("skipping: join B failed: {err}");
                return;
            }
            Err(_) => {
                eprintln!("skipping: join B timed out");
                return;
            }
        };

        let peer_id = PeerId::from("peer-1");
        let signer = Arc::new(Ed25519Signer::from_seed(peer_id.clone(), [7u8; 32]));
        let signer_key = signer.verifying_key();
        let mut keys = HashMap::new();
        keys.insert(peer_id.clone(), signer_key);
        let verifier = Arc::new(StaticEd25519Verifier::new(keys));

        let config_a = IrohConfig {
            network_id: 0,
            group_id,
            bootstrap_nodes: vec![endpoint_b.id().to_string()],
        };
        let config_b = IrohConfig {
            network_id: 0,
            group_id,
            bootstrap_nodes: vec![endpoint_a.id().to_string()],
        };

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let storage_a = Arc::new(RocksStorage::open_in_dir(temp_dir.path().join("a")).expect("rocksdb open a"));
        let storage_b = Arc::new(RocksStorage::open_in_dir(temp_dir.path().join("b")).expect("rocksdb open b"));
        let transport_a = IrohTransport::new(gossip_a, signer, verifier, storage_a, config_a).expect("create transport A");

        let peer_id_b = PeerId::from("peer-2");
        let signer_b = Arc::new(Ed25519Signer::from_seed(peer_id_b.clone(), [8u8; 32]));
        let mut keys_b = HashMap::new();
        keys_b.insert(peer_id.clone(), signer_key);
        keys_b.insert(peer_id_b.clone(), signer_b.verifying_key());
        let verifier_b = Arc::new(StaticEd25519Verifier::new(keys_b));
        let transport_b = IrohTransport::new(gossip_b, signer_b, verifier_b, storage_b, config_b).expect("create transport B");

        let signing_event = SigningEvent {
            event_id: "event-1".to_string(),
            event_source: EventSource::Manual { operator: "test".to_string() },
            derivation_path: "m/45'/111111'/0'/0/0".to_string(),
            derivation_index: Some(0),
            destination_address: "kaspatest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs7p4x9".to_string(),
            amount_sompi: 1234,
            metadata: BTreeMap::new(),
            timestamp_nanos: 0,
            signature: None,
        };

        let session_id = SessionId::from([1u8; 32]);
        let proposal = ProposedSigningSession {
            request_id: RequestId::from("request-1"),
            session_id,
            signing_event,
            event_hash: [2u8; 32],
            validation_hash: [3u8; 32],
            coordinator_peer_id: peer_id.clone(),
            expires_at_nanos: 0,
            kpsbt_blob: Vec::new(),
        };

        let mut subscription = transport_b.subscribe_group(group_id).await.expect("subscribe group");
        tokio::time::sleep(Duration::from_millis(500)).await;
        transport_a.publish_proposal(proposal).await.expect("publish proposal");

        let received = timeout(Duration::from_secs(5), subscription.next())
            .await
            .expect("timeout waiting for proposal")
            .expect("subscription closed")
            .expect("proposal envelope error");

        assert_eq!(received.session_id, session_id);
    }
}
