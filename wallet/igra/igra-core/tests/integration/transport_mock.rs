use igra_core::domain::{EventSource, SigningEvent};
use igra_core::foundation::{PeerId, RequestId, SessionId};
use igra_core::infrastructure::transport::iroh::mock::{MockHub, MockTransport};
use igra_core::infrastructure::transport::iroh::traits::{Transport, TransportMessage};
use std::collections::BTreeMap;
use std::sync::Arc;

fn sample_event() -> SigningEvent {
    SigningEvent {
        event_id: "event-1".to_string(),
        event_source: EventSource::Api { issuer: "tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
        amount_sompi: 1,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature: None,
    }
}

#[tokio::test]
async fn test_transport_mock_when_proposal_published_then_subscriber_receives() {
    let hub = Arc::new(MockHub::new());
    let group_id = [7u8; 32];
    let transport = Arc::new(MockTransport::new(hub.clone(), PeerId::from("peer-1"), group_id, 0));

    let mut sub = transport.subscribe_group(group_id).await.expect("subscribe group");

    transport
        .publish_proposal(igra_core::infrastructure::transport::iroh::traits::ProposedSigningSession {
            request_id: RequestId::from("req-1"),
            session_id: SessionId::from([1u8; 32]),
            signing_event: sample_event(),
            event_hash: [2u8; 32],
            validation_hash: [3u8; 32],
            coordinator_peer_id: PeerId::from("peer-1"),
            expires_at_nanos: 0,
            kpsbt_blob: vec![1, 2, 3],
        })
        .await
        .expect("publish");

    let envelope = sub.next().await.expect("next").expect("envelope");
    match envelope.payload {
        TransportMessage::SigningEventPropose(p) => {
            assert_eq!(p.request_id, RequestId::from("req-1"));
        }
        _ => panic!("expected SigningEventPropose"),
    }
}
