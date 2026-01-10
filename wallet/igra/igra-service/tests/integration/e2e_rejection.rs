//! End-to-end rejection and policy scenarios.

use crate::harness::{env_lock, TestKeyGenerator};
use igra_core::domain::hashes::{event_hash, validation_hash};
use igra_core::application::signer::ProposalValidationRequestBuilder;
use igra_core::application::Signer;
use igra_core::domain::pskt::multisig::{build_pskt, input_hashes, serialize_pskt, tx_template_hash, MultisigInput, MultisigOutput};
use igra_core::domain::{EventSource, GroupPolicy, RequestDecision, SigningEvent, SigningRequest};
use igra_core::foundation::{PeerId, RequestId, SessionId, TransactionId as RequestTransactionId};
use igra_core::infrastructure::storage::{RocksStorage, Storage};
use igra_core::infrastructure::transport::mock::{MockHub, MockTransport};
use igra_core::ThresholdError;
use kaspa_consensus_core::tx::{TransactionId as KaspaTransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::standard::{multisig_redeem_script, pay_to_script_hash_script};
use std::collections::BTreeMap;
use std::sync::Arc;
use tempfile::TempDir;

fn build_pskt_blob(redeem_script: &[u8], amount: u64) -> (Vec<u8>, [u8; 32], Vec<[u8; 32]>) {
    let spk = pay_to_script_hash_script(redeem_script);
    let input = MultisigInput {
        utxo_entry: UtxoEntry::new(amount + 1_000, spk, 0, false),
        previous_outpoint: TransactionOutpoint::new(KaspaTransactionId::from_slice(&[7u8; 32]), 0),
        redeem_script: redeem_script.to_vec(),
        sig_op_count: 2,
    };
    let output = MultisigOutput { amount, script_public_key: kaspa_consensus_core::tx::ScriptPublicKey::from_vec(0, vec![1, 2, 3]) };
    let pskt = build_pskt(&[input], &[output]).expect("pskt");
    let pskt_blob = serialize_pskt(&pskt).expect("serialize pskt");
    let signer_pskt = pskt.signer();
    let tx_hash = tx_template_hash(&signer_pskt).expect("tx hash");
    let per_input = input_hashes(&signer_pskt).expect("input hashes");
    (pskt_blob, tx_hash, per_input)
}

fn build_event(amount: u64, timestamp_nanos: u64) -> SigningEvent {
    SigningEvent {
        event_id: format!("volume-{}", timestamp_nanos),
        event_source: EventSource::Api { issuer: "integration-tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3".to_string(),
        amount_sompi: amount,
        metadata: BTreeMap::new(),
        timestamp_nanos,
        signature: None,
    }
}

#[tokio::test]
async fn test_daily_volume_limit_with_reset() -> Result<(), ThresholdError> {
    let _guard = env_lock();
    let nanos_per_day = 24u64 * 60 * 60 * 1_000_000_000;
    let day1 = 1_700_000_000_000_000_000u64;
    std::env::set_var("KASPA_IGRA_TEST_NOW_NANOS", day1.to_string());

    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let hub = Arc::new(MockHub::new());
    let transport = Arc::new(MockTransport::new(hub, PeerId::from("signer-1"), [3u8; 32], 0));
    let signer = Signer::new(transport, storage.clone());
    let expiry_day1 = day1 + 10 * 60 * 1_000_000_000;

    let keygen = TestKeyGenerator::new("volume-limit");
    let kp1 = keygen.generate_kaspa_keypair_full(1);
    let kp2 = keygen.generate_kaspa_keypair_full(2);
    let (x1, _) = kp1.public_key().x_only_public_key();
    let (x2, _) = kp2.public_key().x_only_public_key();
    let redeem_script = multisig_redeem_script([x1.serialize(), x2.serialize()].iter(), 2).expect("redeem");

    let policy = GroupPolicy { max_daily_volume_sompi: Some(100_000_000_000), ..Default::default() };

    for idx in 0..5u64 {
        let event = build_event(20_000_000_000, day1 + idx);
        let ev_hash = event_hash(&event)?;
        storage.insert_event(ev_hash, event)?;
        storage.insert_request(SigningRequest {
            request_id: RequestId::from(format!("req-{}", idx)),
            session_id: SessionId::from([idx as u8; 32]),
            event_hash: ev_hash,
            coordinator_peer_id: PeerId::from("peer-1"),
            tx_template_hash: [0u8; 32],
            validation_hash: [0u8; 32],
            decision: RequestDecision::Finalized,
            expires_at_nanos: expiry_day1,
            final_tx_id: Some(RequestTransactionId::from([1u8; 32])),
            final_tx_accepted_blue_score: None,
        })?;
    }

    let total = storage.get_volume_since(day1)?;
    assert_eq!(total, 100_000_000_000, "expected 100 KAS accounted for day1, got {}", total);

    let event_exceed = build_event(1_000_000_000, day1 + 10);
    let ev_hash = event_hash(&event_exceed)?;
    let (pskt_blob, tx_hash, per_input) = build_pskt_blob(&redeem_script, event_exceed.amount_sompi);
    let val_hash = validation_hash(&ev_hash, &tx_hash, &per_input);
    let ack = signer
        .validate_proposal(
            ProposalValidationRequestBuilder::new(RequestId::from("req-exceed"), SessionId::from([9u8; 32]), event_exceed)
                .expected_group_id([1u8; 32])
                .proposal_group_id([1u8; 32])
                .expected_event_hash(ev_hash)
                .kpsbt_blob(&pskt_blob)
                .tx_template_hash(tx_hash)
                .expected_validation_hash(val_hash)
                .coordinator_peer_id(PeerId::from("peer-1"))
                .expires_at_nanos(expiry_day1)
                .policy(Some(&policy))
                .build()
                .expect("build request"),
            &PeerId::from("signer-1"),
        )
        .expect("ack");
    assert!(!ack.accept, "expected rejection due to daily volume limit, got ack={:?}", ack);
    assert!(
        ack.reason.clone().unwrap_or_default().contains("daily volume exceeded"),
        "expected daily volume limit error, got {:?}",
        ack.reason
    );

    let day2 = day1 + nanos_per_day + 1;
    std::env::set_var("KASPA_IGRA_TEST_NOW_NANOS", day2.to_string());
    let expiry_day2 = day2 + 10 * 60 * 1_000_000_000;

    let event_ok = build_event(20_000_000_000, day2 + 5);
    let ev_hash_ok = event_hash(&event_ok)?;
    let (pskt_blob_ok, tx_hash_ok, per_input_ok) = build_pskt_blob(&redeem_script, event_ok.amount_sompi);
    let val_hash_ok = validation_hash(&ev_hash_ok, &tx_hash_ok, &per_input_ok);
    let ack_ok = signer
        .validate_proposal(
            ProposalValidationRequestBuilder::new(RequestId::from("req-ok"), SessionId::from([10u8; 32]), event_ok)
                .expected_group_id([1u8; 32])
                .proposal_group_id([1u8; 32])
                .expected_event_hash(ev_hash_ok)
                .kpsbt_blob(&pskt_blob_ok)
                .tx_template_hash(tx_hash_ok)
                .expected_validation_hash(val_hash_ok)
                .coordinator_peer_id(PeerId::from("peer-1"))
                .expires_at_nanos(expiry_day2)
                .policy(Some(&policy))
                .build()
                .expect("build request"),
            &PeerId::from("signer-1"),
        )
        .expect("ack");
    assert!(ack_ok.accept, "expected acceptance after daily reset");

    std::env::remove_var("KASPA_IGRA_TEST_NOW_NANOS");
    Ok(())
}

mod legacy_core_event_validation {
    use async_trait::async_trait;
    use igra_core::infrastructure::config::ServiceConfig;
    use igra_core::domain::hashes::event_hash_without_signature;
    use igra_core::application::{submit_signing_event, EventContext, EventProcessor, SigningEventParams, SigningEventWire};
    use igra_core::domain::{EventSource, SigningEvent};
    use igra_core::domain::validation::{CompositeVerifier, NoopVerifier};
    use igra_core::foundation::{Hash32, PeerId, RequestId, SessionId};
    use igra_core::infrastructure::storage::RocksStorage;
    use secp256k1::{Message, Secp256k1, SecretKey};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tempfile::TempDir;

    struct DummyProcessor;

    #[async_trait]
    impl EventProcessor for DummyProcessor {
        async fn handle_signing_event(
            &self,
            _config: &ServiceConfig,
            _session_id: SessionId,
            _request_id: RequestId,
            _signing_event: SigningEvent,
            _expires_at_nanos: u64,
            _coordinator_peer_id: PeerId,
        ) -> Result<Hash32, igra_core::ThresholdError> {
            Ok([0u8; 32])
        }
    }

    fn base_wire_event(event_source: EventSource) -> SigningEventWire {
        SigningEventWire {
            event_id: "event-1".to_string(),
            event_source,
            derivation_path: "m/45'/111111'/0'/0/0".to_string(),
            derivation_index: Some(0),
            destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
            amount_sompi: 123,
            metadata: BTreeMap::new(),
            timestamp_nanos: 1,
            signature_hex: None,
            signature: None,
        }
    }

    #[tokio::test]
    async fn test_event_validation_when_hyperlane_without_validators_then_rejects() {
        let temp_dir = TempDir::new().expect("temp dir");
        let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
        let ctx = EventContext {
            processor: Arc::new(DummyProcessor),
            config: ServiceConfig::default(),
            message_verifier: Arc::new(CompositeVerifier::new(Vec::new(), Vec::new())),
            storage,
        };

        let params = SigningEventParams {
            session_id_hex: hex::encode([1u8; 32]),
            request_id: "req-1".to_string(),
            coordinator_peer_id: "peer-1".to_string(),
            expires_at_nanos: 0,
            signing_event: base_wire_event(EventSource::Hyperlane { domain: "test".to_string(), sender: "sender".to_string() }),
        };

        let err = submit_signing_event(&ctx, params).await.expect_err("should fail");
        assert!(err.to_string().contains("hyperlane validators"));
    }

    #[tokio::test]
    async fn test_event_validation_when_layerzero_without_validators_then_rejects() {
        let temp_dir = TempDir::new().expect("temp dir");
        let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
        let ctx = EventContext {
            processor: Arc::new(DummyProcessor),
            config: ServiceConfig::default(),
            message_verifier: Arc::new(CompositeVerifier::new(Vec::new(), Vec::new())),
            storage,
        };

        let params = SigningEventParams {
            session_id_hex: hex::encode([2u8; 32]),
            request_id: "req-2".to_string(),
            coordinator_peer_id: "peer-1".to_string(),
            expires_at_nanos: 0,
            signing_event: base_wire_event(EventSource::LayerZero { endpoint: "endpoint".to_string(), sender: "sender".to_string() }),
        };

        let err = submit_signing_event(&ctx, params).await.expect_err("should fail");
        assert!(err.to_string().contains("layerzero endpoint"));
    }

    #[tokio::test]
    async fn test_event_validation_when_layerzero_signature_matches_then_accepts() {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[7u8; 32]).expect("secret key");
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);

        let mut signing_event = SigningEvent {
            event_id: "event-3".to_string(),
            event_source: EventSource::LayerZero { endpoint: "endpoint".to_string(), sender: "sender".to_string() },
            derivation_path: "m/45'/111111'/0'/0/0".to_string(),
            derivation_index: Some(0),
            destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
            amount_sompi: 123,
            metadata: BTreeMap::new(),
            timestamp_nanos: 1,
            signature: None,
        };

        let digest = event_hash_without_signature(&signing_event).expect("hash");
        let message = Message::from_digest_slice(&digest).expect("message");
        let sig = secp.sign_ecdsa(&message, &secret).serialize_compact().to_vec();
        signing_event.signature = Some(sig.clone());

        let temp_dir = TempDir::new().expect("temp dir");
        let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
        let ctx = EventContext {
            processor: Arc::new(DummyProcessor),
            config: ServiceConfig::default(),
            message_verifier: Arc::new(CompositeVerifier::new(Vec::new(), vec![pubkey])),
            storage,
        };

        let params = SigningEventParams {
            session_id_hex: hex::encode([3u8; 32]),
            request_id: "req-3".to_string(),
            coordinator_peer_id: "peer-1".to_string(),
            expires_at_nanos: 0,
            signing_event: SigningEventWire {
                event_id: signing_event.event_id.clone(),
                event_source: signing_event.event_source.clone(),
                derivation_path: signing_event.derivation_path.clone(),
                derivation_index: signing_event.derivation_index,
                destination_address: signing_event.destination_address.clone(),
                amount_sompi: signing_event.amount_sompi,
                metadata: signing_event.metadata.clone(),
                timestamp_nanos: signing_event.timestamp_nanos,
                signature_hex: None,
                signature: Some(sig),
            },
        };

        let result = submit_signing_event(&ctx, params).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_event_validation_when_derivation_index_mismatch_then_rejects() {
        let temp_dir = TempDir::new().expect("temp dir");
        let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
        let ctx = EventContext {
            processor: Arc::new(DummyProcessor),
            config: ServiceConfig::default(),
            message_verifier: Arc::new(NoopVerifier::default()),
            storage,
        };

        let mut wire = base_wire_event(EventSource::Api { issuer: "tests".to_string() });
        wire.derivation_path = "m/45'/111111'/0'/0/1".to_string();
        wire.derivation_index = Some(0);

        let params = SigningEventParams {
            session_id_hex: hex::encode([4u8; 32]),
            request_id: "req-4".to_string(),
            coordinator_peer_id: "peer-1".to_string(),
            expires_at_nanos: 0,
            signing_event: wire,
        };

        let err = submit_signing_event(&ctx, params).await.expect_err("should fail");
        assert!(err.to_string().contains("derivation_path"));
    }
}

mod legacy_core_policy_enforcement {
    use igra_core::application::signer::{ProposalValidationRequestBuilder, Signer};
    use igra_core::domain::hashes::{event_hash, validation_hash};
    use igra_core::domain::{EventSource, GroupPolicy, RequestDecision, SigningEvent, SigningRequest};
    use igra_core::domain::pskt::multisig::{build_pskt, deserialize_pskt_signer, serialize_pskt, MultisigInput, MultisigOutput};
    use igra_core::foundation::{PeerId, RequestId, SessionId, TransactionId as RequestTransactionId};
    use igra_core::infrastructure::storage::{RocksStorage, Storage};
    use igra_core::infrastructure::transport::mock::{MockHub, MockTransport};
    use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionId as KaspaTransactionId, TransactionOutpoint, UtxoEntry};
    use kaspa_txscript::standard::multisig_redeem_script;
    use secp256k1::{Keypair, Secp256k1, SecretKey};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn test_keypair(seed: u8) -> Keypair {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[seed; 32]).expect("secret key");
        Keypair::from_secret_key(&secp, &secret)
    }

    fn build_test_pskt() -> Vec<u8> {
        let kp1 = test_keypair(1);
        let kp2 = test_keypair(2);
        let (x1, _) = kp1.public_key().x_only_public_key();
        let (x2, _) = kp2.public_key().x_only_public_key();
        let redeem = multisig_redeem_script([x1.serialize(), x2.serialize()].iter(), 2).expect("redeem");
        let spk = kaspa_txscript::standard::pay_to_script_hash_script(&redeem);
        let tx_id = KaspaTransactionId::from_slice(&[9u8; 32]);
        let input = MultisigInput {
            utxo_entry: UtxoEntry::new(10_000, spk, 0, false),
            previous_outpoint: TransactionOutpoint::new(tx_id, 0),
            redeem_script: redeem.clone(),
            sig_op_count: 2,
        };
        let output = MultisigOutput { amount: 9_000, script_public_key: ScriptPublicKey::from_vec(0, vec![1, 2, 3]) };
        let pskt = build_pskt(&[input], &[output]).expect("pskt");
        serialize_pskt(&pskt).expect("serialize")
    }

    fn test_event(amount: u64, reason: Option<&str>) -> SigningEvent {
        let mut metadata = BTreeMap::new();
        if let Some(reason) = reason {
            metadata.insert("reason".to_string(), reason.to_string());
        }
        SigningEvent {
            event_id: "event-1".to_string(),
            event_source: EventSource::Api { issuer: "tests".to_string() },
            derivation_path: "m/45'/111111'/0'/0/0".to_string(),
            derivation_index: Some(0),
            destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
            amount_sompi: amount,
            metadata,
            timestamp_nanos: 1,
            signature: None,
        }
    }

    #[test]
    fn test_policy_enforcement_when_require_reason_and_missing_then_rejects() {
        let temp_dir = TempDir::new().expect("temp dir");
        let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
        let hub = Arc::new(MockHub::new());
        let transport = Arc::new(MockTransport::new(hub, PeerId::from("peer-1"), [1u8; 32], 0));
        let signer = Signer::new(transport, storage.clone());

        let pskt_blob = build_test_pskt();
        let signer_pskt = deserialize_pskt_signer(&pskt_blob).expect("signer pskt");
        let tx_hash = igra_core::domain::pskt::multisig::tx_template_hash(&signer_pskt).expect("tx hash");
        let per_input = igra_core::domain::pskt::multisig::input_hashes(&signer_pskt).expect("input hashes");

        let event = test_event(100, None);
        let ev_hash = event_hash(&event).expect("event hash");
        let val_hash = validation_hash(&ev_hash, &tx_hash, &per_input);

        let policy = GroupPolicy {
            allowed_destinations: Vec::new(),
            min_amount_sompi: None,
            max_amount_sompi: None,
            max_daily_volume_sompi: None,
            require_reason: true,
        };

        let request_id = RequestId::from("req-1");
        let ack = signer
            .validate_proposal(
                ProposalValidationRequestBuilder::new(request_id.clone(), SessionId::from([2u8; 32]), event)
                    .expected_group_id([1u8; 32])
                    .proposal_group_id([1u8; 32])
                    .expected_event_hash(ev_hash)
                    .kpsbt_blob(&pskt_blob)
                    .tx_template_hash(tx_hash)
                    .expected_validation_hash(val_hash)
                    .coordinator_peer_id(PeerId::from("peer-1"))
                    .expires_at_nanos(0)
                    .policy(Some(&policy))
                    .build()
                    .expect("build request"),
                &PeerId::from("signer-1"),
            )
            .expect("ack");

        assert!(!ack.accept);
    }

    #[test]
    fn test_policy_enforcement_when_daily_volume_exceeded_then_rejects() {
        let temp_dir = TempDir::new().expect("temp dir");
        let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
        let hub = Arc::new(MockHub::new());
        let transport = Arc::new(MockTransport::new(hub, PeerId::from("peer-1"), [1u8; 32], 0));
        let signer = Signer::new(transport, storage.clone());

        let existing = test_event(80, Some("prior"));
        let existing_hash = event_hash(&existing).expect("hash");
        storage.insert_event(existing_hash, existing).expect("insert event");
        storage
            .insert_request(SigningRequest {
                request_id: RequestId::from("req-prev"),
                session_id: SessionId::from([1u8; 32]),
                event_hash: existing_hash,
                coordinator_peer_id: PeerId::from("peer-1"),
                tx_template_hash: [1u8; 32],
                validation_hash: [2u8; 32],
                decision: RequestDecision::Finalized,
                expires_at_nanos: 0,
                final_tx_id: Some(RequestTransactionId::from([3u8; 32])),
                final_tx_accepted_blue_score: None,
            })
            .expect("insert request");

        let pskt_blob = build_test_pskt();
        let signer_pskt = deserialize_pskt_signer(&pskt_blob).expect("signer pskt");
        let tx_hash = igra_core::domain::pskt::multisig::tx_template_hash(&signer_pskt).expect("tx hash");
        let per_input = igra_core::domain::pskt::multisig::input_hashes(&signer_pskt).expect("input hashes");

        let event = test_event(50, Some("new"));
        let ev_hash = event_hash(&event).expect("event hash");
        let val_hash = validation_hash(&ev_hash, &tx_hash, &per_input);

        let policy = GroupPolicy {
            allowed_destinations: Vec::new(),
            min_amount_sompi: None,
            max_amount_sompi: None,
            max_daily_volume_sompi: Some(100),
            require_reason: false,
        };

        let request_id = RequestId::from("req-1");
        let ack = signer
            .validate_proposal(
                ProposalValidationRequestBuilder::new(request_id, SessionId::from([2u8; 32]), event)
                    .expected_group_id([1u8; 32])
                    .proposal_group_id([1u8; 32])
                    .expected_event_hash(ev_hash)
                    .kpsbt_blob(&pskt_blob)
                    .tx_template_hash(tx_hash)
                    .expected_validation_hash(val_hash)
                    .coordinator_peer_id(PeerId::from("peer-1"))
                    .expires_at_nanos(0)
                    .policy(Some(&policy))
                    .build()
                    .expect("build request"),
                &PeerId::from("signer-1"),
            )
            .expect("ack");

        assert!(!ack.accept);
    }
}

mod legacy_core_policy_rejection_disallowed_destination {
    use igra_core::application::signer::{ProposalValidationRequestBuilder, Signer};
    use igra_core::domain::hashes::{event_hash, validation_hash};
    use igra_core::domain::{EventSource, GroupPolicy, SigningEvent};
    use igra_core::domain::pskt::multisig::{build_pskt, deserialize_pskt_signer, serialize_pskt, MultisigInput, MultisigOutput};
    use igra_core::infrastructure::storage::RocksStorage;
    use igra_core::infrastructure::transport::mock::{MockHub, MockTransport};
    use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionId, TransactionOutpoint, UtxoEntry};
    use kaspa_txscript::standard::multisig_redeem_script;
    use secp256k1::{Keypair, Secp256k1, SecretKey};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tempfile::TempDir;
    use igra_core::foundation::{PeerId, SessionId};

    fn test_keypair(seed: u8) -> Keypair {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[seed; 32]).expect("secret key");
        Keypair::from_secret_key(&secp, &secret)
    }

    fn build_test_pskt() -> Vec<u8> {
        let kp1 = test_keypair(1);
        let kp2 = test_keypair(2);
        let (x1, _) = kp1.public_key().x_only_public_key();
        let (x2, _) = kp2.public_key().x_only_public_key();
        let redeem = multisig_redeem_script([x1.serialize(), x2.serialize()].iter(), 2).expect("redeem");
        let spk = kaspa_txscript::standard::pay_to_script_hash_script(&redeem);
        let tx_id = TransactionId::from_slice(&[9u8; 32]);
        let input = MultisigInput {
            utxo_entry: UtxoEntry::new(10_000, spk, 0, false),
            previous_outpoint: TransactionOutpoint::new(tx_id, 0),
            redeem_script: redeem.clone(),
            sig_op_count: 2,
        };
        let output = MultisigOutput { amount: 9_000, script_public_key: ScriptPublicKey::from_vec(0, vec![1, 2, 3]) };
        let pskt = build_pskt(&[input], &[output]).expect("pskt");
        serialize_pskt(&pskt).expect("serialize")
    }

    fn test_event(destination: &str, amount: u64) -> SigningEvent {
        SigningEvent {
            event_id: "event-1".to_string(),
            event_source: EventSource::Api { issuer: "tests".to_string() },
            derivation_path: "m/45'/111111'/0'/0/0".to_string(),
            derivation_index: Some(0),
            destination_address: destination.to_string(),
            amount_sompi: amount,
            metadata: BTreeMap::new(),
            timestamp_nanos: 1,
            signature: None,
        }
    }

    #[test]
    fn test_policy_enforcement_when_destination_not_allowed_then_rejects() {
        let temp_dir = TempDir::new().expect("temp dir");
        let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
        let hub = Arc::new(MockHub::new());
        let transport = Arc::new(MockTransport::new(hub, PeerId::from("peer-1"), [1u8; 32], 0));
        let signer = Signer::new(transport, storage);

        let pskt_blob = build_test_pskt();
        let signer_pskt = deserialize_pskt_signer(&pskt_blob).expect("signer pskt");
        let tx_hash = igra_core::domain::pskt::multisig::tx_template_hash(&signer_pskt).expect("tx hash");
        let per_input = igra_core::domain::pskt::multisig::input_hashes(&signer_pskt).expect("input hashes");

        let event = test_event("kaspatest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs7p4x9", 100);
        let ev_hash = event_hash(&event).expect("event hash");
        let val_hash = validation_hash(&ev_hash, &tx_hash, &per_input);

        let policy = GroupPolicy {
            allowed_destinations: vec!["kaspatest:allowed".to_string()],
            min_amount_sompi: None,
            max_amount_sompi: None,
            max_daily_volume_sompi: None,
            require_reason: false,
        };

        let ack = signer
            .validate_proposal(
                ProposalValidationRequestBuilder::new("req-1".into(), SessionId::from([2u8; 32]), event)
                    .expected_group_id([1u8; 32])
                    .proposal_group_id([1u8; 32])
                    .expected_event_hash(ev_hash)
                    .kpsbt_blob(&pskt_blob)
                    .tx_template_hash(tx_hash)
                    .expected_validation_hash(val_hash)
                    .coordinator_peer_id(PeerId::from("peer-1"))
                    .expires_at_nanos(0)
                    .policy(Some(&policy))
                    .build()
                    .expect("build request"),
                &PeerId::from("signer-1"),
            )
            .expect("ack");

        assert!(!ack.accept);
    }
}
