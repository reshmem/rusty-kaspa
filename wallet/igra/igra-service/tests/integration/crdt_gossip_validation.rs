use igra_core::domain::coordination::{EventPhase, PhaseContext};
use igra_core::domain::validation::{MessageVerifier, ValidationSource, VerificationReport};
use igra_core::domain::{CrdtSigningMaterial, Event, EventAuditData, SourceType, StoredEvent};
use igra_core::foundation::{Hash32, PeerId, ThresholdError};
use igra_core::infrastructure::config::{AppConfig, PsktBuildConfig, ServiceConfig};
use igra_core::infrastructure::rpc::{UnimplementedRpc, UtxoWithOutpoint};
use igra_core::infrastructure::storage::memory::MemoryStorage;
use igra_core::infrastructure::storage::phase::PhaseStorage;
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::transport::iroh::mock::{MockHub, MockTransport};
use igra_core::infrastructure::transport::iroh::traits::Transport;
use igra_core::infrastructure::transport::messages::{EventCrdtState, EventStateBroadcast};
use igra_service::service::coordination::handle_crdt_broadcast;
use igra_service::service::flow::ServiceFlow;
use kaspa_consensus_core::tx::{TransactionId as KaspaTransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::standard::pay_to_script_hash_script;
use secp256k1::SecretKey;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Clone)]
struct DenyAllVerifier;

impl MessageVerifier for DenyAllVerifier {
    fn verify(&self, _event: &StoredEvent) -> Result<VerificationReport, ThresholdError> {
        Ok(VerificationReport {
            source: ValidationSource::Hyperlane,
            validator_count: 1,
            valid: false,
            valid_signatures: 0,
            threshold_required: 1,
            failure_reason: Some("denied".to_string()),
            event_id: None,
        })
    }

    fn report_for(&self, _event: &StoredEvent) -> VerificationReport {
        VerificationReport {
            source: ValidationSource::Hyperlane,
            validator_count: 1,
            valid: false,
            valid_signatures: 0,
            threshold_required: 1,
            failure_reason: None,
            event_id: None,
        }
    }
}

#[derive(Clone)]
struct AllowAllVerifier;

impl MessageVerifier for AllowAllVerifier {
    fn verify(&self, _event: &StoredEvent) -> Result<VerificationReport, ThresholdError> {
        Ok(VerificationReport {
            source: ValidationSource::Hyperlane,
            validator_count: 1,
            valid: true,
            valid_signatures: 1,
            threshold_required: 1,
            failure_reason: None,
            event_id: None,
        })
    }

    fn report_for(&self, _event: &StoredEvent) -> VerificationReport {
        VerificationReport {
            source: ValidationSource::Hyperlane,
            validator_count: 1,
            valid: true,
            valid_signatures: 1,
            threshold_required: 1,
            failure_reason: None,
            event_id: None,
        }
    }
}

fn minimal_material() -> CrdtSigningMaterial {
    let redeem = vec![1u8, 2, 3];
    let destination = pay_to_script_hash_script(&redeem);
    CrdtSigningMaterial {
        event: Event {
            external_id: [9u8; 32],
            source: SourceType::Hyperlane { origin_domain: 1 },
            destination,
            amount_sompi: 25_000_000,
        },
        audit: EventAuditData {
            external_id_raw: "0x00".to_string(),
            destination_raw: "kaspadev:qp5mxzzk5gush9k2zv0pjhj3cmpq9n8nemljasdzxsqjr4x2dc6wc0225vqpw".to_string(),
            source_data: BTreeMap::new(),
        },
        proof: Some(vec![1, 2, 3]),
    }
}

#[tokio::test]
async fn gossip_rejects_invalid_source_proof() -> Result<(), ThresholdError> {
    let group_id: Hash32 = [7u8; 32];
    let hub = Arc::new(MockHub::new());
    let transport: Arc<dyn Transport> = Arc::new(MockTransport::new(hub, PeerId::from("signer-1"), group_id, 2));
    let store = Arc::new(MemoryStorage::new());
    let storage: Arc<dyn Storage> = store.clone();
    let phase_storage: Arc<dyn PhaseStorage> = store.clone();
    let rpc = Arc::new(UnimplementedRpc::new());
    let flow = ServiceFlow::new_with_rpc(rpc, storage.clone(), transport.clone(), Arc::new(DenyAllVerifier))?;

    let material = minimal_material();
    let event_id = igra_core::domain::hashes::compute_event_id(&material.event);
    let tx_template_hash: Hash32 = [2u8; 32];
    let broadcast = EventStateBroadcast {
        event_id,
        tx_template_hash,
        sender_peer_id: PeerId::from("attacker"),
        state: EventCrdtState { signatures: vec![], completion: None, signing_material: Some(material), kpsbt_blob: None, version: 0 },
        phase_context: Some(PhaseContext { round: 0, phase: EventPhase::Committed }),
    };

    let err = handle_crdt_broadcast(
        &AppConfig::default(),
        &flow,
        &transport,
        &storage,
        &phase_storage,
        &PeerId::from("signer-1"),
        broadcast,
    )
    .await
    .expect_err("should reject invalid proof");
    assert!(matches!(err, ThresholdError::EventSignatureInvalid));

    assert!(storage.get_event_crdt(&event_id, &tx_template_hash)?.is_none());
    Ok(())
}

#[tokio::test]
async fn gossip_rejects_tx_template_hash_mismatch() -> Result<(), ThresholdError> {
    let group_id: Hash32 = [7u8; 32];
    let hub = Arc::new(MockHub::new());
    let transport: Arc<dyn Transport> = Arc::new(MockTransport::new(hub, PeerId::from("signer-1"), group_id, 2));
    let store = Arc::new(MemoryStorage::new());
    let storage: Arc<dyn Storage> = store.clone();
    let phase_storage: Arc<dyn PhaseStorage> = store.clone();

    let rpc = Arc::new(UnimplementedRpc::new());
    let secp = secp256k1::Secp256k1::new();
    let pubkeys = [
        secp256k1::PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).expect("sk1")),
        secp256k1::PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).expect("sk2")),
    ];
    let redeem = igra_core::foundation::redeem_script_from_pubkeys(&pubkeys, 2)?;
    let redeem_script_hex = hex::encode(&redeem);
    let spk = pay_to_script_hash_script(&redeem);
    rpc.push_utxo(UtxoWithOutpoint {
        address: None,
        outpoint: TransactionOutpoint::new(KaspaTransactionId::from_slice(&[7u8; 32]), 0),
        entry: UtxoEntry::new(100_000_000, spk, 0, false),
    });

    let service = ServiceConfig {
        pskt: PsktBuildConfig {
            node_rpc_url: String::new(),
            source_addresses: vec!["kaspadev:qp5mxzzk5gush9k2zv0pjhj3cmpq9n8nemljasdzxsqjr4x2dc6wc0225vqpw".to_string()],
            redeem_script_hex,
            sig_op_count: 2,
            outputs: Vec::new(),
            fee_payment_mode: Default::default(),
            fee_sompi: Some(1_000),
            change_address: Some("kaspadev:qp5mxzzk5gush9k2zv0pjhj3cmpq9n8nemljasdzxsqjr4x2dc6wc0225vqpw".to_string()),
        },
        ..Default::default()
    };
    let app_config = AppConfig { service, ..Default::default() };
    let flow = ServiceFlow::new_with_rpc(rpc, storage.clone(), transport.clone(), Arc::new(AllowAllVerifier))?;

    let material = minimal_material();
    let event_id = igra_core::domain::hashes::compute_event_id(&material.event);
    let tx_template_hash: Hash32 = [0u8; 32]; // malicious / wrong
    let broadcast = EventStateBroadcast {
        event_id,
        tx_template_hash,
        sender_peer_id: PeerId::from("attacker"),
        state: EventCrdtState { signatures: vec![], completion: None, signing_material: Some(material), kpsbt_blob: None, version: 0 },
        phase_context: Some(PhaseContext { round: 0, phase: EventPhase::Committed }),
    };

    let err = handle_crdt_broadcast(&app_config, &flow, &transport, &storage, &phase_storage, &PeerId::from("signer-1"), broadcast)
        .await
        .expect_err("should reject tx template hash mismatch");
    match err {
        ThresholdError::PsktMismatch { .. } => {}
        other => return Err(other),
    }

    assert!(storage.get_event_crdt(&event_id, &tx_template_hash)?.is_none());
    Ok(())
}
