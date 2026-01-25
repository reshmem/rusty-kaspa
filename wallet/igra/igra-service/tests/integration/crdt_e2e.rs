use igra_core::application::{submit_signing_event, EventContext, SigningEventParams, SigningEventWire};
use igra_core::domain::coordination::TwoPhaseConfig;
use igra_core::domain::validation::NoopVerifier;
use igra_core::domain::{GroupPolicy, SourceType};
use igra_core::foundation::{EventId, GroupId, PeerId, ThresholdError};
use igra_core::infrastructure::config::KeyType;
use igra_core::infrastructure::config::{AppConfig, PsktBuildConfig, PsktHdConfig, ServiceConfig};
use igra_core::infrastructure::keys::{KeyAuditLogger, KeyManager};
use igra_core::infrastructure::rpc::{KaspaGrpcQueryClient, UnimplementedRpc, UtxoWithOutpoint};
use igra_core::infrastructure::storage::memory::MemoryStorage;
use igra_core::infrastructure::storage::phase::PhaseStorage;
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::transport::mock::{MockHub, MockTransport};
use igra_service::service::coordination::run_coordination_loop;
use igra_service::service::flow::ServiceFlow;
use kaspa_bip32::{Language, Mnemonic};
use kaspa_consensus_core::tx::{TransactionId as KaspaTransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::standard::pay_to_script_hash_script;
use kaspa_wallet_core::encryption::EncryptionKind;
use kaspa_wallet_core::storage::keydata::PrvKeyData;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use super::helpers::key_manager_with_signer_mnemonic;

const LOOP_STARTUP_GRACE: Duration = Duration::from_millis(50);

/// Timeout for waiting for event completion in tests (seconds).
const TEST_COMPLETION_TIMEOUT_SECS: u64 = 3;

/// CRDT GC interval for tests (seconds) - much shorter than production default.
const TEST_CRDT_GC_INTERVAL_SECS: u64 = 5;

/// CRDT GC TTL for tests (seconds) - keep events for short time.
const TEST_CRDT_GC_TTL_SECS: u64 = 60;

/// Short delay for checking completion status in tests (milliseconds).
const TEST_COMPLETION_CHECK_DELAY_MS: u64 = 100;

fn prv_key_data_from_mnemonic(phrase: &str) -> PrvKeyData {
    let mnemonic = Mnemonic::new(phrase, Language::English).expect("mnemonic");
    PrvKeyData::try_from_mnemonic(mnemonic, None, EncryptionKind::XChaCha20Poly1305, None).expect("prv key data")
}

fn hd_config_for_signer(required_sigs: usize) -> PsktHdConfig {
    PsktHdConfig {
        key_type: KeyType::HdMnemonic,
        xpubs: Vec::new(),
        required_sigs,
        derivation_path: Some("m/45'/111111'/0'/0/0".to_string()),
    }
}

fn build_config(redeem_script_hex: String) -> AppConfig {
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

    AppConfig {
        service,
        policy: GroupPolicy::default(),
        iroh: igra_core::infrastructure::config::IrohRuntimeConfig { network_id: 2, ..Default::default() },
        runtime: igra_core::infrastructure::config::RuntimeConfig {
            crdt_gc_interval_seconds: Some(TEST_CRDT_GC_INTERVAL_SECS),
            crdt_gc_ttl_seconds: Some(TEST_CRDT_GC_TTL_SECS),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn signing_event(label: &str) -> SigningEventWire {
    let external_id = hex::encode(blake3::hash(label.as_bytes()).as_bytes());
    SigningEventWire {
        external_id,
        source: SourceType::Api,
        destination_address: "kaspadev:qp5mxzzk5gush9k2zv0pjhj3cmpq9n8nemljasdzxsqjr4x2dc6wc0225vqpw".to_string(),
        amount_sompi: 25_000_000,
        metadata: BTreeMap::new(),
        proof_hex: None,
        proof: None,
    }
}

#[tokio::test]
async fn crdt_three_signer_converges_and_completes() -> Result<(), ThresholdError> {
    let group_id = GroupId::new([9u8; 32]);
    let hub = Arc::new(MockHub::new());

    // Key material for 3 signers.
    let mnemonics = [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    ];
    let key_data = mnemonics.iter().map(|m| prv_key_data_from_mnemonic(m)).collect::<Vec<_>>();

    let mut indexed_pubkeys = key_data
        .iter()
        .enumerate()
        .map(|(idx, kd)| {
            let pubkey = igra_core::foundation::hd::derive_keypair_from_key_data(kd, Some("m/45'/111111'/0'/0/0"), None)
                .expect("derive keypair")
                .public_key();
            (idx, pubkey)
        })
        .collect::<Vec<_>>();
    indexed_pubkeys.sort_by_key(|(_, pk)| pk.serialize());
    let ordered_pubkeys = indexed_pubkeys.iter().map(|(_, pk)| *pk).collect::<Vec<_>>();
    let redeem = igra_core::foundation::redeem_script_from_pubkeys(&ordered_pubkeys, 2)?;
    let redeem_script_hex = hex::encode(redeem.clone());

    let mut profiles_by_signer = vec![String::new(); mnemonics.len()];
    for (pos, (idx, _)) in indexed_pubkeys.iter().enumerate() {
        profiles_by_signer[*idx] = format!("signer-{:02}", pos + 1);
    }

    let rpc = Arc::new(UnimplementedRpc::new());
    let spk = pay_to_script_hash_script(&redeem);
    rpc.push_utxo(UtxoWithOutpoint {
        address: None,
        outpoint: TransactionOutpoint::new(KaspaTransactionId::from_slice(&[7u8; 32]), 0),
        entry: UtxoEntry::new(100_000_000, spk, 0, false),
    });

    let transports = [
        Arc::new(MockTransport::new(hub.clone(), PeerId::from(profiles_by_signer[0].clone()), group_id, 2)),
        Arc::new(MockTransport::new(hub.clone(), PeerId::from(profiles_by_signer[1].clone()), group_id, 2)),
        Arc::new(MockTransport::new(hub.clone(), PeerId::from(profiles_by_signer[2].clone()), group_id, 2)),
    ];

    let stores = [Arc::new(MemoryStorage::new()), Arc::new(MemoryStorage::new()), Arc::new(MemoryStorage::new())];
    let storages: [Arc<dyn Storage>; 3] = [stores[0].clone(), stores[1].clone(), stores[2].clone()];
    let phase_storages: [Arc<dyn PhaseStorage>; 3] = [stores[0].clone(), stores[1].clone(), stores[2].clone()];

    let mut configs = Vec::new();
    for i in 0..3usize {
        let mut app = build_config(redeem_script_hex.clone());
        app.service.active_profile = Some(profiles_by_signer[i].clone());
        app.service.hd = Some(hd_config_for_signer(2));
        configs.push(Arc::new(app));
    }

    let kaspa_query = Arc::new(KaspaGrpcQueryClient::unimplemented());
    let (key_manager_0, key_audit_log_0): (Arc<dyn KeyManager>, Arc<dyn KeyAuditLogger>) =
        key_manager_with_signer_mnemonic(&profiles_by_signer[0], mnemonics[0]);
    let (key_manager_1, key_audit_log_1): (Arc<dyn KeyManager>, Arc<dyn KeyAuditLogger>) =
        key_manager_with_signer_mnemonic(&profiles_by_signer[1], mnemonics[1]);
    let (key_manager_2, key_audit_log_2): (Arc<dyn KeyManager>, Arc<dyn KeyAuditLogger>) =
        key_manager_with_signer_mnemonic(&profiles_by_signer[2], mnemonics[2]);
    let key_managers: [Arc<dyn KeyManager>; 3] = [key_manager_0.clone(), key_manager_1.clone(), key_manager_2.clone()];
    let key_audit_logs: [Arc<dyn KeyAuditLogger>; 3] = [key_audit_log_0.clone(), key_audit_log_1.clone(), key_audit_log_2.clone()];
    let flows = [
        Arc::new(ServiceFlow::new_with_rpc(
            key_manager_0.clone(),
            key_audit_log_0.clone(),
            rpc.clone(),
            kaspa_query.clone(),
            storages[0].clone(),
            transports[0].clone(),
            Arc::new(NoopVerifier),
        )?),
        Arc::new(ServiceFlow::new_with_rpc(
            key_manager_1.clone(),
            key_audit_log_1.clone(),
            rpc.clone(),
            kaspa_query.clone(),
            storages[1].clone(),
            transports[1].clone(),
            Arc::new(NoopVerifier),
        )?),
        Arc::new(ServiceFlow::new_with_rpc(
            key_manager_2.clone(),
            key_audit_log_2.clone(),
            rpc.clone(),
            kaspa_query.clone(),
            storages[2].clone(),
            transports[2].clone(),
            Arc::new(NoopVerifier),
        )?),
    ];

    let two_phase = TwoPhaseConfig { commit_quorum: 2, min_input_score_depth: 0, ..TwoPhaseConfig::default() };

    let loops = [
        tokio::spawn(run_coordination_loop(
            configs[0].clone(),
            two_phase.clone(),
            flows[0].clone(),
            transports[0].clone(),
            storages[0].clone(),
            phase_storages[0].clone(),
            PeerId::from(profiles_by_signer[0].clone()),
            group_id,
        )),
        tokio::spawn(run_coordination_loop(
            configs[1].clone(),
            two_phase.clone(),
            flows[1].clone(),
            transports[1].clone(),
            storages[1].clone(),
            phase_storages[1].clone(),
            PeerId::from(profiles_by_signer[1].clone()),
            group_id,
        )),
        tokio::spawn(run_coordination_loop(
            configs[2].clone(),
            two_phase.clone(),
            flows[2].clone(),
            transports[2].clone(),
            storages[2].clone(),
            phase_storages[2].clone(),
            PeerId::from(profiles_by_signer[2].clone()),
            group_id,
        )),
    ];

    tokio::time::sleep(LOOP_STARTUP_GRACE).await;

    // Ingest the same event on all 3 nodes (as if each had its own watcher).
    let mut event_id_hex = None;
    for i in 0..3usize {
        let local_profile = profiles_by_signer[i].clone();
        let ctx = EventContext {
            config: configs[i].service.clone(),
            policy: configs[i].policy.clone(),
            two_phase: two_phase.clone(),
            local_peer_id: PeerId::from(local_profile.clone()),
            message_verifier: Arc::new(NoopVerifier),
            storage: storages[i].clone(),
            phase_storage: phase_storages[i].clone(),
            transport: transports[i].clone(),
            rpc: rpc.clone(),
            key_manager: key_managers[i].clone(),
            key_audit_log: key_audit_logs[i].clone(),
        };

        let params = SigningEventParams {
            session_id_hex: hex::encode([1u8; 32]),
            external_request_id: Some(format!("req-{}", i + 1)),
            coordinator_peer_id: local_profile,
            expires_at_nanos: 0,
            event: signing_event("event-1"),
        };

        let result = submit_signing_event(&ctx, params).await?;
        event_id_hex.get_or_insert(result.event_id_hex);
    }

    let event_id_hex = event_id_hex.expect("event id");
    let event_id_bytes = hex::decode(event_id_hex).expect("event_id_hex");
    let event_id = EventId::new(event_id_bytes.as_slice().try_into().expect("hash32"));

    // Wait for a completion record to appear on all nodes.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(TEST_COMPLETION_TIMEOUT_SECS);
    loop {
        if tokio::time::Instant::now() > deadline {
            return Err(ThresholdError::Message("timeout waiting for CRDT completion".to_string()));
        }

        let mut done = true;
        for storage in &storages {
            if storage.get_event_completion(&event_id)?.is_none() {
                done = false;
                break;
            }
        }
        if done {
            break;
        }
        tokio::time::sleep(Duration::from_millis(TEST_COMPLETION_CHECK_DELAY_MS)).await;
    }

    // Stop loops.
    for handle in loops {
        handle.abort();
    }
    Ok(())
}
