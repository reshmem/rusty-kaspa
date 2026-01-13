use igra_core::application::{submit_signing_event, EventContext, SigningEventParams, SigningEventWire};
use igra_core::domain::validation::NoopVerifier;
use igra_core::domain::{EventSource, GroupPolicy};
use igra_core::foundation::{Hash32, PeerId, ThresholdError};
use igra_core::infrastructure::config::{AppConfig, PsktBuildConfig, PsktHdConfig, ServiceConfig};
use igra_core::infrastructure::rpc::{UnimplementedRpc, UtxoWithOutpoint};
use igra_core::infrastructure::storage::memory::MemoryStorage;
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::transport::mock::{MockHub, MockTransport};
use igra_service::service::coordination::run_coordination_loop;
use igra_service::service::flow::ServiceFlow;
use kaspa_bip32::{Language, Mnemonic};
use kaspa_consensus_core::tx::{TransactionId as KaspaTransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::standard::pay_to_script_hash_script;
use kaspa_wallet_core::encryption::{Encryptable, EncryptionKind};
use kaspa_wallet_core::prelude::Secret;
use kaspa_wallet_core::storage::keydata::PrvKeyData;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Once;
use std::time::Duration;

const WALLET_SECRET: &str = "test-wallet-secret";

fn ensure_wallet_secret() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        std::env::set_var("KASPA_IGRA_WALLET_SECRET", WALLET_SECRET);
    });
}

fn prv_key_data_from_mnemonic(phrase: &str) -> PrvKeyData {
    let mnemonic = Mnemonic::new(phrase, Language::English).expect("mnemonic");
    PrvKeyData::try_new_from_mnemonic(mnemonic, None, EncryptionKind::XChaCha20Poly1305).expect("prv key data")
}

fn hd_config_for_signer(all_key_data: &[PrvKeyData], local_index: usize, required_sigs: usize) -> PsktHdConfig {
    let wallet_secret = Secret::from(WALLET_SECRET);

    let mut ordered = Vec::with_capacity(all_key_data.len());
    ordered.push(all_key_data[local_index].clone());
    for (idx, kd) in all_key_data.iter().enumerate() {
        if idx != local_index {
            ordered.push(kd.clone());
        }
    }

    let encrypted = Encryptable::from(ordered)
        .into_encrypted(&wallet_secret, EncryptionKind::XChaCha20Poly1305)
        .expect("encrypt mnemonics");

    PsktHdConfig {
        mnemonics: Vec::new(),
        encrypted_mnemonics: Some(encrypted),
        xpubs: Vec::new(),
        required_sigs,
        passphrase: None,
    }
}

fn build_config(redeem_script_hex: String) -> AppConfig {
    let mut service = ServiceConfig::default();
    service.pskt = PsktBuildConfig {
        node_rpc_url: String::new(),
        source_addresses: Vec::new(),
        redeem_script_hex,
        sig_op_count: 2,
        outputs: Vec::new(),
        fee_payment_mode: Default::default(),
        fee_sompi: Some(1_000),
        change_address: Some("kaspadev:qp5mxzzk5gush9k2zv0pjhj3cmpq9n8nemljasdzxsqjr4x2dc6wc0225vqpw".to_string()),
    };

    AppConfig {
        service,
        policy: GroupPolicy::default(),
        iroh: igra_core::infrastructure::config::IrohRuntimeConfig { network_id: 2, ..Default::default() },
        ..Default::default()
    }
}

fn signing_event(event_id: &str) -> SigningEventWire {
    SigningEventWire {
        event_id: event_id.to_string(),
        event_source: EventSource::Api { issuer: "tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspadev:qp5mxzzk5gush9k2zv0pjhj3cmpq9n8nemljasdzxsqjr4x2dc6wc0225vqpw".to_string(),
        amount_sompi: 10_000_000,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature_hex: None,
        signature: None,
    }
}

#[tokio::test]
async fn crdt_three_signer_converges_and_completes() -> Result<(), ThresholdError> {
    ensure_wallet_secret();

    let group_id: Hash32 = [9u8; 32];
    let hub = Arc::new(MockHub::new());

    // Key material for 3 signers.
    let mnemonics = [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    ];
    let key_data = mnemonics.iter().map(|m| prv_key_data_from_mnemonic(m)).collect::<Vec<_>>();

    let pubkeys = key_data
        .iter()
        .map(|kd| {
            igra_core::foundation::hd::derive_keypair_from_key_data(kd, "m/45'/111111'/0'/0/0", None)
                .expect("derive keypair")
                .public_key()
        })
        .collect::<Vec<_>>();
    let redeem = igra_core::foundation::redeem_script_from_pubkeys(&pubkeys, 2)?;
    let redeem_script_hex = hex::encode(redeem.clone());

    let rpc = Arc::new(UnimplementedRpc::new());
    let spk = pay_to_script_hash_script(&redeem);
    rpc.push_utxo(UtxoWithOutpoint {
        address: None,
        outpoint: TransactionOutpoint::new(KaspaTransactionId::from_slice(&[7u8; 32]), 0),
        entry: UtxoEntry::new(100_000_000, spk, 0, false),
    });

    let transports = [
        Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-1"), group_id, 2)),
        Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-2"), group_id, 2)),
        Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-3"), group_id, 2)),
    ];

    let storages = [
        Arc::new(MemoryStorage::new()) as Arc<dyn Storage>,
        Arc::new(MemoryStorage::new()) as Arc<dyn Storage>,
        Arc::new(MemoryStorage::new()) as Arc<dyn Storage>,
    ];

    let mut configs = Vec::new();
    for i in 0..3usize {
        let mut app = build_config(redeem_script_hex.clone());
        app.service.hd = Some(hd_config_for_signer(&key_data, i, 2));
        configs.push(Arc::new(app));
    }

    let flows = [
        Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storages[0].clone(), transports[0].clone())?),
        Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storages[1].clone(), transports[1].clone())?),
        Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storages[2].clone(), transports[2].clone())?),
    ];

    let loops = [
        tokio::spawn(run_coordination_loop(configs[0].clone(), flows[0].clone(), transports[0].clone(), storages[0].clone(), PeerId::from("signer-1"), group_id)),
        tokio::spawn(run_coordination_loop(configs[1].clone(), flows[1].clone(), transports[1].clone(), storages[1].clone(), PeerId::from("signer-2"), group_id)),
        tokio::spawn(run_coordination_loop(configs[2].clone(), flows[2].clone(), transports[2].clone(), storages[2].clone(), PeerId::from("signer-3"), group_id)),
    ];

    // Ingest the same event on all 3 nodes (as if each had its own watcher).
    for i in 0..3usize {
        let ctx = EventContext {
            config: configs[i].service.clone(),
            policy: configs[i].policy.clone(),
            local_peer_id: PeerId::from(format!("signer-{}", i + 1)),
            message_verifier: Arc::new(NoopVerifier),
            storage: storages[i].clone(),
            transport: transports[i].clone(),
            rpc: rpc.clone(),
        };

        let params = SigningEventParams {
            session_id_hex: hex::encode([1u8; 32]),
            request_id: format!("req-{}", i + 1),
            coordinator_peer_id: format!("signer-{}", i + 1),
            expires_at_nanos: 0,
            signing_event: signing_event("event-1"),
        };

        submit_signing_event(&ctx, params).await?;
    }

    // Wait for a completion record to appear on all nodes.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if tokio::time::Instant::now() > deadline {
            return Err(ThresholdError::Message("timeout waiting for CRDT completion".to_string()));
        }
        let mut completed = 0usize;
        for storage in &storages {
            let pending = storage.list_pending_event_crdts()?;
            if pending.is_empty() {
                completed += 1;
            }
        }
        if completed == 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Stop loops.
    for handle in loops {
        handle.abort();
    }
    Ok(())
}
