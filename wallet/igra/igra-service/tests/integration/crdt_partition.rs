use async_trait::async_trait;
use igra_core::application::{submit_signing_event, EventContext, SigningEventParams, SigningEventWire};
use igra_core::domain::validation::NoopVerifier;
use igra_core::domain::{GroupPolicy, SourceType};
use igra_core::foundation::{Hash32, PeerId, ThresholdError};
use igra_core::infrastructure::config::{AppConfig, PsktBuildConfig, PsktHdConfig, ServiceConfig};
use igra_core::infrastructure::rpc::{UnimplementedRpc, UtxoWithOutpoint};
use igra_core::infrastructure::storage::memory::MemoryStorage;
use igra_core::infrastructure::storage::rocks::RocksStorage;
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::transport::iroh::traits::{Transport, TransportMessage, TransportSubscription};
use igra_core::infrastructure::transport::messages::StateSyncRequest;
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;
use tempfile::tempdir;

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

    let encrypted =
        Encryptable::from(ordered).into_encrypted(&wallet_secret, EncryptionKind::XChaCha20Poly1305).expect("encrypt mnemonics");

    PsktHdConfig {
        mnemonics: Vec::new(),
        encrypted_mnemonics: Some(encrypted),
        xpubs: Vec::new(),
        required_sigs,
        passphrase: None,
        derivation_path: Some("m/45'/111111'/0'/0/0".to_string()),
    }
}

fn build_config(redeem_script_hex: String) -> AppConfig {
    let mut service = ServiceConfig::default();
    service.pskt = PsktBuildConfig {
        node_rpc_url: String::new(),
        source_addresses: vec!["kaspadev:qp5mxzzk5gush9k2zv0pjhj3cmpq9n8nemljasdzxsqjr4x2dc6wc0225vqpw".to_string()],
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

async fn wait_for_all_complete(storages: &[Arc<dyn Storage>], timeout: Duration) -> Result<(), ThresholdError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() > deadline {
            return Err(ThresholdError::Message("timeout waiting for CRDT completion".to_string()));
        }

        let mut completed = 0usize;
        for storage in storages {
            if storage.list_pending_event_crdts()?.is_empty() {
                completed += 1;
            }
        }
        if completed == storages.len() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_complete(storage: &Arc<dyn Storage>, timeout: Duration) -> Result<(), ThresholdError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() > deadline {
            return Err(ThresholdError::Message("timeout waiting for CRDT completion".to_string()));
        }
        if storage.list_pending_event_crdts()?.is_empty() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[derive(Clone)]
struct FilteringTransport {
    inner: Arc<MockTransport>,
    local_peer_id: PeerId,
    partitioned: Arc<AtomicBool>,
    drop_broadcast_threshold: Option<u8>,
    max_delay_ms: Option<u64>,
}

impl FilteringTransport {
    fn new(inner: Arc<MockTransport>, local_peer_id: PeerId) -> Self {
        Self {
            inner,
            local_peer_id,
            partitioned: Arc::new(AtomicBool::new(false)),
            drop_broadcast_threshold: None,
            max_delay_ms: None,
        }
    }

    fn with_partition_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.partitioned = flag;
        self
    }

    fn with_drop_broadcast_threshold(mut self, threshold: u8) -> Self {
        self.drop_broadcast_threshold = Some(threshold);
        self
    }

    fn with_max_delay_ms(mut self, max_delay_ms: u64) -> Self {
        self.max_delay_ms = Some(max_delay_ms);
        self
    }
}

#[async_trait]
impl Transport for FilteringTransport {
    async fn publish_event_state(
        &self,
        broadcast: igra_core::infrastructure::transport::messages::EventStateBroadcast,
    ) -> Result<(), ThresholdError> {
        self.inner.publish_event_state(broadcast).await
    }

    async fn publish_state_sync_request(
        &self,
        request: igra_core::infrastructure::transport::messages::StateSyncRequest,
    ) -> Result<(), ThresholdError> {
        self.inner.publish_state_sync_request(request).await
    }

    async fn publish_state_sync_response(
        &self,
        response: igra_core::infrastructure::transport::messages::StateSyncResponse,
    ) -> Result<(), ThresholdError> {
        self.inner.publish_state_sync_response(response).await
    }

    async fn subscribe_group(&self, group_id: Hash32) -> Result<TransportSubscription, ThresholdError> {
        let mut subscription = self.inner.subscribe_group(group_id).await?;
        let partitioned = self.partitioned.clone();
        let local_peer_id = self.local_peer_id.clone();
        let drop_broadcast_threshold = self.drop_broadcast_threshold;
        let max_delay_ms = self.max_delay_ms;

        let stream = async_stream::stream! {
            loop {
                let Some(item) = subscription.next().await else { break; };
                match item {
                    Ok(envelope) => {
                        let is_remote = envelope.sender_peer_id != local_peer_id;
                        if is_remote && partitioned.load(Ordering::Relaxed) {
                            continue;
                        }

                        if let Some(threshold) = drop_broadcast_threshold {
                            if matches!(envelope.payload, TransportMessage::EventStateBroadcast(_)) && envelope.payload_hash[0] < threshold {
                                continue;
                            }
                        }

                        if let Some(max_ms) = max_delay_ms {
                            if is_remote {
                                let delay = (envelope.payload_hash[1] as u64) % (max_ms + 1);
                                tokio::time::sleep(Duration::from_millis(delay)).await;
                            }
                        }

                        yield Ok(envelope);
                    }
                    Err(err) => yield Err(err),
                }
            }
        };

        Ok(TransportSubscription::new(Box::pin(stream)))
    }
}

#[tokio::test]
async fn chaos_partition_recovery_via_state_sync() -> Result<(), ThresholdError> {
    ensure_wallet_secret();

    let group_id: Hash32 = [11u8; 32];
    let hub = Arc::new(MockHub::new());

    let mnemonics = [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    ];
    let key_data = mnemonics.iter().map(|m| prv_key_data_from_mnemonic(m)).collect::<Vec<_>>();

    let pubkeys = key_data
        .iter()
        .map(|kd| {
            igra_core::foundation::hd::derive_keypair_from_key_data(kd, Some("m/45'/111111'/0'/0/0"), None)
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

    let raw_transports = [
        Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-1"), group_id, 2)),
        Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-2"), group_id, 2)),
        Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-3"), group_id, 2)),
    ];

    let partitioned = Arc::new(AtomicBool::new(true));
    let transports: [Arc<dyn Transport>; 3] = [
        raw_transports[0].clone(),
        raw_transports[1].clone(),
        Arc::new(
            FilteringTransport::new(raw_transports[2].clone(), PeerId::from("signer-3")).with_partition_flag(partitioned.clone()),
        ),
    ];

    let storages: [Arc<dyn Storage>; 3] =
        [Arc::new(MemoryStorage::new()), Arc::new(MemoryStorage::new()), Arc::new(MemoryStorage::new())];

    let mut configs = Vec::new();
    for i in 0..3usize {
        let mut app = build_config(redeem_script_hex.clone());
        app.service.hd = Some(hd_config_for_signer(&key_data, i, 2));
        configs.push(Arc::new(app));
    }

    let flows = [
        Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storages[0].clone(), transports[0].clone(), Arc::new(NoopVerifier))?),
        Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storages[1].clone(), transports[1].clone(), Arc::new(NoopVerifier))?),
        Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storages[2].clone(), transports[2].clone(), Arc::new(NoopVerifier))?),
    ];

    let loops = [
        tokio::spawn(run_coordination_loop(
            configs[0].clone(),
            flows[0].clone(),
            transports[0].clone(),
            storages[0].clone(),
            PeerId::from("signer-1"),
            group_id,
        )),
        tokio::spawn(run_coordination_loop(
            configs[1].clone(),
            flows[1].clone(),
            transports[1].clone(),
            storages[1].clone(),
            PeerId::from("signer-2"),
            group_id,
        )),
        tokio::spawn(run_coordination_loop(
            configs[2].clone(),
            flows[2].clone(),
            transports[2].clone(),
            storages[2].clone(),
            PeerId::from("signer-3"),
            group_id,
        )),
    ];

    // Ingest the same event on all 3 nodes (as if each had its own watcher).
    let mut event_id_hex = None;
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
            external_request_id: Some(format!("req-{}", i + 1)),
            coordinator_peer_id: format!("signer-{}", i + 1),
            expires_at_nanos: 0,
            event: signing_event("event-partition"),
        };

        let result = submit_signing_event(&ctx, params).await?;
        event_id_hex.get_or_insert(result.event_id_hex);
    }
    let event_id_hex = event_id_hex.expect("event id");
    let event_id_bytes = hex::decode(event_id_hex).expect("event_id_hex");
    let event_id: Hash32 = event_id_bytes.as_slice().try_into().expect("hash32");

    // Nodes 1 and 2 should complete without node 3 seeing their messages.
    wait_for_all_complete(&[storages[0].clone(), storages[1].clone()], Duration::from_secs(10)).await?;
    // Node 3 is partitioned; it should still have pending work.
    assert!(!storages[2].list_pending_event_crdts()?.is_empty());

    // Heal the partition and request sync.
    partitioned.store(false, Ordering::Relaxed);
    raw_transports[2]
        .publish_state_sync_request(StateSyncRequest { event_ids: vec![event_id], requester_peer_id: PeerId::from("signer-3") })
        .await?;

    // Node 3 catches up via response merge.
    wait_for_complete(&storages[2].clone(), Duration::from_secs(10)).await?;

    for handle in loops {
        handle.abort();
    }
    Ok(())
}

#[tokio::test]
async fn chaos_random_message_loss_eventual_convergence() -> Result<(), ThresholdError> {
    ensure_wallet_secret();

    let group_id: Hash32 = [12u8; 32];
    let hub = Arc::new(MockHub::new());

    let mnemonics = [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    ];
    let key_data = mnemonics.iter().map(|m| prv_key_data_from_mnemonic(m)).collect::<Vec<_>>();

    let pubkeys = key_data
        .iter()
        .map(|kd| {
            igra_core::foundation::hd::derive_keypair_from_key_data(kd, Some("m/45'/111111'/0'/0/0"), None)
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
        outpoint: TransactionOutpoint::new(KaspaTransactionId::from_slice(&[8u8; 32]), 0),
        entry: UtxoEntry::new(100_000_000, spk, 0, false),
    });

    let raw_transports = [
        Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-1"), group_id, 2)),
        Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-2"), group_id, 2)),
        Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-3"), group_id, 2)),
    ];

    // Drop ~50% of EventStateBroadcast messages deterministically.
    let transports: [Arc<dyn Transport>; 3] = [
        Arc::new(FilteringTransport::new(raw_transports[0].clone(), PeerId::from("signer-1")).with_drop_broadcast_threshold(128)),
        Arc::new(FilteringTransport::new(raw_transports[1].clone(), PeerId::from("signer-2")).with_drop_broadcast_threshold(128)),
        Arc::new(FilteringTransport::new(raw_transports[2].clone(), PeerId::from("signer-3")).with_drop_broadcast_threshold(128)),
    ];

    let storages: [Arc<dyn Storage>; 3] =
        [Arc::new(MemoryStorage::new()), Arc::new(MemoryStorage::new()), Arc::new(MemoryStorage::new())];

    let mut configs = Vec::new();
    for i in 0..3usize {
        let mut app = build_config(redeem_script_hex.clone());
        app.service.hd = Some(hd_config_for_signer(&key_data, i, 2));
        configs.push(Arc::new(app));
    }

    let flows = [
        Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storages[0].clone(), transports[0].clone(), Arc::new(NoopVerifier))?),
        Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storages[1].clone(), transports[1].clone(), Arc::new(NoopVerifier))?),
        Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storages[2].clone(), transports[2].clone(), Arc::new(NoopVerifier))?),
    ];

    let loops = [
        tokio::spawn(run_coordination_loop(
            configs[0].clone(),
            flows[0].clone(),
            transports[0].clone(),
            storages[0].clone(),
            PeerId::from("signer-1"),
            group_id,
        )),
        tokio::spawn(run_coordination_loop(
            configs[1].clone(),
            flows[1].clone(),
            transports[1].clone(),
            storages[1].clone(),
            PeerId::from("signer-2"),
            group_id,
        )),
        tokio::spawn(run_coordination_loop(
            configs[2].clone(),
            flows[2].clone(),
            transports[2].clone(),
            storages[2].clone(),
            PeerId::from("signer-3"),
            group_id,
        )),
    ];

    let mut event_id_hex = None;
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
            session_id_hex: hex::encode([2u8; 32]),
            external_request_id: Some(format!("req-{}", i + 1)),
            coordinator_peer_id: format!("signer-{}", i + 1),
            expires_at_nanos: 0,
            event: signing_event("event-loss"),
        };

        let result = submit_signing_event(&ctx, params).await?;
        event_id_hex.get_or_insert(result.event_id_hex);
    }
    let event_id_hex = event_id_hex.expect("event id");
    let event_id_bytes = hex::decode(event_id_hex).expect("event_id_hex");
    let event_id: Hash32 = event_id_bytes.as_slice().try_into().expect("hash32");

    // Force a sync round to compensate for dropped broadcasts.
    for (idx, raw) in raw_transports.iter().enumerate() {
        raw.publish_state_sync_request(StateSyncRequest {
            event_ids: vec![event_id],
            requester_peer_id: PeerId::from(format!("signer-{}", idx + 1)),
        })
        .await?;
    }

    wait_for_all_complete(&[storages[0].clone(), storages[1].clone(), storages[2].clone()], Duration::from_secs(15)).await?;

    for handle in loops {
        handle.abort();
    }
    Ok(())
}

#[tokio::test]
async fn chaos_out_of_order_delivery_converges() -> Result<(), ThresholdError> {
    ensure_wallet_secret();

    let group_id: Hash32 = [13u8; 32];
    let hub = Arc::new(MockHub::new());

    let mnemonics = [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    ];
    let key_data = mnemonics.iter().map(|m| prv_key_data_from_mnemonic(m)).collect::<Vec<_>>();

    let pubkeys = key_data
        .iter()
        .map(|kd| {
            igra_core::foundation::hd::derive_keypair_from_key_data(kd, Some("m/45'/111111'/0'/0/0"), None)
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
        outpoint: TransactionOutpoint::new(KaspaTransactionId::from_slice(&[9u8; 32]), 0),
        entry: UtxoEntry::new(100_000_000, spk, 0, false),
    });

    let raw_transports = [
        Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-1"), group_id, 2)),
        Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-2"), group_id, 2)),
        Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-3"), group_id, 2)),
    ];
    let transports: [Arc<dyn Transport>; 3] = [
        Arc::new(FilteringTransport::new(raw_transports[0].clone(), PeerId::from("signer-1")).with_max_delay_ms(25)),
        Arc::new(FilteringTransport::new(raw_transports[1].clone(), PeerId::from("signer-2")).with_max_delay_ms(25)),
        Arc::new(FilteringTransport::new(raw_transports[2].clone(), PeerId::from("signer-3")).with_max_delay_ms(25)),
    ];

    let storages: [Arc<dyn Storage>; 3] =
        [Arc::new(MemoryStorage::new()), Arc::new(MemoryStorage::new()), Arc::new(MemoryStorage::new())];

    let mut configs = Vec::new();
    for i in 0..3usize {
        let mut app = build_config(redeem_script_hex.clone());
        app.service.hd = Some(hd_config_for_signer(&key_data, i, 2));
        configs.push(Arc::new(app));
    }

    let flows = [
        Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storages[0].clone(), transports[0].clone(), Arc::new(NoopVerifier))?),
        Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storages[1].clone(), transports[1].clone(), Arc::new(NoopVerifier))?),
        Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storages[2].clone(), transports[2].clone(), Arc::new(NoopVerifier))?),
    ];

    let loops = [
        tokio::spawn(run_coordination_loop(
            configs[0].clone(),
            flows[0].clone(),
            transports[0].clone(),
            storages[0].clone(),
            PeerId::from("signer-1"),
            group_id,
        )),
        tokio::spawn(run_coordination_loop(
            configs[1].clone(),
            flows[1].clone(),
            transports[1].clone(),
            storages[1].clone(),
            PeerId::from("signer-2"),
            group_id,
        )),
        tokio::spawn(run_coordination_loop(
            configs[2].clone(),
            flows[2].clone(),
            transports[2].clone(),
            storages[2].clone(),
            PeerId::from("signer-3"),
            group_id,
        )),
    ];

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
            session_id_hex: hex::encode([3u8; 32]),
            external_request_id: Some(format!("req-{}", i + 1)),
            coordinator_peer_id: format!("signer-{}", i + 1),
            expires_at_nanos: 0,
            event: signing_event("event-reorder"),
        };

        submit_signing_event(&ctx, params).await?;
    }

    wait_for_all_complete(&[storages[0].clone(), storages[1].clone(), storages[2].clone()], Duration::from_secs(10)).await?;

    for handle in loops {
        handle.abort();
    }
    Ok(())
}

#[tokio::test]
async fn chaos_node_restart_persists_and_catches_up() -> Result<(), ThresholdError> {
    ensure_wallet_secret();

    let group_id: Hash32 = [14u8; 32];
    let hub = Arc::new(MockHub::new());

    let mnemonics = [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    ];
    let key_data = mnemonics.iter().map(|m| prv_key_data_from_mnemonic(m)).collect::<Vec<_>>();

    let pubkeys = key_data
        .iter()
        .map(|kd| {
            igra_core::foundation::hd::derive_keypair_from_key_data(kd, Some("m/45'/111111'/0'/0/0"), None)
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
        outpoint: TransactionOutpoint::new(KaspaTransactionId::from_slice(&[10u8; 32]), 0),
        entry: UtxoEntry::new(100_000_000, spk, 0, false),
    });

    let raw_transports = [
        Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-1"), group_id, 2)),
        Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-2"), group_id, 2)),
        Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-3"), group_id, 2)),
    ];
    let transports: [Arc<dyn Transport>; 3] = [raw_transports[0].clone(), raw_transports[1].clone(), raw_transports[2].clone()];

    let node3_dir = tempdir().expect("tempdir");
    let storage1: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let storage2: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let storage3: Arc<dyn Storage> = Arc::new(RocksStorage::open(node3_dir.path())?);

    let mut configs = Vec::new();
    for i in 0..3usize {
        let mut app = build_config(redeem_script_hex.clone());
        app.service.hd = Some(hd_config_for_signer(&key_data, i, 2));
        configs.push(Arc::new(app));
    }

    let flow1 = Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storage1.clone(), transports[0].clone(), Arc::new(NoopVerifier))?);
    let flow2 = Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storage2.clone(), transports[1].clone(), Arc::new(NoopVerifier))?);
    let flow3 = Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storage3.clone(), transports[2].clone(), Arc::new(NoopVerifier))?);

    let loop1 = tokio::spawn(run_coordination_loop(
        configs[0].clone(),
        flow1.clone(),
        transports[0].clone(),
        storage1.clone(),
        PeerId::from("signer-1"),
        group_id,
    ));
    let loop2 = tokio::spawn(run_coordination_loop(
        configs[1].clone(),
        flow2.clone(),
        transports[1].clone(),
        storage2.clone(),
        PeerId::from("signer-2"),
        group_id,
    ));
    let loop3 = tokio::spawn(run_coordination_loop(
        configs[2].clone(),
        flow3.clone(),
        transports[2].clone(),
        storage3.clone(),
        PeerId::from("signer-3"),
        group_id,
    ));

    let mut event_id_hex = None;
    for (idx, (storage, transport)) in [
        (storage1.clone(), transports[0].clone()),
        (storage2.clone(), transports[1].clone()),
        (storage3.clone(), transports[2].clone()),
    ]
    .into_iter()
    .enumerate()
    {
        let ctx = EventContext {
            config: configs[idx].service.clone(),
            policy: configs[idx].policy.clone(),
            local_peer_id: PeerId::from(format!("signer-{}", idx + 1)),
            message_verifier: Arc::new(NoopVerifier),
            storage,
            transport,
            rpc: rpc.clone(),
        };

        let params = SigningEventParams {
            session_id_hex: hex::encode([4u8; 32]),
            external_request_id: Some(format!("req-{}", idx + 1)),
            coordinator_peer_id: format!("signer-{}", idx + 1),
            expires_at_nanos: 0,
            event: signing_event("event-restart"),
        };

        let result = submit_signing_event(&ctx, params).await?;
        event_id_hex.get_or_insert(result.event_id_hex);
    }
    let event_id_hex = event_id_hex.expect("event id");
    let event_id_bytes = hex::decode(event_id_hex).expect("event_id_hex");
    let event_id: Hash32 = event_id_bytes.as_slice().try_into().expect("hash32");

    // Crash node 3 after it has had a chance to persist its local signature.
    tokio::time::sleep(Duration::from_millis(200)).await;
    loop3.abort();
    let _ = loop3.await;
    drop(flow3);
    drop(storage3);

    // Nodes 1 and 2 should complete.
    wait_for_all_complete(&[storage1.clone(), storage2.clone()], Duration::from_secs(10)).await?;

    // Restart node 3 with the same RocksDB dir.
    let storage3_restarted: Arc<dyn Storage> = Arc::new(RocksStorage::open(node3_dir.path())?);
    let flow3_restarted =
        Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storage3_restarted.clone(), transports[2].clone(), Arc::new(NoopVerifier))?);
    let loop3_restarted = tokio::spawn(run_coordination_loop(
        configs[2].clone(),
        flow3_restarted.clone(),
        transports[2].clone(),
        storage3_restarted.clone(),
        PeerId::from("signer-3"),
        group_id,
    ));

    // Trigger a sync round to pull completion/sigs.
    raw_transports[2]
        .publish_state_sync_request(StateSyncRequest { event_ids: vec![event_id], requester_peer_id: PeerId::from("signer-3") })
        .await?;

    wait_for_complete(&storage3_restarted, Duration::from_secs(10)).await?;

    loop1.abort();
    loop2.abort();
    loop3_restarted.abort();
    Ok(())
}
