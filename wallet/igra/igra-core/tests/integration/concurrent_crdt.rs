use igra_core::foundation::{EventId, PeerId, ThresholdError, TxTemplateHash};
use igra_core::infrastructure::storage::{RocksStorage, Storage};
use igra_core::infrastructure::transport::messages::{CrdtSignature, EventCrdtState};
use std::sync::Arc;
use tempfile::TempDir;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_crdt_merges_do_not_deadlock() -> Result<(), ThresholdError> {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("open rocksdb"));

    let mut handles = Vec::new();
    for task in 0..4u8 {
        let storage = storage.clone();
        handles.push(tokio::spawn(async move {
            for iter in 0..25u8 {
                let event_id = EventId::new([task; 32]);
                let tx_hash = TxTemplateHash::new([iter; 32]);
                let incoming = EventCrdtState {
                    signatures: vec![CrdtSignature {
                        input_index: 0,
                        pubkey: vec![task, iter],
                        signature: vec![iter],
                        signer_peer_id: Some(PeerId::from(format!("peer-{task}"))),
                        timestamp_nanos: 1_000 + u64::from(iter),
                    }],
                    completion: None,
                    signing_material: None,
                    kpsbt_blob: None,
                    version: 0,
                };
                storage.merge_event_crdt(&event_id, &tx_hash, &incoming, None, None)?;
            }
            Ok::<(), ThresholdError>(())
        }));
    }

    for handle in handles {
        handle.await.expect("join")?;
    }

    Ok(())
}
