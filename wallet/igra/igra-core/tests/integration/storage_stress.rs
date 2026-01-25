use igra_core::foundation::{EventId, PeerId, ThresholdError, TransactionId, TxTemplateHash};
use igra_core::infrastructure::storage::{RocksStorage, Storage};
use tempfile::TempDir;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn storage_stress_500_events() -> Result<(), ThresholdError> {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = RocksStorage::open_in_dir(temp_dir.path()).expect("open rocksdb");

    let submitter = PeerId::from("submitter");
    let tx_id = TransactionId::new([1u8; 32]);

    for i in 0..500u16 {
        let mut id_bytes = [0u8; 32];
        id_bytes[0..2].copy_from_slice(&i.to_be_bytes());
        let event_id = EventId::new(id_bytes);

        let tx_hash = TxTemplateHash::new([u8::try_from(i % 255).unwrap_or(0); 32]);
        storage.mark_crdt_completed(&event_id, &tx_hash, tx_id, &submitter, 10, None)?;
    }

    assert_eq!(storage.hyperlane_get_delivered_count()?, 0);
    Ok(())
}
