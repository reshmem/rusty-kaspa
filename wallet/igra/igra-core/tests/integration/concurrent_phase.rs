use igra_core::domain::coordination::EventPhase;
use igra_core::foundation::{EventId, ThresholdError, TxTemplateHash};
use igra_core::infrastructure::storage::{PhaseStorage, RocksStorage};
use std::sync::Arc;
use tempfile::TempDir;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_try_enter_proposing_is_single_winner() -> Result<(), ThresholdError> {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("open rocksdb"));

    let event_id = EventId::new([42u8; 32]);
    let now = 123;

    let mut handles = Vec::new();
    for _ in 0..8 {
        let storage = storage.clone();
        handles.push(tokio::spawn(async move { storage.try_enter_proposing(&event_id, now) }));
    }

    let mut winners = 0u32;
    for h in handles {
        if h.await.expect("join")? {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);

    let phase = storage.get_phase(&event_id)?.expect("phase");
    assert_eq!(phase.phase, EventPhase::Proposing);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_mark_committed_is_idempotent() -> Result<(), ThresholdError> {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("open rocksdb"));

    let event_id = EventId::new([7u8; 32]);
    let canonical_hash = TxTemplateHash::new([9u8; 32]);

    let mut handles = Vec::new();
    for round in 0..8u32 {
        let storage = storage.clone();
        handles.push(tokio::spawn(async move { storage.mark_committed(&event_id, round, canonical_hash, 1_000 + u64::from(round)) }));
    }

    for h in handles {
        h.await.expect("join")?;
    }

    let phase = storage.get_phase(&event_id)?.expect("phase");
    assert!(matches!(phase.phase, EventPhase::Committed));
    assert_eq!(phase.canonical_hash, Some(canonical_hash));
    Ok(())
}
