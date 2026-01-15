use igra_core::domain::coordination::EventPhase;
use igra_core::foundation::{Hash32, ThresholdError};
use igra_core::infrastructure::storage::{PhaseStorage, RocksStorage};
use tempfile::TempDir;

#[test]
fn mark_committed_is_idempotent_for_same_hash_even_if_round_differs() -> Result<(), ThresholdError> {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = RocksStorage::open_in_dir(temp_dir.path()).expect("open rocksdb");

    let event_id: Hash32 = [42u8; 32];
    let canonical_hash: Hash32 = [77u8; 32];
    let now = 1;

    assert!(storage.mark_committed(&event_id, 0, canonical_hash, now)?);

    // Replay with a different round should still succeed (round is informational once committed).
    assert!(storage.mark_committed(&event_id, 3, canonical_hash, now + 1)?);

    let phase = storage.get_phase(&event_id)?.expect("phase");
    assert_eq!(phase.phase, EventPhase::Committed);
    assert_eq!(phase.canonical_hash, Some(canonical_hash));
    assert_eq!(phase.round, 3);

    Ok(())
}

