use igra_core::foundation::{PeerId, SessionId};
use igra_core::infrastructure::storage::{RocksStorage, Storage};
use tempfile::TempDir;

#[tokio::test]
async fn replay_prevention_marks_seen_messages() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = RocksStorage::open_in_dir(temp_dir.path()).expect("storage");

    let session_id = SessionId::from([9u8; 32]);
    let first = storage.mark_seen_message(&PeerId::from("peer-1"), &session_id, 1, 100).expect("mark seen");
    assert!(first, "first message should be new");

    let second = storage.mark_seen_message(&PeerId::from("peer-1"), &session_id, 1, 101).expect("mark seen");
    assert!(!second, "duplicate message should be rejected");

    let third = storage.mark_seen_message(&PeerId::from("peer-1"), &session_id, 2, 102).expect("mark seen");
    assert!(third, "new seq should be accepted");
}
