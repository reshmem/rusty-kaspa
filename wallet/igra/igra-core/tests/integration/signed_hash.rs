use igra_core::foundation::{EventId, TxTemplateHash};
use igra_core::infrastructure::storage::{MemoryStorage, PhaseStorage, RecordSignedHashResult};

#[test]
fn signed_hash_record_is_set_once_and_detects_conflicts() {
    let storage = MemoryStorage::new();
    let event_id = EventId::new([7u8; 32]);
    let h1 = TxTemplateHash::new([1u8; 32]);
    let h2 = TxTemplateHash::new([2u8; 32]);

    assert_eq!(storage.get_signed_hash(&event_id).expect("get"), None);

    let r1 = storage.record_signed_hash(&event_id, h1, 1).expect("record");
    assert_eq!(r1, RecordSignedHashResult::Set);
    assert_eq!(storage.get_signed_hash(&event_id).expect("get"), Some(h1));

    let r2 = storage.record_signed_hash(&event_id, h1, 2).expect("record");
    assert_eq!(r2, RecordSignedHashResult::AlreadySame);
    assert_eq!(storage.get_signed_hash(&event_id).expect("get"), Some(h1));

    let r3 = storage.record_signed_hash(&event_id, h2, 3).expect("record");
    assert_eq!(r3, RecordSignedHashResult::Conflict { existing: h1, attempted: h2 });
    assert_eq!(storage.get_signed_hash(&event_id).expect("get"), Some(h1));
}
