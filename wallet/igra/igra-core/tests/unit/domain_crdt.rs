use igra_core::domain::crdt::{merge_event_states, EventCrdt, GSet, LWWRegister, SignatureRecord};
use igra_core::foundation::{EventId, PeerId, TransactionId, TxTemplateHash};

#[test]
fn test_gset_merge_properties() {
    let mut a = GSet::from_items(vec![1, 2, 3]);
    let b = GSet::from_items(vec![3, 4, 5]);

    let mut c = GSet::from_items(vec![3, 4, 5]);
    let d = GSet::from_items(vec![1, 2, 3]);

    a.merge(&b);
    c.merge(&d);
    assert_eq!(a.len(), c.len());

    let before = a.len();
    a.merge(&a.clone());
    assert_eq!(before, a.len());
}

#[test]
fn test_lww_register_basic() {
    let mut reg = LWWRegister::new();
    assert!(reg.set("a", 10));
    assert!(!reg.set("old", 5));
    assert!(reg.set("b", 11));
    assert_eq!(reg.value(), Some(&"b"));
}

#[test]
fn test_event_crdt_threshold_and_merge() {
    let event_hash = EventId::new([1u8; 32]);
    let tx_hash = TxTemplateHash::new([2u8; 32]);
    let mut crdt_a = EventCrdt::new(event_hash, tx_hash);
    let mut crdt_b = EventCrdt::new(event_hash, tx_hash);

    // 2-of-3 threshold, 2 inputs.
    let input_count = 2usize;
    let required = 2usize;

    crdt_a.add_signature(SignatureRecord {
        input_index: 0,
        pubkey: vec![1],
        signature: vec![10],
        signer_peer_id: Some(PeerId::from("a1")),
        timestamp_nanos: 1,
    });
    crdt_a.add_signature(SignatureRecord {
        input_index: 1,
        pubkey: vec![1],
        signature: vec![11],
        signer_peer_id: Some(PeerId::from("a1")),
        timestamp_nanos: 2,
    });

    crdt_b.add_signature(SignatureRecord {
        input_index: 0,
        pubkey: vec![2],
        signature: vec![20],
        signer_peer_id: Some(PeerId::from("b1")),
        timestamp_nanos: 3,
    });
    crdt_b.add_signature(SignatureRecord {
        input_index: 1,
        pubkey: vec![2],
        signature: vec![21],
        signer_peer_id: Some(PeerId::from("b1")),
        timestamp_nanos: 4,
    });

    assert!(!crdt_a.has_threshold(input_count, required));
    crdt_a.merge(&crdt_b);
    assert!(crdt_a.has_threshold(input_count, required));

    let completion = igra_core::domain::crdt::CompletionInfo {
        tx_id: TransactionId::from([9u8; 32]),
        submitter_peer_id: PeerId::from("submitter"),
        timestamp_nanos: 100,
        blue_score: Some(123),
    };
    crdt_a.set_completed(completion, 100);

    let merged = merge_event_states(&crdt_a, &crdt_b);
    assert!(merged.is_completed());
}
