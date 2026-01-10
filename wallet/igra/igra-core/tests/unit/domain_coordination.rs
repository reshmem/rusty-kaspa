use igra_core::domain::coordination::threshold::has_threshold;
use igra_core::domain::PartialSigRecord;

fn sig(input_index: u32, pubkey: u8) -> PartialSigRecord {
    PartialSigRecord {
        signer_peer_id: "peer".to_string().into(),
        input_index,
        pubkey: vec![pubkey],
        signature: vec![1, 2, 3],
        timestamp_nanos: 0,
    }
}

#[test]
fn test_threshold_when_exact_m_then_true() {
    let partials = vec![sig(0, 1), sig(0, 2), sig(1, 1), sig(1, 2)];
    assert!(has_threshold(&partials, 2, 2));
}

#[test]
fn test_threshold_when_below_m_then_false() {
    let partials = vec![sig(0, 1), sig(1, 1)];
    assert!(!has_threshold(&partials, 2, 2));
}

#[test]
fn test_threshold_when_above_m_then_true() {
    let partials = vec![sig(0, 1), sig(0, 2), sig(0, 3), sig(1, 1), sig(1, 2), sig(1, 3)];
    assert!(has_threshold(&partials, 2, 2));
}
