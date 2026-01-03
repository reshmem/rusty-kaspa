use igra_core::coordination::threshold::has_threshold;
use igra_core::model::PartialSigRecord;

fn sig(input_index: u32, pubkey: u8) -> PartialSigRecord {
    PartialSigRecord {
        signer_peer_id: "peer".to_string(),
        input_index,
        pubkey: vec![pubkey],
        signature: vec![1, 2, 3],
        timestamp_nanos: 0,
    }
}

#[test]
fn threshold_exact_m() {
    let partials = vec![sig(0, 1), sig(0, 2), sig(1, 1), sig(1, 2)];
    assert!(has_threshold(&partials, 2, 2));
}

#[test]
fn threshold_below_m() {
    let partials = vec![sig(0, 1), sig(1, 1)];
    assert!(!has_threshold(&partials, 2, 2));
}

#[test]
fn threshold_above_m() {
    let partials = vec![sig(0, 1), sig(0, 2), sig(0, 3), sig(1, 1), sig(1, 2), sig(1, 3)];
    assert!(has_threshold(&partials, 2, 2));
}
