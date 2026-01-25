//! Constant-time operation tests.
//!
//! Verifies that hash equality comparisons are timing-attack resistant.

use igra_core::foundation::{EventId, TxTemplateHash};

#[test]
fn tx_template_hash_ct_eq_correctness() {
    let hash1 = TxTemplateHash::from([0xABu8; 32]);
    let hash2 = TxTemplateHash::from([0xABu8; 32]);
    let hash3 = TxTemplateHash::from([0xCDu8; 32]);

    assert!(hash1.ct_eq(&hash2), "equal hashes should return true");
    assert!(!hash1.ct_eq(&hash3), "different hashes should return false");
}

#[test]
fn event_id_ct_eq_correctness() {
    let id1 = EventId::from([1u8; 32]);
    let id2 = EventId::from([1u8; 32]);
    let id3 = EventId::from([2u8; 32]);

    assert!(id1.ct_eq(&id2), "equal IDs should return true");
    assert!(!id1.ct_eq(&id3), "different IDs should return false");
}

#[test]
fn ct_eq_with_default_values() {
    let default_tx = TxTemplateHash::default();
    let default_id = EventId::default();

    assert!(default_tx.ct_eq(&TxTemplateHash::default()));
    assert!(default_id.ct_eq(&EventId::default()));

    let non_default_tx = TxTemplateHash::from([0xFFu8; 32]);
    assert!(!default_tx.ct_eq(&non_default_tx));
}

/// Statistical timing test to verify constant-time behavior.
///
/// This is a basic sanity check, not a rigorous security analysis.
/// For production, consider using `dudect` crate for statistical verification.
#[test]
fn ct_eq_timing_sanity_check() {
    use std::time::Instant;

    let hash1 = TxTemplateHash::from([0x42u8; 32]);
    let hash_match = TxTemplateHash::from([0x42u8; 32]);

    let hash_differ_first = TxTemplateHash::from({
        let mut h = [0x42u8; 32];
        h[0] = 0xFF;
        h
    });

    let hash_differ_last = TxTemplateHash::from({
        let mut h = [0x42u8; 32];
        h[31] = 0xFF;
        h
    });

    for _ in 0..10_000 {
        let _ = hash1.ct_eq(&hash_match);
        let _ = hash1.ct_eq(&hash_differ_first);
        let _ = hash1.ct_eq(&hash_differ_last);
    }

    let iterations = 1_000_000u128;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = hash1.ct_eq(&hash_match);
    }
    let time_match = start.elapsed();

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = hash1.ct_eq(&hash_differ_first);
    }
    let time_first = start.elapsed();

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = hash1.ct_eq(&hash_differ_last);
    }
    let time_last = start.elapsed();

    let times = [time_match.as_nanos(), time_first.as_nanos(), time_last.as_nanos()];
    let avg = times.iter().sum::<u128>() / times.len() as u128;
    let max_dev = times.iter().map(|t| t.abs_diff(avg)).max().unwrap_or(0);

    let threshold = avg / 4;

    assert!(
        max_dev < threshold,
        "Timing variation too high: max_dev={} threshold={} (match={:?}, first={:?}, last={:?})",
        max_dev,
        threshold,
        time_match,
        time_first,
        time_last
    );

    eprintln!("✅ Constant-time check passed:");
    eprintln!("   Match:        {:?} ({} ns/op)", time_match, time_match.as_nanos() / iterations);
    eprintln!("   First differs: {:?} ({} ns/op)", time_first, time_first.as_nanos() / iterations);
    eprintln!("   Last differs:  {:?} ({} ns/op)", time_last, time_last.as_nanos() / iterations);
    eprintln!("   Max deviation: {:.2}% of average", (max_dev as f64 / avg as f64) * 100.0);
}

#[test]
fn ct_eq_works_for_all_hash_types() {
    use igra_core::foundation::{ExternalId, GroupId, PayloadHash, SessionId};

    let bytes1 = [0xAAu8; 32];
    let bytes2 = [0xBBu8; 32];

    assert!(TxTemplateHash::from(bytes1).ct_eq(&TxTemplateHash::from(bytes1)));
    assert!(!TxTemplateHash::from(bytes1).ct_eq(&TxTemplateHash::from(bytes2)));

    assert!(EventId::from(bytes1).ct_eq(&EventId::from(bytes1)));
    assert!(!EventId::from(bytes1).ct_eq(&EventId::from(bytes2)));

    assert!(GroupId::from(bytes1).ct_eq(&GroupId::from(bytes1)));
    assert!(!GroupId::from(bytes1).ct_eq(&GroupId::from(bytes2)));

    assert!(SessionId::from(bytes1).ct_eq(&SessionId::from(bytes1)));
    assert!(!SessionId::from(bytes1).ct_eq(&SessionId::from(bytes2)));

    assert!(ExternalId::from(bytes1).ct_eq(&ExternalId::from(bytes1)));
    assert!(!ExternalId::from(bytes1).ct_eq(&ExternalId::from(bytes2)));

    assert!(PayloadHash::from(bytes1).ct_eq(&PayloadHash::from(bytes1)));
    assert!(!PayloadHash::from(bytes1).ct_eq(&PayloadHash::from(bytes2)));
}
