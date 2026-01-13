use igra_core::domain::crdt::{merge_event_states, CompletionInfo, EventCrdt, SignatureRecord};
use igra_core::foundation::{Hash32, PeerId, TransactionId};
use std::collections::BTreeSet;

fn next_u64(state: &mut u64) -> u64 {
    // LCG parameters from Numerical Recipes; fine for deterministic test coverage.
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
    *state
}

fn gen_bytes(state: &mut u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push((next_u64(state) & 0xff) as u8);
    }
    out
}

fn sig_record(state: &mut u64, input_count: u32, signer: u8) -> SignatureRecord {
    let input_index = (next_u64(state) % input_count as u64) as u32;
    SignatureRecord {
        input_index,
        pubkey: vec![signer],
        signature: gen_bytes(state, 64),
        signer_peer_id: Some(PeerId::from(format!("peer-{}", signer))),
        timestamp_nanos: next_u64(state),
    }
}

fn sig_key_set(crdt: &EventCrdt) -> BTreeSet<(u32, Vec<u8>)> {
    crdt.signatures().map(|s| (s.input_index, s.pubkey.clone())).collect()
}

fn completion_key(crdt: &EventCrdt) -> Option<(Hash32, PeerId, u64)> {
    crdt.completion().map(|c| (*c.tx_id.as_hash(), c.submitter_peer_id.clone(), c.timestamp_nanos))
}

#[test]
fn merge_commutative_for_signatures_and_completion() {
    let event_hash: Hash32 = [1u8; 32];
    let tx_hash: Hash32 = [2u8; 32];

    for seed in 0u64..100u64 {
        let mut a = EventCrdt::new(event_hash, tx_hash);
        let mut b = EventCrdt::new(event_hash, tx_hash);

        let mut rng = seed ^ 0xA5A5_5A5A_DEAD_BEEF;
        for _ in 0..20 {
            let signer = ((next_u64(&mut rng) % 5) as u8) + 1;
            a.add_signature(sig_record(&mut rng, 3, signer));
        }
        for _ in 0..20 {
            let signer = ((next_u64(&mut rng) % 5) as u8) + 1;
            b.add_signature(sig_record(&mut rng, 3, signer));
        }

        // Sometimes add competing completions with different timestamps.
        if (next_u64(&mut rng) & 1) == 1 {
            let t1 = (next_u64(&mut rng) % 1_000) + 1;
            let t2 = (next_u64(&mut rng) % 1_000) + 1;
            a.set_completed(
                CompletionInfo {
                    tx_id: TransactionId::from([3u8; 32]),
                    submitter_peer_id: PeerId::from("peer-a"),
                    timestamp_nanos: t1,
                    blue_score: None,
                },
                t1,
            );
            b.set_completed(
                CompletionInfo {
                    tx_id: TransactionId::from([4u8; 32]),
                    submitter_peer_id: PeerId::from("peer-b"),
                    timestamp_nanos: t2,
                    blue_score: None,
                },
                t2,
            );
        }

        let ab = merge_event_states(&a, &b);
        let ba = merge_event_states(&b, &a);

        assert_eq!(sig_key_set(&ab), sig_key_set(&ba));
        assert_eq!(completion_key(&ab), completion_key(&ba));
    }
}

#[test]
fn merge_idempotent_for_signatures_and_completion() {
    let event_hash: Hash32 = [9u8; 32];
    let tx_hash: Hash32 = [8u8; 32];

    for seed in 0u64..100u64 {
        let mut crdt = EventCrdt::new(event_hash, tx_hash);
        let mut rng = seed ^ 0x1234_5678_9ABC_DEF0;

        for _ in 0..30 {
            let signer = ((next_u64(&mut rng) % 7) as u8) + 1;
            crdt.add_signature(sig_record(&mut rng, 4, signer));
        }

        if (next_u64(&mut rng) & 1) == 1 {
            let ts = (next_u64(&mut rng) % 1_000) + 1;
            crdt.set_completed(
                CompletionInfo {
                    tx_id: TransactionId::from([5u8; 32]),
                    submitter_peer_id: PeerId::from("peer"),
                    timestamp_nanos: ts,
                    blue_score: None,
                },
                ts,
            );
        }

        let before_keys = sig_key_set(&crdt);
        let before_completion = completion_key(&crdt);
        let mut mutated = crdt.clone();
        mutated.merge(&crdt.clone());
        assert_eq!(before_keys, sig_key_set(&mutated));
        assert_eq!(before_completion, completion_key(&mutated));
    }
}

