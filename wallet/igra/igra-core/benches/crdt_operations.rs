use criterion::{black_box, criterion_group, criterion_main, Criterion};
use igra_core::foundation::{EventId, PeerId, ThresholdError, TxTemplateHash};
use igra_core::infrastructure::storage::{RocksStorage, Storage};
use igra_core::infrastructure::transport::messages::{CrdtSignature, EventCrdtState};
use tempfile::TempDir;

fn bench_merge_event_crdt(c: &mut Criterion) {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = RocksStorage::open_in_dir(temp_dir.path()).expect("open rocksdb");

    let event_id = EventId::new([1u8; 32]);
    let tx_hash = TxTemplateHash::new([2u8; 32]);

    let incoming = EventCrdtState {
        signatures: vec![CrdtSignature {
            input_index: 0,
            pubkey: vec![1],
            signature: vec![2],
            signer_peer_id: Some(PeerId::from("bench-peer")),
            timestamp_nanos: 1,
        }],
        completion: None,
        signing_material: None,
        kpsbt_blob: None,
        version: 0,
    };

    c.bench_function("rocks_merge_event_crdt", |b| {
        b.iter(|| -> Result<(), ThresholdError> {
            let _ = storage.merge_event_crdt(black_box(&event_id), black_box(&tx_hash), black_box(&incoming), None, None)?;
            Ok(())
        })
    });
}

criterion_group!(benches, bench_merge_event_crdt);
criterion_main!(benches);
