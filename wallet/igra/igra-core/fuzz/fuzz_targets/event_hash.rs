#![no_main]

use arbitrary::Unstructured;
use igra_core::coordination::hashes::{event_hash, event_hash_without_signature};
use igra_core::model::{EventSource, SigningEvent};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

fn read_string(u: &mut Unstructured<'_>, max_len: usize) -> Option<String> {
    let len = u.int_in_range(0..=max_len).ok()?;
    let bytes = u.bytes(len).ok()?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn build_event(mut u: Unstructured<'_>) -> Option<SigningEvent> {
    let event_id = read_string(&mut u, 32)?;
    let derivation_path = read_string(&mut u, 32)?;
    let destination_address = read_string(&mut u, 64)?;
    let amount_sompi = u.arbitrary::<u64>().ok()?;
    let timestamp_nanos = u.arbitrary::<u64>().ok()?;
    let derivation_index = if u.arbitrary::<bool>().ok()? {
        Some(u.arbitrary::<u32>().ok()?)
    } else {
        None
    };
    let signature = if u.arbitrary::<bool>().ok()? {
        let len = u.int_in_range(0..=128).ok()?;
        let mut buf = vec![0u8; len];
        u.fill_buffer(&mut buf).ok()?;
        Some(buf)
    } else {
        None
    };

    let meta_len = u.int_in_range(0..=4).ok()?;
    let mut metadata = BTreeMap::new();
    for _ in 0..meta_len {
        let key = read_string(&mut u, 16)?;
        let value = read_string(&mut u, 32)?;
        metadata.insert(key, value);
    }

    let source_kind = u.arbitrary::<u8>().ok()?;
    let event_source = match source_kind % 5 {
        0 => EventSource::Hyperlane {
            domain: read_string(&mut u, 16)?,
            sender: read_string(&mut u, 32)?,
        },
        1 => EventSource::LayerZero {
            endpoint: read_string(&mut u, 16)?,
            sender: read_string(&mut u, 32)?,
        },
        2 => EventSource::Api {
            issuer: read_string(&mut u, 16)?,
        },
        3 => EventSource::Manual {
            operator: read_string(&mut u, 16)?,
        },
        _ => EventSource::Other {
            kind: read_string(&mut u, 16)?,
            payload: read_string(&mut u, 32)?,
        },
    };

    Some(SigningEvent {
        event_id,
        event_source,
        derivation_path,
        derivation_index,
        destination_address,
        amount_sompi,
        metadata,
        timestamp_nanos,
        signature,
    })
}

fuzz_target!(|data: &[u8]| {
    let u = Unstructured::new(data);
    let Some(event) = build_event(u) else {
        return;
    };
    let _ = event_hash_without_signature(&event);
    let _ = event_hash(&event);
});
