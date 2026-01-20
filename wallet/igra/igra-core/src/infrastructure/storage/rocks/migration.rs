use super::schema::*;
use crate::foundation::ThresholdError;
use rocksdb::{ColumnFamilyDescriptor, MergeOperands, Options as RocksOptions, DB};
use std::path::Path;

// Merge operator for atomic volume accumulation
// Handles concurrent updates to volume counters without race conditions
fn volume_merge_operator(_key: &[u8], existing_val: Option<&[u8]>, operands: &MergeOperands) -> Option<Vec<u8>> {
    let mut total = match existing_val {
        Some(bytes) if bytes.len() == 8 => {
            let array: [u8; 8] = bytes.try_into().ok()?;
            u64::from_be_bytes(array)
        }
        _ => 0,
    };

    for op in operands {
        if op.len() == 8 {
            if let Ok(array) = TryInto::<[u8; 8]>::try_into(op) {
                let value = u64::from_be_bytes(array);
                total = total.saturating_add(value);
            }
        }
    }

    Some(total.to_be_bytes().to_vec())
}

pub fn open_db_with_cfs(path: impl AsRef<Path>) -> Result<DB, ThresholdError> {
    let mut options = RocksOptions::default();
    options.create_if_missing(true);
    options.create_missing_column_families(true);
    options.set_use_fsync(true);
    options.set_manual_wal_flush(false);
    options.set_paranoid_checks(true);
    options.optimize_for_point_lookup(64);

    let mut volume_options = RocksOptions::default();
    volume_options.set_merge_operator_associative("volume_add", volume_merge_operator);

    let cfs = vec![
        ColumnFamilyDescriptor::new(CF_DEFAULT, RocksOptions::default()),
        ColumnFamilyDescriptor::new(CF_METADATA, RocksOptions::default()),
        ColumnFamilyDescriptor::new(CF_GROUP, RocksOptions::default()),
        ColumnFamilyDescriptor::new(CF_EVENT, RocksOptions::default()),
        ColumnFamilyDescriptor::new(CF_EVENT_INDEX, RocksOptions::default()),
        ColumnFamilyDescriptor::new(CF_EVENT_CRDT, RocksOptions::default()),
        ColumnFamilyDescriptor::new(CF_EVENT_PHASE, RocksOptions::default()),
        ColumnFamilyDescriptor::new(CF_EVENT_PROPOSAL, RocksOptions::default()),
        ColumnFamilyDescriptor::new(CF_EVENT_SIGNED_HASH, RocksOptions::default()),
        ColumnFamilyDescriptor::new(CF_VOLUME, volume_options),
        ColumnFamilyDescriptor::new(CF_SEEN, RocksOptions::default()),
        ColumnFamilyDescriptor::new(CF_HYPERLANE_MESSAGE, RocksOptions::default()),
        ColumnFamilyDescriptor::new(CF_HYPERLANE_DELIVERY, RocksOptions::default()),
    ];

    DB::open_cf_descriptors(&options, path, cfs)
        .map_err(|err| ThresholdError::StorageError { operation: "rocksdb open_cf_descriptors".to_string(), details: err.to_string() })
}
