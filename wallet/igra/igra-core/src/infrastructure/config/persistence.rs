use crate::foundation::ThresholdError;
use crate::infrastructure::config::types::AppConfig;
use rocksdb::{ColumnFamilyDescriptor, MergeOperands, Options as RocksOptions, DB};
use std::path::{Path, PathBuf};

const CONFIG_KEY: &[u8] = b"cfg:app";
const CF_DEFAULT: &str = "default";
const CF_VOLUME: &str = "volume";

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

pub fn load_config_from_db(data_dir: &Path) -> Result<Option<AppConfig>, ThresholdError> {
    let db_path = rocksdb_path(data_dir);
    if !db_path.exists() {
        return Ok(None);
    }
    let db = open_config_db(&db_path, false)?;
    let value = db.get(CONFIG_KEY).map_err(|err| ThresholdError::StorageError {
        operation: "rocksdb get config".to_string(),
        details: err.to_string(),
    })?;
    match value {
        Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        None => Ok(None),
    }
}

pub fn store_config_in_db(data_dir: &Path, config: &AppConfig) -> Result<(), ThresholdError> {
    let db_path = rocksdb_path(data_dir);
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| ThresholdError::StorageError {
            operation: "create config db dir".to_string(),
            details: err.to_string(),
        })?;
    }
    let db = open_config_db(&db_path, true)?;
    let bytes = serde_json::to_vec_pretty(config)?;
    db.put(CONFIG_KEY, bytes).map_err(|err| ThresholdError::StorageError {
        operation: "rocksdb put config".to_string(),
        details: err.to_string(),
    })
}

fn rocksdb_path(data_dir: &Path) -> PathBuf {
    data_dir.join("threshold-signing")
}

fn open_config_db(path: &Path, create_if_missing: bool) -> Result<DB, ThresholdError> {
    let mut options = RocksOptions::default();
    options.create_if_missing(create_if_missing);

    let cf_names = if path.exists() {
        DB::list_cf(&options, path).map_err(|err| ThresholdError::StorageError {
            operation: "rocksdb list_cf".to_string(),
            details: err.to_string(),
        })?
    } else {
        vec![CF_DEFAULT.to_string()]
    };

    let mut descriptors = Vec::with_capacity(cf_names.len());
    for name in cf_names {
        let mut cf_options = RocksOptions::default();
        if name == CF_VOLUME {
            cf_options.set_merge_operator_associative("volume_add", volume_merge_operator);
        }
        descriptors.push(ColumnFamilyDescriptor::new(name, cf_options));
    }

    DB::open_cf_descriptors(&options, path, descriptors).map_err(|err| ThresholdError::StorageError {
        operation: "rocksdb open_cf_descriptors config".to_string(),
        details: err.to_string(),
    })
}
