//! System-wide constants for Igra threshold signing.

/// Nanoseconds per second (10^9).
pub const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Nanoseconds per day (24 * 60 * 60 * 10^9).
///
/// Used for volume limit calculations aligned to UTC days.
pub const NANOS_PER_DAY: u64 = 24 * 60 * 60 * NANOS_PER_SECOND;

/// Minimum session timeout in nanoseconds (10 seconds).
///
/// Sessions shorter than this are rejected to prevent timing attacks
/// and give signers time to validate proposals.
pub const MIN_SESSION_DURATION_NS: u64 = 10 * NANOS_PER_SECOND;

/// Maximum session timeout in nanoseconds (1 hour).
///
/// Sessions longer than this are rejected to prevent indefinite resource holds.
pub const MAX_SESSION_DURATION_NS: u64 = 60 * 60 * NANOS_PER_SECOND;

/// Default session timeout in nanoseconds (5 minutes).
pub const DEFAULT_SESSION_TIMEOUT_NS: u64 = 5 * 60 * NANOS_PER_SECOND;

/// Maximum message size for gossip transport (10 MB).
pub const MAX_MESSAGE_SIZE_BYTES: usize = 10 * 1024 * 1024;

/// Maximum number of UTXOs/inputs in a single PSKT.
pub const MAX_PSKT_INPUTS: usize = 1000;

/// Maximum number of outputs in a single PSKT.
pub const MAX_PSKT_OUTPUTS: usize = 1000;

/// Maximum size of event metadata in bytes (10 KB).
pub const MAX_EVENT_METADATA_SIZE: usize = 10 * 1024;

/// Maximum length of event ID string.
pub const MAX_EVENT_ID_LENGTH: usize = 256;

/// Maximum length of destination address string.
pub const MAX_ADDRESS_LENGTH: usize = 256;

/// Schnorr signature size in bytes (64 bytes).
pub const SCHNORR_SIGNATURE_SIZE: usize = 64;

/// Schnorr public key size in bytes (32 bytes, x-only).
pub const SCHNORR_PUBKEY_SIZE: usize = 32;

/// Blake3 hash size in bytes (32 bytes).
pub const HASH_SIZE: usize = 32;

/// ECDSA signature size in compact format (64 bytes).
pub const ECDSA_SIGNATURE_SIZE: usize = 64;

/// ECDSA recovery ID size (1 byte).
pub const ECDSA_RECOVERY_ID_SIZE: usize = 1;

/// Fee calculation precision scale (10^6).
pub const FEE_PRECISION_SCALE: u64 = 1_000_000;

/// Default fee in sompi (0.001 KAS = 100,000 sompi).
pub const DEFAULT_FEE_SOMPI: u64 = 100_000;

/// Maximum number of bootstrap peers for gossip.
pub const MAX_BOOTSTRAP_PEERS: usize = 10;

/// Gossip publish retry attempts.
pub const GOSSIP_PUBLISH_RETRIES: usize = 3;

/// Delay between gossip publish retries in milliseconds.
pub const GOSSIP_RETRY_DELAY_MS: u64 = 200;

/// Maximum gossip topic length in bytes.
pub const MAX_GOSSIP_TOPIC_LENGTH: usize = 256;

/// Rate limiter burst capacity (requests).
pub const RATE_LIMIT_CAPACITY: f64 = 100.0;

/// Rate limiter refill rate (requests per second).
pub const RATE_LIMIT_REFILL_RATE: f64 = 10.0;

/// Rate limiter cleanup interval in seconds.
pub const RATE_LIMIT_CLEANUP_INTERVAL_SECS: u64 = 300;

/// RocksDB write batch size (number of operations).
pub const ROCKSDB_WRITE_BATCH_SIZE: usize = 100;

/// RocksDB cache size in bytes (128 MB).
pub const ROCKSDB_CACHE_SIZE: usize = 128 * 1024 * 1024;

/// Maximum threshold N (total signers).
pub const MAX_THRESHOLD_N: u16 = 100;

/// Minimum threshold M (required signatures).
pub const MIN_THRESHOLD_M: u16 = 1;

#[cfg(test)]
pub mod test {
    use super::*;

    /// Test session timeout (1 minute).
    pub const TEST_SESSION_TIMEOUT_NS: u64 = 60 * NANOS_PER_SECOND;

    /// Test event amount (1 KAS).
    pub const TEST_EVENT_AMOUNT: u64 = 100_000_000;
}
