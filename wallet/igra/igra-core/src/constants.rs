//! System-wide constants for Igra threshold signing.
//!
//! All magic numbers should be defined here for:
//! - Discoverability (one place to find all limits)
//! - Documentation (explain WHY each constant has its value)
//! - Easy tuning (change in one place)

// ============================================================================
// Time Constants
// ============================================================================

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

// ============================================================================
// Size Limits
// ============================================================================

/// Maximum message size for gossip transport (10 MB).
///
/// Prevents DoS attacks via oversized messages. This limit applies to:
/// - Serialized proposals
/// - Serialized signatures
/// - Any other gossip message
pub const MAX_MESSAGE_SIZE_BYTES: usize = 10 * 1024 * 1024;

/// Maximum number of UTXOs/inputs in a single PSKT.
///
/// Kaspa consensus limit for transaction inputs.
pub const MAX_PSKT_INPUTS: usize = 1000;

/// Maximum number of outputs in a single PSKT.
///
/// Kaspa consensus limit for transaction outputs.
pub const MAX_PSKT_OUTPUTS: usize = 1000;

/// Maximum size of event metadata in bytes (10 KB).
///
/// Prevents bloat in event records stored in database.
pub const MAX_EVENT_METADATA_SIZE: usize = 10 * 1024;

/// Maximum length of event ID string.
pub const MAX_EVENT_ID_LENGTH: usize = 256;

/// Maximum length of destination address string.
pub const MAX_ADDRESS_LENGTH: usize = 256;

// ============================================================================
// Cryptographic Constants
// ============================================================================

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

// ============================================================================
// Fee Calculation
// ============================================================================

/// Fee calculation precision scale (10^6).
///
/// Allows fee portions to be specified as fractions (e.g., 0.25 = 250,000 / 1,000,000).
/// Using fixed-point arithmetic ensures determinism across platforms.
pub const FEE_PRECISION_SCALE: u64 = 1_000_000;

/// Default fee in sompi (0.001 KAS = 100,000 sompi).
///
/// Typical Kaspa transaction fee for standard-sized transactions.
pub const DEFAULT_FEE_SOMPI: u64 = 100_000;

// ============================================================================
// Network and Gossip
// ============================================================================

/// Maximum number of bootstrap peers for gossip.
///
/// Prevents configuration errors where too many bootstrap peers
/// slow down connection establishment.
pub const MAX_BOOTSTRAP_PEERS: usize = 10;

/// Gossip publish retry attempts.
///
/// Number of times to retry failed gossip publish operations.
pub const GOSSIP_PUBLISH_RETRIES: usize = 3;

/// Delay between gossip publish retries in milliseconds.
pub const GOSSIP_RETRY_DELAY_MS: u64 = 200;

/// Maximum gossip topic length in bytes.
pub const MAX_GOSSIP_TOPIC_LENGTH: usize = 256;

// ============================================================================
// Rate Limiting
// ============================================================================

/// Rate limiter burst capacity (requests).
///
/// Maximum number of requests a peer can make in a burst before being throttled.
pub const RATE_LIMIT_CAPACITY: f64 = 100.0;

/// Rate limiter refill rate (requests per second).
///
/// Steady-state rate at which request quota is replenished.
pub const RATE_LIMIT_REFILL_RATE: f64 = 10.0;

/// Rate limiter cleanup interval in seconds.
///
/// How often to clean up old peer entries from the rate limiter cache.
pub const RATE_LIMIT_CLEANUP_INTERVAL_SECS: u64 = 300; // 5 minutes

// ============================================================================
// Storage
// ============================================================================

/// RocksDB write batch size (number of operations).
///
/// Batching improves write performance for bulk operations.
pub const ROCKSDB_WRITE_BATCH_SIZE: usize = 100;

/// RocksDB cache size in bytes (128 MB).
pub const ROCKSDB_CACHE_SIZE: usize = 128 * 1024 * 1024;

// ============================================================================
// Threshold Signing
// ============================================================================

/// Maximum threshold N (total signers).
pub const MAX_THRESHOLD_N: u16 = 100;

/// Minimum threshold M (required signatures).
pub const MIN_THRESHOLD_M: u16 = 1;

// ============================================================================
// Test Constants
// ============================================================================

#[cfg(test)]
pub mod test {
    use super::*;

    /// Test session timeout (1 minute).
    pub const TEST_SESSION_TIMEOUT_NS: u64 = 60 * NANOS_PER_SECOND;

    /// Test event amount (1 KAS).
    pub const TEST_EVENT_AMOUNT: u64 = 100_000_000;
}
