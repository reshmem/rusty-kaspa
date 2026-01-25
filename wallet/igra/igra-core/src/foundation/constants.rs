//! System-wide constants for Igra threshold signing.

/// Nanoseconds per second (10^9).
pub const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Nanoseconds per day (24 * 60 * 60 * 10^9).
///
/// Used for volume limit calculations aligned to UTC days.
pub const NANOS_PER_DAY: u64 = 24 * 60 * 60 * NANOS_PER_SECOND;

/// Environment variable used to override wall-clock time for deterministic tests.
pub const TEST_NOW_NANOS_ENV_VAR: &str = "KASPA_IGRA_TEST_NOW_NANOS";

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

/// Max gRPC message size for kaspad RPC client, in bytes.
///
/// This is passed as the `max_message_size`/`max_decoding_message_size` argument to `kaspa_grpc_client::GrpcClient`.
pub const GRPC_MAX_MESSAGE_SIZE_BYTES: u64 = 500_000;

/// Maximum number of UTXOs/inputs in a single PSKT.
pub const MAX_PSKT_INPUTS: usize = 1000;

/// Maximum number of outputs in a single PSKT.
pub const MAX_PSKT_OUTPUTS: usize = 1000;

/// Maximum size of event metadata in bytes (16 KiB).
///
/// This caps untrusted `metadata` / `source_data` maps to prevent log/DB amplification.
pub const MAX_EVENT_METADATA_SIZE: usize = 16 * 1024;

/// Maximum length of externally-provided identifiers before canonicalization.
pub const MAX_EXTERNAL_ID_RAW_LENGTH: usize = 128;

/// Maximum number of key/value pairs allowed in event metadata.
pub const MAX_EVENT_METADATA_KEYS: usize = 64;

/// Maximum length (bytes) of a single metadata key.
pub const MAX_EVENT_METADATA_KEY_LENGTH: usize = 64;

/// Maximum length (bytes) of a single metadata value.
pub const MAX_EVENT_METADATA_VALUE_LENGTH: usize = 2048;

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

/// Circuit breaker base backoff duration (seconds).
pub const CIRCUIT_BREAKER_BASE_BACKOFF_SECS: u64 = 1;

/// How often to emit aggregated gossip publish stats (nanos).
pub const GOSSIP_PUBLISH_INFO_REPORT_INTERVAL_NANOS: u64 = 30 * NANOS_PER_SECOND;

/// How long to retain "seen message" entries for replay protection (nanos).
pub const SEEN_MESSAGE_TTL_NANOS: u64 = NANOS_PER_DAY;

/// Run seen-message cleanup every N accepted messages.
pub const SEEN_MESSAGE_CLEANUP_INTERVAL_MESSAGES: u64 = 500;

/// Max age of per-peer rate limiter buckets (seconds).
pub const RATE_LIMITER_BUCKET_MAX_AGE_SECS: u64 = 15 * 60;

/// API/RPC rate limiter cleanup interval (seconds).
pub const RPC_RATE_LIMIT_CLEANUP_INTERVAL_SECS: u64 = 60;

/// API/RPC rate limiter entry TTL (seconds).
pub const RPC_RATE_LIMIT_ENTRY_TTL_SECS: u64 = 15 * 60;

/// API/RPC fixed-window size for per-IP rate limiting (seconds).
pub const RPC_RATE_LIMIT_WINDOW_SECS: u64 = 1;

/// Default kaspad gRPC URL (devnet/staging convenience).
pub const DEFAULT_NODE_RPC_URL: &str = "grpc://127.0.0.1:16110";

/// Default JSON-RPC listen address for igra-service.
pub const DEFAULT_RPC_ADDR: &str = "127.0.0.1:8088";

/// Default hyperlane polling interval (seconds).
pub const DEFAULT_POLL_SECS: u64 = 5;

/// Default PSKT sig-op count for standard multisig redeem scripts.
pub const DEFAULT_SIG_OP_COUNT: u8 = 2;

/// Default session timeout (seconds).
pub const DEFAULT_SESSION_TIMEOUT_SECS: u64 = 60;

// === Hyperlane Protocol Limits ===

/// Maximum size of a Hyperlane message body (1 MiB).
pub const MAX_HYPERLANE_BODY_SIZE_BYTES: usize = 1024 * 1024;

/// Maximum number of Hyperlane validators supported in config.
pub const MAX_HYPERLANE_VALIDATORS: usize = 256;

// === Configuration Limits ===

/// Maximum size of the main config file (10 MiB).
pub const MAX_CONFIG_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024;

/// Maximum number of profiles supported in config.
pub const MAX_PROFILES: usize = 100;

// === Protocol Timeouts ===

/// Maximum allowed proposal timeout (seconds).
pub const MAX_PROPOSAL_TIMEOUT_SECS: u64 = 600;

/// Maximum transaction submit attempts.
pub const MAX_SUBMIT_TX_ATTEMPTS: u32 = 4;

// === Storage Limits ===

/// RocksDB lock acquisition timeout (seconds).
pub const STORAGE_LOCK_TIMEOUT_SECS: u64 = 2;

/// Minimum required disk space (bytes).
pub const MIN_DISK_SPACE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Minimum open file limit.
pub const MIN_OPEN_FILE_LIMIT: u64 = 4096;

/// Default session expiry (seconds).
pub const DEFAULT_SESSION_EXPIRY_SECS: u64 = 600;

/// Default CRDT GC interval (seconds).
pub const DEFAULT_CRDT_GC_INTERVAL_SECS: u64 = 600;

/// Seconds per hour.
const SECONDS_PER_HOUR: u64 = 3600;

/// Hours per day.
const HOURS_PER_DAY: u64 = 24;

/// Default CRDT completed-state retention TTL (seconds).
/// Events older than this are eligible for garbage collection.
pub const DEFAULT_CRDT_GC_TTL_SECS: u64 = HOURS_PER_DAY * SECONDS_PER_HOUR;

/// Hyperlane domainId for Kaspa mainnet (`"KASM"` as big-endian ASCII).
///
/// Hyperlane domain IDs are a `u32` namespace and are not required to match any chain-native ID.
pub const HYPERLANE_DOMAIN_ID_KASPA_MAINNET: u32 = 0x4B41_534D;

/// Hyperlane domainId for Kaspa testnet (`"KAST"` as big-endian ASCII).
pub const HYPERLANE_DOMAIN_ID_KASPA_TESTNET: u32 = 0x4B41_5354;

/// Hyperlane domainId for Kaspa devnet (`"KASD"` as big-endian ASCII).
///
/// Note: our local devnet currently uses the legacy value `7` for compatibility with existing
/// scripts and configs. Use this constant for any future migration to an explicit namespace.
pub const HYPERLANE_DOMAIN_ID_KASPA_DEVNET: u32 = 0x4B41_5344;

// === Iroh Discovery Constants ===

/// Maximum time to wait for DHT bootstrap (milliseconds).
pub const DHT_BOOTSTRAP_TIMEOUT_MS: u64 = 10_000;

/// Pkarr record republish interval (seconds).
///
/// Records expire after ~3600s; republish at 50 minutes.
pub const PKARR_REPUBLISH_INTERVAL_SECS: u64 = 3_000;

/// Maximum custom relay URL length.
pub const MAX_RELAY_URL_LENGTH: usize = 256;

/// Default relay URL (Iroh's public relay).
pub const DEFAULT_RELAY_URL: &str = "https://relay.iroh.computer";

/// DNS discovery query timeout (milliseconds).
pub const DNS_DISCOVERY_TIMEOUT_MS: u64 = 5_000;

#[cfg(test)]
pub mod test {
    use super::*;

    /// Test session timeout (1 minute).
    pub const TEST_SESSION_TIMEOUT_NS: u64 = 60 * NANOS_PER_SECOND;

    /// Test event amount (1 KAS).
    pub const TEST_EVENT_AMOUNT: u64 = 100_000_000;
}
