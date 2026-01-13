//! IGRA-specific logging constants.
//!
//! Uses `log` + `log4rs` with patterns compatible with the rest of rusty-kaspa.

/// Log file name for igra services.
pub const LOG_FILE_NAME: &str = "igra.log";
/// Error log file name (warn+error).
pub const ERR_LOG_FILE_NAME: &str = "igra_err.log";

/// Console log pattern (colored).
///
/// Format: `timestamp [LEVEL] message [module] [thread-id]`
pub const LOG_LINE_PATTERN_COLORED: &str = "{d(%Y-%m-%d %H:%M:%S%.3f)} [{h({l:5})}] {m} [{M}] [{I}]{n}";

/// File log pattern (no colors).
pub const LOG_LINE_PATTERN: &str = "{d(%Y-%m-%d %H:%M:%S%.3f)} [{l:5}] {m} [{M}] [{I}]{n}";

/// Maximum log file size before rotation (50 MB).
pub const LOG_FILE_MAX_SIZE: u64 = 50_000_000;

/// Maximum number of archived log files.
pub const LOG_FILE_MAX_ROLLS: u32 = 5;

/// Our crates that should log at INFO level by default.
/// Everything else defaults to WARN (whitelist approach).
pub const WHITELISTED_CRATES: &[&str] = &["igra_core", "igra_service"];
