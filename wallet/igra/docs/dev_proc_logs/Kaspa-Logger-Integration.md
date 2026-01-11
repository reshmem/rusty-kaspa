# Kaspa Logger Integration

This document outlines the plan to switch igra from `tracing` + `tracing_subscriber` to `log` + `log4rs` - the same logging stack used by rusty-kaspa, but as a direct dependency (not through `kaspa_core`).

---

## Current State

### igra (Current)
```rust
// igra-service/src/bin/kaspa-threshold-service/setup.rs
use tracing_subscriber;

tracing_subscriber::fmt()
    .with_env_filter(filter)
    .with_target(false)
    .with_thread_ids(false)
    .with_ansi(use_ansi)
    .compact()
    .try_init();
```

**Output Format:**
```
2026-01-11T19:57:44.794475Z  INFO logging initialized level=info
```

### rusty-kaspa (Reference)
```rust
// kaspa-core/src/log/mod.rs - uses log + log4rs
kaspa_core::log::init_logger(log_dir.as_deref(), &args.log_level);
```

**Output Format:**
```
2024-01-12 14:30:45.123+01:00 [INFO ] message
```

---

## Why `log` + `log4rs` Directly?

We use the same stack as rusty-kaspa (`log` + `log4rs`) but as direct dependencies, not through `kaspa_core::log`. This keeps igra lightweight and independent.

| Feature | tracing_subscriber | log + log4rs |
|---------|-------------------|--------------|
| Log rotation | Manual (tracing-appender) | Built-in (size-based) |
| Error log separation | No | Yes (separate `*_err.log`) |
| Archive compression | No | Yes (gzip) |
| Pattern customization | Limited | Full log4rs patterns |
| Module filtering | Yes | Yes |
| Thread ID | Yes | Yes |
| File:Line | No (unless spans) | Yes |
| Dependency weight | Light | Light |
| Needs kaspa_core | No | No |

### Why NOT kaspa_core::log?

- `kaspa_core` is a heavy dependency (pulls in many kaspa modules)
- `kaspa_core::log` is just a thin wrapper around `log` + `log4rs`
- igra doesn't need WASM support (which is the main value-add of kaspa_core::log)
- Direct `log4rs` gives us full control over configuration

---

## Proposed Log Format

### Pattern for Console (with colors)
```
{d(%Y-%m-%d %H:%M:%S%.3f)} [{h({({l}):5.5})}] {m} [{I}][{f}:{L}]{n}
```

### Pattern for File (no colors)
```
{d(%Y-%m-%d %H:%M:%S%.3f)} [{({l}):5.5}] {m} [{I}][{f}:{L}]{n}
```

### Pattern Variables
| Variable | Description | Example |
|----------|-------------|---------|
| `{d(...)}` | Timestamp with format | `2024-01-12 14:30:45.123` |
| `{l}` | Log level | `INFO` |
| `{h(...)}` | Highlight/color wrapper | (colors the level) |
| `{m}` | Log message | `service started` |
| `{I}` | Thread ID | `5` |
| `{f}` | Source file name | `setup.rs` |
| `{L}` | Line number | `42` |
| `{n}` | Newline | |

### Example Output
```
2024-01-12 14:30:45.123 [INFO ] logging initialized level=info [1][setup.rs:28]
2024-01-12 14:30:45.124 [INFO ] loading application config profile path=/tmp/config.toml [1][setup.rs:44]
2024-01-12 14:30:45.150 [INFO ] coordination loop started group_id=b2278b... [5][loop.rs:52]
2024-01-12 14:30:46.200 [WARN ] hyperlane signing event rejected error=invalid recipient [12][hyperlane.rs:470]
2024-01-12 14:35:45.123 [INFO ] === SESSION COMPLETE === outcome=SUCCESS duration_ms=4500 [5][loop.rs:277]
```

---

## Implementation Plan

### Phase 1: Add Dependencies

**File: `igra-core/Cargo.toml`**
```toml
[dependencies]
log = "0.4"
log4rs = "1.2"
```

**File: `igra-service/Cargo.toml`**
```toml
[dependencies]
log = "0.4"
# log4rs only needed if service does its own init (usually igra-core handles it)
```

### Phase 2: Create Custom Log Format Constants

**File: `igra-core/src/infrastructure/logging/consts.rs`**
```rust
//! IGRA-specific logging constants.
//! Extends kaspa_core::log with thread ID and file:line info.

/// Log file name for igra services
pub const LOG_FILE_NAME: &str = "igra.log";
/// Error log file name
pub const ERR_LOG_FILE_NAME: &str = "igra_err.log";

/// Console log pattern with thread ID and file:line at end (colored)
/// Format: timestamp [LEVEL] message [THREAD-ID][file:line]
pub const LOG_LINE_PATTERN_COLORED: &str =
    "{d(%Y-%m-%d %H:%M:%S%.3f)} [{h({({l}):5.5})}] {m} [{I}][{f}:{L}]{n}";

/// File log pattern with thread ID and file:line at end (no colors)
pub const LOG_LINE_PATTERN: &str =
    "{d(%Y-%m-%d %H:%M:%S%.3f)} [{({l}):5.5}] {m} [{I}][{f}:{L}]{n}";

/// Maximum log file size before rotation (50 MB)
pub const LOG_FILE_MAX_SIZE: u64 = 50_000_000;

/// Maximum number of archived log files
pub const LOG_FILE_MAX_ROLLS: u32 = 5;
```

### Phase 3: Create IGRA Logger Initialization

**File: `igra-core/src/infrastructure/logging/mod.rs`**
```rust
//! Logging infrastructure using kaspa_core::log backend.

mod consts;

pub use consts::*;
use log::LevelFilter;
use log4rs::{
    append::{
        console::ConsoleAppender,
        rolling_file::{
            policy::compound::{
                roll::fixed_window::FixedWindowRoller,
                trigger::size::SizeTrigger,
                CompoundPolicy,
            },
            RollingFileAppender,
        },
    },
    config::{Appender, Logger, Root},
    encode::pattern::PatternEncoder,
    filter::threshold::ThresholdFilter,
    Config,
};
use std::path::PathBuf;

const CONSOLE_APPENDER: &str = "stdout";
const LOG_FILE_APPENDER: &str = "log_file";
const ERR_LOG_FILE_APPENDER: &str = "err_log_file";

/// Initialize the IGRA logger with optional file output.
///
/// # Arguments
/// * `log_dir` - Optional directory for log files. If None, only console output.
/// * `filters` - Log level filter expression (e.g., "info,igra_core=debug")
///
/// # Example
/// ```ignore
/// init_logger(Some("/var/log/igra"), "info,igra_core=debug");
/// ```
pub fn init_logger(log_dir: Option<&str>, filters: &str) {
    let root_level = parse_root_level(filters);
    let loggers = parse_module_levels(filters);

    // Console appender with colors and thread ID
    let console = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(LOG_LINE_PATTERN_COLORED)))
        .build();

    let mut config_builder = Config::builder()
        .appender(Appender::builder().build(CONSOLE_APPENDER, Box::new(console)));

    let mut root_appenders = vec![CONSOLE_APPENDER];

    // File appender with rotation
    if let Some(dir) = log_dir {
        let log_path = PathBuf::from(dir).join(LOG_FILE_NAME);
        let archive_pattern = PathBuf::from(dir).join(format!("{}.{{}}.gz", LOG_FILE_NAME));

        let roller = FixedWindowRoller::builder()
            .base(1)
            .build(archive_pattern.to_str().unwrap(), LOG_FILE_MAX_ROLLS)
            .unwrap();

        let trigger = SizeTrigger::new(LOG_FILE_MAX_SIZE);
        let policy = CompoundPolicy::new(Box::new(trigger), Box::new(roller));

        let file_appender = RollingFileAppender::builder()
            .encoder(Box::new(PatternEncoder::new(LOG_LINE_PATTERN)))
            .build(log_path, Box::new(policy))
            .unwrap();

        config_builder = config_builder
            .appender(Appender::builder().build(LOG_FILE_APPENDER, Box::new(file_appender)));
        root_appenders.push(LOG_FILE_APPENDER);

        // Error-only log file
        let err_log_path = PathBuf::from(dir).join(ERR_LOG_FILE_NAME);
        let err_archive_pattern = PathBuf::from(dir).join(format!("{}.{{}}.gz", ERR_LOG_FILE_NAME));

        let err_roller = FixedWindowRoller::builder()
            .base(1)
            .build(err_archive_pattern.to_str().unwrap(), LOG_FILE_MAX_ROLLS)
            .unwrap();

        let err_trigger = SizeTrigger::new(LOG_FILE_MAX_SIZE);
        let err_policy = CompoundPolicy::new(Box::new(err_trigger), Box::new(err_roller));

        let err_file_appender = RollingFileAppender::builder()
            .encoder(Box::new(PatternEncoder::new(LOG_LINE_PATTERN)))
            .build(err_log_path, Box::new(err_policy))
            .unwrap();

        config_builder = config_builder.appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(LevelFilter::Warn)))
                .build(ERR_LOG_FILE_APPENDER, Box::new(err_file_appender)),
        );
        root_appenders.push(ERR_LOG_FILE_APPENDER);
    }

    // Add module-specific loggers
    for (module, level) in loggers {
        config_builder = config_builder.logger(
            Logger::builder()
                .appenders(root_appenders.iter().map(|s| s.to_string()))
                .build(module, level),
        );
    }

    let config = config_builder
        .build(Root::builder().appenders(root_appenders).build(root_level))
        .unwrap();

    let _ = log4rs::init_config(config);
}

fn parse_root_level(filters: &str) -> LevelFilter {
    for part in filters.split(',') {
        let part = part.trim();
        if !part.contains('=') {
            if let Ok(level) = part.parse() {
                return level;
            }
        }
    }
    LevelFilter::Info
}

fn parse_module_levels(filters: &str) -> Vec<(String, LevelFilter)> {
    let mut result = Vec::new();
    for part in filters.split(',') {
        let part = part.trim();
        if let Some((module, level_str)) = part.split_once('=') {
            if let Ok(level) = level_str.parse() {
                result.push((module.to_string(), level));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_root_level() {
        assert_eq!(parse_root_level("info"), LevelFilter::Info);
        assert_eq!(parse_root_level("debug"), LevelFilter::Debug);
        assert_eq!(parse_root_level("info,igra=debug"), LevelFilter::Info);
        assert_eq!(parse_root_level("igra=debug"), LevelFilter::Info); // default
    }

    #[test]
    fn test_parse_module_levels() {
        let levels = parse_module_levels("info,igra_core=debug,igra_service=trace");
        assert_eq!(levels.len(), 2);
        assert_eq!(levels[0], ("igra_core".to_string(), LevelFilter::Debug));
        assert_eq!(levels[1], ("igra_service".to_string(), LevelFilter::Trace));
    }
}
```

### Phase 4: Update Service Initialization

**File: `igra-service/src/bin/kaspa-threshold-service/setup.rs`**
```rust
use igra_core::infrastructure::logging;
use log::{info, warn, debug, error};  // Standard log macros

pub fn init_logging(log_dir: Option<&str>, level: &str) -> Result<(), ThresholdError> {
    logging::init_logger(log_dir, level);

    // Initialize audit logger (separate concern)
    igra_core::infrastructure::audit::init_audit_logger(
        Box::new(igra_core::infrastructure::audit::StructuredAuditLogger)
    );

    info!("logging initialized level={}", level);
    Ok(())
}
```

### Phase 5: Replace tracing Macros

**Search and replace across igra codebase:**

| From | To |
|------|-----|
| `use tracing::{info, warn, debug, error, trace};` | `use log::{info, warn, debug, error, trace};` |
| `tracing::info!` | `log::info!` |
| `#[tracing::instrument]` | Remove (log manually) |

**Note:** The `#[tracing::instrument]` decorator creates automatic spans. With log4rs, we need to log entry/exit manually if needed:
```rust
// Before (tracing)
#[tracing::instrument(skip(self))]
fn process(&self, data: &[u8]) -> Result<()> {
    // ...
}

// After (log)
fn process(&self, data: &[u8]) -> Result<()> {
    debug!("process called data_len={}", data.len());
    let result = /* ... */;
    debug!("process complete");
    result
}
```

---

## Migration Checklist

### Phase 1: Dependencies
- [ ] Add `log = "0.4"` to `igra-core/Cargo.toml`
- [ ] Add `log4rs = "1.2"` to `igra-core/Cargo.toml`
- [ ] Add `log = "0.4"` to `igra-service/Cargo.toml`
- [ ] Run `cargo check`

### Phase 2: Logger Module
- [ ] Create `igra-core/src/infrastructure/logging/mod.rs`
- [ ] Create `igra-core/src/infrastructure/logging/consts.rs`
- [ ] Export from `igra-core/src/infrastructure/mod.rs`
- [ ] Write tests

### Phase 3: Service Integration
- [ ] Update `setup.rs` to use new logger
- [ ] Test console output format
- [ ] Test file output and rotation
- [ ] Test error log separation

### Phase 4: Replace Macros
- [ ] Replace imports in `igra-core/src/**/*.rs`
- [ ] Replace imports in `igra-service/src/**/*.rs`
- [ ] Remove `#[tracing::instrument]` attributes
- [ ] Add manual entry/exit logs where needed
- [ ] Run `cargo check`

### Phase 5: Cleanup
- [ ] Remove `tracing` dependency from `igra-core`
- [ ] Remove `tracing-subscriber` dependency from `igra-service`
- [ ] Remove old `setup::init_logging` code
- [ ] Run full test suite

### Phase 6: Testing
- [ ] Start service with console only: `--no-log-files`
- [ ] Start service with file logging
- [ ] Verify log rotation works (create large log)
- [ ] Verify error log separation
- [ ] Verify module-level filtering: `info,igra_core::application=debug`

---

## Log Level Guidelines

| Level | When to Use | Example |
|-------|------------|---------|
| `error!` | Unrecoverable failures | "failed to open database" |
| `warn!` | Recoverable issues, degraded state | "retrying RPC connection" |
| `info!` | Significant state changes, milestones | "session completed", "service started" |
| `debug!` | Detailed operational info | "received proposal", "validation passed" |
| `trace!` | Very detailed debugging | "parsing PSKT byte 42" |

---

## File Output Structure

```
/var/log/igra/
├── igra.log              # All logs (rotated)
├── igra.log.1.gz         # Archive 1
├── igra.log.2.gz         # Archive 2
├── ...
├── igra_err.log          # WARN+ only (rotated)
├── igra_err.log.1.gz
└── ...
```

---

## Backward Compatibility

### Audit Logging
The audit logging system (`igra_core::infrastructure::audit`) is independent and uses `serde_json` for structured output. It does NOT need to change.

### Metrics
The Prometheus metrics system is independent and does NOT need to change.

### Structured Fields
The `log` crate doesn't support structured fields like tracing. Convert:
```rust
// Before (tracing)
info!(session_id = %session_id, amount = amount, "processing");

// After (log)
info!("processing session_id={} amount={}", session_id, amount);
```

---

## Example: Full Service Startup Log

```
2024-01-12 14:30:45.100 [INFO ] logging initialized level=info [1][setup.rs:28]
2024-01-12 14:30:45.101 [INFO ] loading application config [1][setup.rs:35]
2024-01-12 14:30:45.110 [INFO ] initializing storage data_dir=/var/lib/igra [1][setup.rs:75]
2024-01-12 14:30:45.150 [INFO ] RocksStorage opened path=/var/lib/igra/threshold-signing [1][engine.rs:45]
2024-01-12 14:30:45.151 [INFO ] using iroh identity from config peer_id=signer-1 [1][setup.rs:90]
2024-01-12 14:30:45.152 [INFO ] group_id validated group_id=b2278b4e... [1][setup.rs:121]
2024-01-12 14:30:45.153 [INFO ] ╔═══════════════════════════════════════════╗ [1][setup.rs:136]
2024-01-12 14:30:45.153 [INFO ] ║    IGRA Threshold Signing Service         ║ [1][setup.rs:137]
2024-01-12 14:30:45.153 [INFO ] ╠═══════════════════════════════════════════╣ [1][setup.rs:138]
2024-01-12 14:30:45.153 [INFO ] ║ Peer ID:   signer-1                       ║ [1][setup.rs:139]
2024-01-12 14:30:45.153 [INFO ] ║ Group ID:  b2278b4e...                    ║ [1][setup.rs:140]
2024-01-12 14:30:45.153 [INFO ] ║ Threshold: 2/3 signers                    ║ [1][setup.rs:141]
2024-01-12 14:30:45.153 [INFO ] ╚═══════════════════════════════════════════╝ [1][setup.rs:145]
2024-01-12 14:30:45.200 [INFO ] starting json-rpc server addr=0.0.0.0:8088 [1][main.rs:85]
2024-01-12 14:30:45.201 [INFO ] coordination loop started group_id=b2278b4e peer_id=signer-1 [5][loop.rs:52]
2024-01-12 14:30:45.202 [INFO ] HTTP server ready addr=0.0.0.0:8088 [6][router.rs:25]
```

---

## References

- [log crate](https://docs.rs/log/latest/log/) - Standard Rust logging facade
- [log4rs documentation](https://docs.rs/log4rs/latest/log4rs/) - Logging backend
- [log4rs pattern syntax](https://docs.rs/log4rs/latest/log4rs/encode/pattern/index.html) - Pattern format reference
- [kaspa-core/src/log/](../../../core/src/log/) - rusty-kaspa implementation (for reference)
