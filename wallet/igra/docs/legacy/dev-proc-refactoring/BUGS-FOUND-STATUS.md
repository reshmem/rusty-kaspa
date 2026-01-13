# BUGS-FOUND.md status

**Date**: 2026-01-10

This file tracks what was implemented from `BUGS-FOUND.md` after the domain/infra refactor (file paths in the bug report may differ from current layout).

## Implemented (with notes)

- **#1 + #2 (API rate limiter)**: Implemented per-IP buckets + fail-closed on poisoned lock.
  - Files: `igra-service/src/api/middleware/rate_limit.rs`, `igra-service/src/api/router.rs`
  - Tests updated to serve with connect-info: `igra-service/tests/api/mod.rs`, `igra-service/tests/integration/rpc/*`

- **#3 + #4 + #10 + #11 + #12 + #66 (MemoryStorage correctness)**: Added replay protection, state transition validation, fixed seen-message timestamp tracking + cleanup, removed incorrect volume tracking from `mark_seen_message`, made `begin_batch` fail loudly (no silent no-op), and removed `Mutex::lock().unwrap()` panics via `lock_inner()`.
  - File: `igra-core/src/infrastructure/storage/memory.rs`

- **#5 (Hyperlane signature parsing cap)**: Added a hard cap on signature chunk count and pre-allocated the vector.
  - File: `igra-core/src/domain/validation/hyperlane.rs`

- **#8 (Atomic ordering)**: Changed iroh client `seq_no` increments to `AcqRel`.
  - File: `igra-core/src/infrastructure/transport/iroh/client.rs`

- **#13 (Rocks request updates should not silently succeed)**: `update_request_decision`, `update_request_final_tx`, `update_request_final_tx_score` now error on missing request.
  - File: `igra-core/src/infrastructure/storage/rocks/engine.rs`

- **#14 (Coordinator collect_acks can hang forever)**: Added timeout + threshold-based exit (signature changed; previously unused).
  - File: `igra-core/src/application/coordinator.rs`

- **#15 (Hardcoded derivation path)**: Added `hyperlane.default_derivation_path` to config, loader support, and RPC state wiring; hyperlane handler now uses the configured value.
  - Files: `igra-core/src/infrastructure/config/types.rs`, `igra-core/src/infrastructure/config/loader.rs`, `igra-service/src/api/state.rs`, `igra-service/src/api/handlers/hyperlane.rs`, `igra-service/src/bin/kaspa-threshold-service.rs`

- **#16 + #39 + #58 (Volume calculation correctness/perf)**: Removed the “sum all finalized events regardless of day” fallback; added event de-dup in scan; changed index lookup to point-get for the queried day.
  - File: `igra-core/src/infrastructure/storage/rocks/engine.rs`

- **#18 (Partial sigs dropped during collection)**: Persist partial sigs to storage during the finalize collection loop.
  - File: `igra-service/src/service/coordination/finalization.rs`

- **#19 + #45 (has_threshold correctness/perf)**: Removed the overly-strict early-return and avoided per-input pre-allocation.
  - File: `igra-core/src/domain/coordination/threshold.rs`

- **#21 (Fee split assertion after rounding)**: Removed the assertion; `signer_fee = fee.saturating_sub(recipient_fee)` already guarantees consistency.
  - File: `igra-core/src/domain/pskt/builder.rs`

- **#23 + #17 (Hyperlane domain/threshold correctness)**:
  - `threshold == 0` now errors during ISM config build (instead of “N-of-N”).
  - ISM validator lookup uses `message.origin` (not destination).
  - File: `igra-core/src/infrastructure/hyperlane/mod.rs`

- **#24 (PSKT invalid input index error detail)**: Use `ThresholdError::InvalidInputIndex { index, max }`.
  - File: `igra-core/src/domain/pskt/multisig.rs`

- **#27 (session active race)**: Mark session active before spawning finalize task.
  - File: `igra-service/src/service/coordination/loop_.rs`

- **#38 (seen cleanup cutoff uses sender timestamp)**: Cleanup cutoff now uses local time (not sender-provided timestamps).
  - File: `igra-core/src/infrastructure/transport/iroh/filtering.rs`

- **#25 (policy min/max consistency)**: `AppConfig::validate()` now rejects `policy.min_amount_sompi > policy.max_amount_sompi`.
  - File: `igra-core/src/infrastructure/config/validation.rs`

- **#28 (expiry skew tolerance)**: Relaxed `expires_at_nanos` validation to allow clock skew (±30s) and avoid rejecting valid sessions.
  - File: `igra-core/src/application/signer.rs`

- **#29 (derivation mismatch diagnostics)**: `InvalidDerivationPath` now includes expected vs actual values; derivation paths are validated for basic format.
  - File: `igra-core/src/domain/event/validation.rs`

- **#30 (monitor errors ignored)**: Transaction monitor + score update failures are now logged.
  - File: `igra-service/src/service/coordination/finalization.rs`

- **#31 (group.network_id parse failure)**: `group.network_id` now errors on parse failure instead of silently falling back.
  - File: `igra-core/src/infrastructure/config/loader.rs`

- **#33 (circuit breaker state race)**: Circuit breaker now uses a single mutex-protected state instead of mixed atomics/locks.
  - File: `igra-core/src/infrastructure/rpc/circuit_breaker.rs`

- **#34 (transport rate limiter cleanup)**: Rate limiter now self-cleans periodically during `check_rate_limit*` calls.
  - File: `igra-core/src/infrastructure/transport/rate_limiter.rs`

- **#49 (active sessions leak on panic)**: Finalization task now uses `catch_unwind` and always clears the active session entry.
  - File: `igra-service/src/service/coordination/loop_.rs`

- **#54 (proposal stored twice / self-publish duplicates)**: Outgoing iroh publish paths no longer call `record_payload`; incoming proposal handling treats `EventReplayed` as idempotent to allow self-messages through.
  - Files: `igra-core/src/infrastructure/transport/iroh/client.rs`, `igra-core/src/infrastructure/transport/iroh/filtering.rs`

- **#61 + #73 (PSKT errors not specific)**: Converted several PSKT validation errors from `Message` to `PsktValidationFailed`.
  - Files: `igra-core/src/domain/pskt/validation.rs`, `igra-core/src/domain/pskt/builder.rs`

- **#67 (seen timestamp corruption handling)**: Rocks cleanup now logs and skips corrupted timestamps instead of coercing to zero.
  - File: `igra-core/src/infrastructure/storage/rocks/engine.rs`

- **#68 (submit_transaction not retried)**: Coordinator finalization retries submit with exponential backoff.
  - File: `igra-core/src/application/coordinator.rs`

- **#78 (recovery id error detail)**: Hyperlane signature recovery now reports invalid recovery id with the raw value.
  - File: `igra-core/src/infrastructure/hyperlane/mod.rs`

- **#79 + #47 (insufficient signatures message + prealloc)**: Finalizer errors now include counts; signature buffer prealloc added.
  - File: `igra-core/src/domain/pskt/multisig.rs`

- **#98 + #100 (destination/amount validation)**: Policy enforcement now rejects invalid destination addresses and `amount_sompi == 0`.
  - File: `igra-core/src/domain/policy/enforcement.rs`

- **#96 + #97 (unbounded RequestId/PeerId)**: Enforced max length at the external decoding boundary (RPC params → ids).
  - File: `igra-core/src/domain/event/validation.rs`

## Reviewed / not implemented (yet)

- **#6 (Rocks insert_event TOCTOU)**: Not implemented. A proper fix needs transactional semantics (e.g., TransactionDB) or a different storage strategy; current keying makes inserts idempotent but cannot guarantee “replay must error” under true concurrency.

- **#7 (PartialSigSubmit request_id empty in backend signer)**: Implemented by changing `SignerBackend::sign` to accept `&RequestId` and populating it in `ThresholdSigner`.
  - Note: This required updating callers + a few integration tests.

- **#9 (Decryption unwrap panic)**: Disagreed with the bug as written: `Encryptable::decrypt()` returns `Decrypted<T>` (not `Option<T>`). `Decrypted::unwrap()` is infallible in this codebase; leaving `.unwrap()` is safe.

## Build/validation performed

- `RUSTC_WRAPPER= CARGO_TARGET_DIR=target cargo check -p igra-core -p igra-service`
- `RUSTC_WRAPPER= CARGO_TARGET_DIR=target cargo test -p igra-core -p igra-service --tests --no-run`
