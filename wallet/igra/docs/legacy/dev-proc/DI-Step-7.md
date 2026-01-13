# Domain/Infrastructure Refactor – Step 7

## Plan (before changes)
- Move message validation (hyperlane/layerzero/verifier helpers) into the domain layer so it is pure and independent of transport/storage.
- Replace `validation/*` modules with a thin re-export that points to the new domain location.
- Update imports (fuzz targets, devnet helper) to use the domain hashes path.
- Keep behavior identical; no functional changes intended.

## Notes after implementation
- Added `domain/validation/` with `hyperlane.rs`, `layerzero.rs`, `verifier.rs`, and `parse_validator_pubkeys`; all use `domain::hashes` and stay I/O-free.
- Simplified `validation/mod.rs` to re-export the domain validation module; removed old validation module files to avoid drift.
- Updated fuzz target and devnet fake hyperlane helper to import `domain::hashes`.
- Tests: `cargo test -p igra-core -p igra-service -- --nocapture` now passes (only pre-existing lint warnings in test harness).
