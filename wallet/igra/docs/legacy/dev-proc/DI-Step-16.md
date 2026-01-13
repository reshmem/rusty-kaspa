# Domain/Infrastructure Refactor – Step 16

## Plan (before changes)
- Move storage (trait + RocksDB impl) into the `infrastructure` namespace while keeping the legacy `storage` path via a shim.
- Preserve behavior and public API surface.

## Notes after implementation
- Added `infrastructure/storage/mod.rs` and `infrastructure/storage/rocks.rs` with the existing storage trait and RocksDB implementation.
- `storage/mod.rs` now re-exports from `infrastructure::storage`, keeping prior imports working.
- No functional changes; relies on the same code, just relocated for the infra layer.
