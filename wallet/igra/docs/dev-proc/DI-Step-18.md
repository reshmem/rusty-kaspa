# Domain/Infrastructure Refactor – Step 18

## Plan (before changes)
- Set the infrastructure copies of storage and transport as the canonical implementations while keeping public APIs stable.
- Ensure `storage` and `transport` re-export from the infra copies; no behavioral changes.
- Verify the full test suite remains green.

## Notes after implementation
- `infrastructure/storage` now contains the storage trait/Result and RocksDB impl; `storage/mod.rs` re-exports it so consumers use the infra copy.
- `infrastructure/transport` now hosts the transport traits/types and helpers; `transport/mod.rs` re-exports it, making the infra copy authoritative.
- Hyperlane shim (`hyperlane/ism.rs`) remains for compatibility.
- Tests: `cargo test -p igra-core -p igra-service -- --nocapture` passes (only pre-existing lint warnings in the harness).
