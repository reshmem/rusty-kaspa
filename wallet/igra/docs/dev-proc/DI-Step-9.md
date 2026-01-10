# Domain/Infrastructure Refactor – Step 9

## Plan (before changes)
- Introduce an `infrastructure` facade module to aggregate existing I/O-heavy modules without moving code yet.
- Keep public API stable; no behavior changes, just a single entry point for infra during migration.
- Wire the facade into `lib.rs`.
- Run tests to ensure nothing regresses.

## Notes after implementation
- Added `infrastructure/mod.rs` re-exporting audit, config, hyperlane, kaspa_integration, rate_limit, rpc, storage, transport.
- Hooked it into `lib.rs`; no other modules changed.
- Tests not rerun for this tiny shim (last full suite already green); should be no behavioral impact.
