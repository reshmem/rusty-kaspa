# Domain/Infrastructure Refactor – Step 15

## Plan (before changes)
- Move Hyperlane ISM verification into the `infrastructure` namespace while keeping the legacy `hyperlane` path intact via a shim.
- Preserve behavior (config-driven validator sets, proof verification) and public API.
- No additional test run needed beyond the latest green suite.

## Notes after implementation
- Added `infrastructure/hyperlane/mod.rs` containing the ISM types, verifier trait, and `ConfiguredIsm` implementation.
- `hyperlane/mod.rs` now re-exports the infra module to keep existing imports working.
- Behavior unchanged; groundwork laid for future infra consolidation.
