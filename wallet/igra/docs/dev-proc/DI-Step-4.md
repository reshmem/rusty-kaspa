# Domain/Infrastructure Refactor – Step 4

## Plan (before changes)
- Move pure coordination helpers into the `domain` layer:
  - Relocate `coordination/hashes.rs` and `coordination/policy.rs` into `domain/` as first true domain moves.
  - Update imports to use `crate::foundation` and `crate::domain::*`.
  - Maintain backward compatibility by re-exporting these modules from `coordination` (shim) so existing paths continue working.
- Run full tests to ensure no regressions.

## Notes after implementation
- Moved `coordination/hashes.rs` → `domain/hashes.rs` and `coordination/policy.rs` → `domain/policy.rs`, keeping logic unchanged.
- Updated `coordination/mod.rs` to re-export `domain::{hashes, policy}` while keeping other coordination modules intact.
- Updated all consumers to import via the new paths.
- Full test suite still passes (`cargo test -p igra-core -p igra-service -- --nocapture`), only the pre-existing test-harness lint warnings remain.
