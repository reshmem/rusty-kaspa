# Domain/Infrastructure Refactor – Step 8

## Plan (before changes)
- Move the pure coordination threshold helper into the domain layer.
- Keep existing public surface working by leaving a shim in `coordination/threshold.rs`.
- Update domain facade to expose the new coordination namespace.
- Run the core + service test suite to ensure no regressions.

## Notes after implementation
- Added `domain/coordination/` with `threshold.rs`; unchanged logic, just relocated.
- `coordination/threshold.rs` now re-exports the domain version to avoid breakage.
- `coordination/mod.rs` continues to re-export domain hashes/policy, and `domain/mod.rs` now exposes `coordination`.
- Tests: `cargo test -p igra-core -p igra-service -- --nocapture` still passes.
