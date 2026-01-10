# Domain/Infrastructure Refactor – Step 3

## Plan (before changes)
- Scaffold a `domain` module that cleanly exposes the pure/business logic surface while keeping existing code in place.
- Create `igra-core/src/domain/mod.rs` that re-exports current domain-friendly modules (state machine, signing, pskt, model) and existing pure helpers (coordination hashes, policy enforcement) without moving files yet.
- Add `domain` to `lib.rs` so downstream code can start importing from the new namespace.
- Keep all behavior unchanged; this is an organizational shim only.
- Run full tests to confirm no regressions.

## Notes after implementation
- Added `igra-core/src/domain/mod.rs` re-exporting `model`, `pskt`, `signing`, `state_machine`, and aliases for `coordination::hashes` and `coordination::policy`.
- Exposed `domain` in `lib.rs` (non-breaking re-export layer).
- All tests still pass (`cargo test -p igra-core -p igra-service -- --nocapture`), aside from the existing test-harness lint warnings.
