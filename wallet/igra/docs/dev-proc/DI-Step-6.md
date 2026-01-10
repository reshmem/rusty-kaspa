# Domain/Infrastructure Refactor – Step 6

## Plan (before changes)
- Move pure event types and helpers into the domain layer:
  - Create `domain/event.rs` containing `SigningEventWire`, `SigningEventParams`, `SigningEventResult`, `decode_hash32`, `resolve_derivation_path`, and the pure conversion `into_signing_event`.
  - Update `event/mod.rs` to use these domain types/helpers; keep I/O and storage concerns in `event/mod.rs`.
- Keep behavior unchanged; this is a structural move only.
- Run full tests to ensure no regressions.

## Notes after implementation
- Added `domain/event.rs` with the wire types and pure helpers; updated `domain/mod.rs` to re-export it.
- `event/mod.rs` now imports these domain types/functions and no longer defines them locally.
- All tests still pass (`cargo test -p igra-core -p igra-service -- --nocapture`), aside from pre-existing lint warnings in the test harness.
