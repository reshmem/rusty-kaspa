# Domain/Infrastructure Refactor – Step 5

## Plan (before changes)
- Move the request lifecycle FSM into the domain layer:
  - Relocate `state_machine.rs` to `domain/state_machine.rs`.
  - Update `domain/mod.rs` to own and re-export the module.
  - Leave a shim at the old path (`state_machine.rs`) that re-exports the new location to keep imports working.
- Run the full test suite to verify no regressions.

## Notes after implementation
- Moved the FSM into `domain/state_machine.rs`; old `state_machine.rs` now re-exports the domain module.
- Updated `domain/mod.rs` to expose the new module.
- All tests still pass (`cargo test -p igra-core -p igra-service -- --nocapture`), with only the pre-existing test-harness lint warnings.
