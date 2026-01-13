# Domain/Infrastructure Refactor – Step 20

## Plan (before changes)
- Move the event ingestion pipeline (EventProcessor, EventContext, submit_signing_event) into the `infrastructure` layer, keeping the legacy `event` module as a shim.
- Preserve behavior and public API; no functional changes.
- Validate with the existing core/service test suite.

## Notes after implementation
- Added `infrastructure/event/mod.rs` containing the event ingestion logic; `event/mod.rs` now re-exports the infra module.
- Updated `infrastructure/mod.rs` to export `event` so infra is the canonical home.
- Tests: `cargo test -p igra-core -p igra-service -- --nocapture` pass (only pre-existing warning noise).
