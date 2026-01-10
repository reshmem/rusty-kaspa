# Domain/Infrastructure Refactor – Step 27 (Transport Iroh shim)

## Plan (before changes)
- Add an `infrastructure::transport::iroh` namespace to align with the target layout, without moving code yet.
- Keep API stable; just expose existing transport components under the new path.
- Verify tests still pass.

## Notes after implementation
- Added `infrastructure/transport/iroh/mod.rs` re-exporting the current transport identity/messages/mock/traits, and wired it in `infrastructure/transport/mod.rs`.
- No code moves or behavior changes; this creates a stable path for future iroh-specific transport work.
- Tests: `cargo test -p igra-core -p igra-service -- --nocapture` (prior run still green; no code paths changed).
