# Domain/Infrastructure Refactor – Step 26 (Domain event/policy directories)

## Plan (before changes)
- Introduce explicit domain subdirectories for event and policy to align with the desired layered layout.
- Move existing event parsing/hash helpers and policy enforcement into those directories while keeping public APIs stable via re-exports.
- Ensure full test suite remains green.

## Notes after implementation
- Added `domain/event/{mod.rs,types.rs,validation.rs,hashing.rs}` and moved the SigningEvent wire types, decode helpers, and hash re-exports there. `decode_session_and_request_ids` now lives in `domain::event::validation` and is re-exported by `domain::event`.
- Added `domain/policy/{mod.rs,enforcement.rs}` with the policy enforcer trait and default implementation (storage-free, takes current volume).
- Kept `domain/request/mod.rs` as a shim to the state machine for future expansion.
- Removed the old flat `domain/event.rs` and `domain/policy.rs` files that conflicted with the new module layout.
- Tests: `cargo test -p igra-core -p igra-service -- --nocapture` pass (existing warning noise only).
