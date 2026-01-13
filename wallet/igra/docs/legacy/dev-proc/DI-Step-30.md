# Domain/Infrastructure Refactor – Step 30 (Transport move to iroh namespace)

## Plan (before changes)
- Move the actual transport implementation (identity/messages/mock/traits) under `infrastructure/transport/iroh/` and turn the old top-level files into shims.
- Keep public APIs stable; re-export from the new module paths.
- Validate with full tests.

## Notes after implementation
- Created `infrastructure/transport/iroh/{identity.rs,messages.rs,mock.rs,traits.rs}` and moved the existing implementations there.
- Converted the prior `infrastructure/transport/{identity,messages,mock,traits}.rs` into thin re-exports of the iroh versions.
- Made the transport traits module public so it can be re-exported.
- Tests: `cargo test -p igra-core -p igra-service -- --nocapture` pass (existing warning noise only).
