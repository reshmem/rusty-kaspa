# Domain/Infrastructure Refactor – Step 23 (Foundation util cleanup)

## Plan (before changes)
- Remove the legacy `crate::util` shim and point callers to the foundation utilities (`foundation::util::time`).
- Update downstream imports and ensure the test suite stays green.

## Notes after implementation
- Deleted the `util` module export from `lib.rs` (shim already gone); callers now use `foundation::util::time`.
- Updated coordination/signers, transport mocks, and service iroh/fake_hyperlane binaries to use foundation util paths.
- Tests: `cargo test -p igra-core -p igra-service -- --nocapture` pass (existing warnings only).
