# Domain/Infrastructure Refactor – Step 17

## Plan (before changes)
- Move transport (messages, identity helpers, mock, trait) into the `infrastructure` namespace while keeping the legacy `transport` path via a shim.
- Preserve behavior and public API surface.

## Notes after implementation
- Added `infrastructure/transport/{mod.rs,identity.rs,messages.rs,mock.rs}` with the existing transport definitions.
- `transport/mod.rs` now re-exports from `infrastructure::transport`, so old imports still work.
- No functional changes; this is a structural move toward a clean infra layer.
