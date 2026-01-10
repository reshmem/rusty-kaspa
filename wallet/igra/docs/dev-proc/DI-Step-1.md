# Domain/Infrastructure Refactor – Step 1

## Plan (before changes)
- Introduce a `foundation` module to group shared primitives (types, error, constants, util) as the first migration step toward the layered architecture in `ARCHITECTURE-DOMAIN-INFRASTRUCTURE.md`.
- Keep existing module paths working by re-exporting the current modules from `foundation`, avoiding broad import churn in this step.
- Update `lib.rs` to expose the new `foundation` namespace.
- Verify the crate still builds and tests pass.

## Notes after implementation
- Added `igra-core/src/foundation/mod.rs` re-exporting `types`, `error`, `constants`, and `util`.
- Exposed the `foundation` module via `lib.rs`.
- All tests still pass (`cargo test -p igra-core -p igra-service -- --nocapture`).
