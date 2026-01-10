# Domain/Infrastructure Refactor – Step 2

## Plan (before changes)
- Materialize the foundation layer by relocating shared primitives into `foundation/`:
  - Move `types.rs`, `error.rs`, `constants.rs`, and `util/` (conversion, encoding, time) into `foundation/`.
  - Leave compatibility shims in the original paths that re-export the new locations so existing imports keep working.
- Update `foundation/mod.rs` to own these modules and re-export them.
- Run full tests to confirm no breakage.

## Notes after implementation
- Added `foundation` submodules: `constants.rs`, `error.rs`, `types.rs`, and `util/` (conversion, encoding, time).
- Updated `foundation/mod.rs` to declare and re-export the moved modules.
- Replaced original `types.rs`, `error.rs`, `constants.rs`, and `util/mod.rs` with thin re-exports pointing to `foundation`.
- Full test suite still passes (`cargo test -p igra-core -p igra-service -- --nocapture`), only existing test-harness lint warnings remain.
