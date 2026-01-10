# Domain/Infrastructure Refactor – Step 24 (Foundation constants/types check)

## Plan (before changes)
- Confirm foundation is the canonical home for shared constants and types, and that legacy shims simply re-export foundation.
- No code changes expected; just record the state.

## Notes after check
- `constants.rs` and `types.rs` at the root are thin re-exports of `foundation::{constants,types}`; foundation holds the real definitions.
- No additional import changes were needed; existing callers already use the shimmed modules or foundation directly.
- No code changes; tests remain green from the previous run.
