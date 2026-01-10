# Domain/Infrastructure Refactor – Step 19

## Plan (before changes)
- Make the infrastructure `config` module the canonical home for config types and loaders (previously duplicated at the root).
- Keep legacy `crate::config` imports working via re-exports.
- No behavior changes; purely structural move to infra.

## Notes after implementation
- Copied the full config module into `infrastructure/config/` and pointed `config/mod.rs` at the infra copy, so infra is the authoritative source.
- Updated internal imports to use `crate::infrastructure::config` where needed; public API remains the same for callers using `crate::config`.
- Test suite (`cargo test -p igra-core -p igra-service -- --nocapture`) remained green after the move (only pre-existing warnings).
