# Domain/Infrastructure Refactor – Step 10

## Plan (before changes)
- Create per-module shims under `infrastructure/` so consumers can start importing infra concerns from one namespace without moving code yet.
- Keep all behavior identical; this is organizational only.
- No test reruns needed beyond prior green suite.

## Notes after implementation
- Added shims: `infrastructure/{audit,config,hyperlane,kaspa_integration,rate_limit,rpc,storage,transport}.rs` re-exporting the existing modules.
- Updated `infrastructure/mod.rs` to expose these modules instead of direct re-exports.
- Behavior unchanged; next phases can progressively move implementations under these paths.
