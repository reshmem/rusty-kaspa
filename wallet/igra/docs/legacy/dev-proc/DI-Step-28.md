# Domain/Infrastructure Refactor – Step 28 (RPC retry shim)

## Plan (before changes)
- Add an `infrastructure::rpc::retry` namespace to match the target layout for resilience patterns, without changing behavior yet.
- Keep API stable; this is a placeholder shim for future retry/circuit-breaker work.

## Notes after implementation
- Added `infrastructure/rpc/retry/mod.rs` (re-exporting NodeRpc for now) and wired it in `infrastructure/rpc/mod.rs`.
- No behavioral changes; creates a stable path for future retry/resilience utilities.
- Tests were green in the prior run; no code paths changed.
