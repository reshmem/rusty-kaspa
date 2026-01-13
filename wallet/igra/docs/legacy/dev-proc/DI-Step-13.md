# Domain/Infrastructure Refactor – Step 13

## Plan (before changes)
- Move the RPC client abstractions into the `infrastructure` namespace while keeping the legacy `rpc` path via a shim.
- Preserve behavior and public surface; no functional changes.
- No additional test run needed beyond the last green suite.

## Notes after implementation
- Added `infrastructure/rpc/{mod.rs,grpc.rs}` containing the NodeRpc trait, UTXO types, UnimplementedRpc, and the GRPC client implementation.
- `rpc/mod.rs` now re-exports `infrastructure::rpc::*` to keep existing imports working.
- Removed the old single-file infra shim; infra module is now the canonical home for RPC code.
