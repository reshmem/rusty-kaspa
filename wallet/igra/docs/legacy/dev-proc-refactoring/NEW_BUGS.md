# NEW_BUGS.md

## 2026-01-10

### `igra-service` JSON-RPC router constructor not publicly reachable
- **Symptom**: Integration tests that build the JSON-RPC router could not import the router constructor after the layered refactor (the module became private / no longer re-exported from the expected path).
- **Impact**: `igra-service` integration tests failed to compile.
- **Fix**: Re-exported the router constructor from `igra-service/src/api/json_rpc.rs`:
  - `pub use super::router::build_router;`
- **Why this is acceptable**: This restores a public, testable entrypoint without changing runtime behavior; it only exposes an existing internal function.

