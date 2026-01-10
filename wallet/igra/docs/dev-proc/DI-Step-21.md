# Domain/Infrastructure Refactor – Step 21

## Plan (before changes)
- Sweep the application layer (`igra-service`, orchestration helpers) for any direct imports of infra modules and ensure they rely on the shimmed public modules (`coordination`, `event`, `rpc`, etc.).
- Avoid behavioral changes; only adjust imports if needed.

## Findings / Notes
- `igra-service` already consumes the stable module fronts (`coordination`, `rpc`, `event`, etc.) which re-export infra; no direct `infrastructure::` imports were present, so no code change was required.
- The devnet fake_hyperlane helper continues to import via `igra_core::event`, which now points at the infra event module via the shim.
- No behavioral changes; shims keep API stable.
