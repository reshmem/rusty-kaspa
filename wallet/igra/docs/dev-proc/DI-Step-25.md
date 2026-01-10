# Domain/Infrastructure Refactor – Step 25 (Boundary recap)

## Summary
- Domain layer is pure: no direct infra imports remain; policy enforcement now takes pre-fetched data, and state machine/validation live in domain.
- Infrastructure owns all I/O (storage, transport, rpc, hyperlane, coordination/event ingestion, audit, rate_limit, kaspa_integration).
- Foundation hosts shared primitives (constants, types, util); root shims simply re-export foundation modules.
- Application layer (igra-service, orchestration helpers) consumes the stable shims; no direct `infrastructure::` imports are required.

## Next options
- If desired, tighten visibility (e.g., `pub(crate)` in infra where possible) and remove obsolete legacy files once downstream consumers are updated.
- Add lint/tests to guard against domain → infra imports in the future.
