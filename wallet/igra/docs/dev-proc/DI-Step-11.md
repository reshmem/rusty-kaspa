# Domain/Infrastructure Refactor – Step 11

## Plan (before changes)
- Move the rate limiting implementation into the new `infrastructure` namespace while keeping the legacy `crate::rate_limit` path working.
- Keep tests intact; no behavior changes expected.
- Document the move as part of the domain/infra migration.

## Notes after implementation
- Relocated rate limiter code into `infrastructure/rate_limit.rs`; the original `rate_limit.rs` now re-exports from `infrastructure::rate_limit`.
- Tests remain alongside the implementation in the infra module; behavior unchanged.
- No additional test run (prior suite green); change is structural only.
