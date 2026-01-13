# Domain/Infrastructure Refactor – Next Steps (observability)

Proposed next move:
- Add `infrastructure/observability/{mod.rs,metrics.rs,tracing.rs,health.rs}` as shims re-exporting existing metrics/health pieces (currently under `service/metrics` etc.) or placeholders if none exist yet.
- Wire the namespace into `infrastructure/mod.rs`.
- Keep behavior unchanged; rerun tests.

If approved, I’ll create the shims and re-export existing metrics hooks, then run the test suite.
