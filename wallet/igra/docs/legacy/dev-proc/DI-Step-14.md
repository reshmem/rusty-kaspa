# Domain/Infrastructure Refactor – Step 14

## Plan (before changes)
- Move the audit logging module into the `infrastructure` namespace while keeping the legacy `audit` path intact via a shim.
- Preserve behavior and macros; no functional changes expected.
- No new test run needed (recent suite green).

## Notes after implementation
- Added `infrastructure/audit/mod.rs` with the full audit logging implementation and macros.
- `audit/mod.rs` now re-exports from the infra module, keeping existing imports working.
- Ready for further infra migrations.
