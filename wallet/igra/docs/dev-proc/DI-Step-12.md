# Domain/Infrastructure Refactor – Step 12

## Plan (before changes)
- Move kaspa node integration helpers into the `infrastructure` namespace while preserving the old `kaspa_integration` path via a shim.
- Keep behavior unchanged and ensure PSKT building and tx submission remain available.
- No full test run required (recent suite green), but code compiles.

## Notes after implementation
- `infrastructure/kaspa_integration.rs` now hosts the submit/build helpers; re-exports `build_pskt`.
- `kaspa_integration/mod.rs` is now a shim re-exporting the infra module, maintaining existing imports.
- Behavior unchanged; ready for further infra moves.
