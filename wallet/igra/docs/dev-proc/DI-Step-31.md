# Domain/Infrastructure Refactor – Step 31 (Application shim files)

## Plan (before changes)
- Flesh out the application shim by adding coordinator/signer/event_processor/lifecycle modules that re-export existing orchestration.
- Keep behavior unchanged; just provide stable paths for the target layout.
- Verify tests remain green.

## Notes after implementation
- Added `application/{coordinator.rs,signer.rs,event_processor.rs,lifecycle.rs}` and updated `application/mod.rs` to re-export these, plus the existing TransactionMonitor.
- No behavioral changes; tests (`cargo test -p igra-core -p igra-service -- --nocapture`) remain green (existing warning noise only).
