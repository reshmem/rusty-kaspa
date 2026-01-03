# Igra V1 - Gemini TODOs

This document lists the recommended tasks to prepare the Igra threshold signing wallet for its V1 launch, based on the analysis from `docs/legacy/dev/SECOND-SCAN.md` and `docs/security/SECURITY-FIXES-SUMMARY.md`.

## 🔴 Critical (Must-Have for Production)

- [ ] **Fix Group ID Verification Logic**: Make the service fail fast if the computed `group_id` does not match the configured `group_id`.
- [ ] **Add `group_id.rs` Test Coverage**: Implement unit tests for the group ID derivation to ensure determinism and uniqueness.
- [ ] **Enhance Configuration Validation**: Add more robust validation for `AppConfig` to check for:
    - `member_pubkeys` count matches `threshold_n`.
    - `session_timeout_seconds` is within a reasonable range.
    - `FeePaymentMode::Split` `recipient_portion` is between 0.0 and 1.0.
- [ ] **Write Deployment Guide**: Create `docs/service/DEPLOYMENT.md` with step-by-step instructions for setup, configuration, monitoring, and troubleshooting.
- [ ] **Write Security Documentation**: Create `docs/service/SECURITY.md` covering the threat model, key separation, replay protection, and best practices for operators.

## 🟡 High Priority (Important for Production Quality)

- [ ] **Add Edge Case Tests**: Implement integration tests for failure scenarios:
    - **Threshold detection:** Test with exact `m`, `m-1`, and `m+1` signatures.
    - **Timeout scenarios:** Test session timeouts with no responses and partial responses.
    - **Replay protection:** Test duplicate event and session ID submissions.
    - **Policy rejection:** Test rejections for all policy rules (destination, amount, velocity, memo).
    - **Concurrent sessions:** Test multiple simultaneous signing sessions.
    - **Coordinator failure:** Test for graceful failure and timeout if the coordinator crashes.
- [ ] **Perform Performance Testing**: Load test the system with 100+ events per hour and multiple concurrent sessions to profile memory, CPU, and storage growth.
- [ ] **Write Integration Guide**: Create `docs/service/INTEGRATION.md` for external bridge operators, with JSON-RPC examples, error handling, and retry logic.
- [ ] **Implement Health Check Endpoints**: Add `/health` and `/ready` endpoints to the service for external monitoring.

## 🟢 Medium Priority (Nice-to-Have)

- [ ] **Optimize Threshold Detection**: Optimize the `has_threshold()` function to avoid recomputing hashes on every check, possibly by caching results.
- [ ] **Write API Reference Documentation**: Create `docs/service/API_REFERENCE.md` with a complete reference for all JSON-RPC methods, Iroh messages, and the storage schema.
- [ ] **Add Metrics and Observability**: Integrate Prometheus metrics for signing sessions, latency, policy rejections, and active sessions.
- [ ] **Implement Structured Logging**: Replace `eprintln!` with the `tracing` crate for structured, machine-readable logs.

## ⚪ Low Priority (Future Enhancements)

- [ ] **Add Docker Compose Examples**: Provide a `docker-compose.yml` for a reference deployment including the Igra service and a Kaspa node.
- [ ] **Create Grafana Dashboard Templates**: Create JSON templates for visualizing the Prometheus metrics.

## 🔒 Security-Specific Tests

- [ ] **Add Security Unit Tests**:
    - Verify constant-time behavior of hash comparisons.
    - Add cross-platform determinism tests for fee calculation and UTXO sorting.
    - Simulate replay attacks in unit tests to verify rejection.
- [ ] **Test on Different Platforms**:
    - Verify on both x86_64 and ARM architectures.
    - Test with different compiler optimization levels (`--release`, `--profile dev`).
