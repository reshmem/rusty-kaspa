# Integration Tests Added

This document summarizes the integration tests in this workspace, what they cover, and what they prove. It includes the existing integration suite plus the tests added in this thread.

## Config Parity (igra-core)

**Location:** `igra-core/tests/integration_configs.rs`

**Test:** `igra-core/tests/integration_configs.rs`  
**Name:** `integration_configs_load_and_match_group_id`

**What it tests**
- Loads all three signer INI files in `integration/`.
- Verifies `threshold_m = 2` and `threshold_n = 3`.
- Ensures `member_pubkeys` count matches `threshold_n`.
- Computes the group id and asserts it matches `iroh.group_id`.
- Ensures each signer has its expected `iroh.peer_id`.
- Ensures the `iroh.verifier_keys` set matches the expected 3 keys.

**What it proves**
- INI parsing and validation are correct.
- Group configuration is consistent across all signers.
- The derived group id is deterministic and matches the config.
- Iroh peer metadata is complete and aligned across nodes.

## 2-of-3 Flow (Mock Transport, Mock RPC)

**Location:** `igra-service/tests/two_of_three_flow.rs`

**Test:** `igra-service/tests/two_of_three_flow.rs`  
**Name:** `two_of_three_signing_flow_finalizes`

**What it tests**
- Builds a PSKT for a 2-of-3 multisig with deterministic inputs/outputs.
- Signs with 2 out of 3 keypairs.
- Inserts partial signatures into storage.
- Finalizes and “submits” the transaction using `UnimplementedRpc`.
- Confirms the request is finalized and a transaction is produced.

**What it proves**
- Threshold signature collection and partial signature handling works.
- Finalization logic assembles a valid transaction without a real node.
- Storage state transitions to `Finalized` as expected.

## Hyperlane + Iroh Flow (Real Iroh, Mock RPC)

**Location:** `igra-service/tests/hyperlane_iroh_flow.rs`

**Test:** `igra-service/tests/hyperlane_iroh_flow.rs`  
**Name:** `hyperlane_request_over_iroh_reaches_finalized_state`  
**Default:** ignored (requires local Iroh sockets)

**What it tests**
- Spawns three real Iroh endpoints and joins a local gossip group.
- Uses a mocked UTXO (100 KAS) and a 50 KAS Hyperlane request.
- Uses two validator signatures (concatenated) for Hyperlane validation.
- Runs the full coordination loop over real Iroh transport.
- Finalizes a transaction using `UnimplementedRpc` without mempool submission.

**What it proves**
- Real Iroh transport can carry the propose → ack → partial sig → finalize flow.
- Hyperlane event verification works with multiple signatures (2-of-2 in test).
- The coordinator can reach a finalized state without real Kaspa/Hyperlane nodes.

**How to run**
```
cargo test -p igra-service --test hyperlane_iroh_flow -- --ignored
```

If local sockets can’t bind, the test will skip with a clear message.

## PSKT Determinism (Cross-Signer)

**Location:** `igra-service/tests/integration/determinism/pskt_cross_signer.rs`  
**Entrypoint:** `igra-service/tests/integration_determinism.rs`  
**Name:** `test_pskt_determinism_across_signers`

**What it tests**
- Builds identical PSKTs across three independent RPC views of the same UTXO set.
- Verifies deterministic ordering with different UTXO insertion orders.
- Verifies matching PSKT blobs, tx template hashes, and validation hashes.
- Runs across three fee payment modes (RecipientPays, SignersPay, Split 0.5).

**What it proves**
- PSKT construction is deterministic across signers.
- Sorting logic in PSKT builder removes RPC ordering differences.
- Validation hashes match across nodes for the same event/inputs.

## 3-of-5 Threshold (Mock Transport)

**Location:** `igra-service/tests/integration/flows/happy_path.rs`

**Tests**
- `happy_path_threshold_3_of_5_all_signers`
- `happy_path_threshold_3_of_5_exactly_three_signers`
- `happy_path_threshold_3_of_5_insufficient_signers`

**What they test**
- Finalization with 3-of-5 when all signers respond.
- Finalization when exactly 3 signatures are provided.
- Finalization failure when only 2 signatures are present.

**What they prove**
- Threshold logic works beyond 2-of-3.
- Finalizer enforces minimum signature count.

## Daily Volume Limit Reset

**Location:** `igra-service/tests/integration/policy/volume_limits.rs`  
**Entrypoint:** `igra-service/tests/integration_policy.rs`  
**Name:** `test_daily_volume_limit_with_reset`

**What it tests**
- Enforces max daily volume at the policy layer.
- Uses a test time override to advance by one day.
- Confirms acceptance after the daily window rolls.

**What it proves**
- Daily volume limit enforcement is correct.
- Time-based reset logic is testable and functional.

## Transport Envelope Authentication

**Location:** `igra-service/tests/integration/cryptography/transport_auth.rs`  
**Entrypoint:** `igra-service/tests/integration_cryptography.rs`

**What it tests**
- Ed25519 signing and verification for transport envelopes.
- Detection of payload tampering (hash mismatch + signature failure).

**What it proves**
- Transport-level signatures are enforced and tamper detection works.

## Constant-Time Hash Comparison

**Location:** `igra-service/tests/integration/security/timing_attacks.rs`

**What it tests**
- Timing characteristics of `subtle::ConstantTimeEq` across match/early/late differences.

**What it proves**
- Hash comparisons stay within a tight timing variance envelope.

## Existing Integration Suite (igra-service/tests)

The integration suite is organized by umbrella test files that include specific modules under `igra-service/tests/integration/`.

### Top-Level Integration Entrypoints

- **Location:** `igra-service/tests/integration_flows.rs`  
  **Includes:** `integration/flows/happy_path.rs`, `integration/flows/failure_scenarios.rs`, `integration/flows/concurrent_sessions.rs`  
  **Coverage:** End-to-end flows (success and failure cases) with Iroh, RocksDB, and mocked node/validators.

- **Location:** `igra-service/tests/integration_rpc.rs`  
  **Includes:** `integration/rpc/event_submission.rs`, `integration/rpc/authentication.rs`, `integration/rpc/health_ready_metrics.rs`  
  **Coverage:** JSON-RPC request validation, auth checks, and health/metrics endpoints.

- **Location:** `igra-service/tests/integration_performance.rs`  
  **Includes:** `integration/performance/pskt_build_latency.rs`, `integration/performance/signature_throughput.rs`, `integration/performance/concurrent_capacity.rs`, `integration/performance/memory_usage.rs`  
  **Coverage:** Deterministic performance baselines for PSKT build, signing throughput, concurrency capacity, and memory growth.

- **Location:** `igra-service/tests/integration_security.rs`  
  **Includes:** `integration/security/malicious_coordinator.rs`, `integration/security/replay_attack.rs`, `integration/security/dos_resistance.rs`, `integration/security/timing_attacks.rs`  
  **Coverage:** Adversarial scenarios, replay attempts, and basic DoS resistance.

- **Location:** `igra-service/tests/integration_determinism.rs`  
  **Includes:** `integration/determinism/pskt_cross_signer.rs`  
  **Coverage:** Cross-signer PSKT determinism and hash consistency.

- **Location:** `igra-service/tests/integration_policy.rs`  
  **Includes:** `integration/policy/volume_limits.rs`  
  **Coverage:** Policy enforcement for daily volume limits with time advancement.

- **Location:** `igra-service/tests/integration_cryptography.rs`  
  **Includes:** `integration/cryptography/transport_auth.rs`  
  **Coverage:** Transport-level signature correctness and tamper detection.

### Standalone Integration Tests

- **Location:** `igra-service/tests/iroh_transport.rs`  
  **Name:** `iroh_transport_receives_published_proposal`  
  **Coverage:** Real Iroh gossip transport between two peers, proposal delivery.

- **Location:** `igra-service/tests/v1_service_integration.rs`  
  **Name:** `v1_service_signing_event_builds_pskt`  
  **Coverage:** Full signing event submission → PSKT build (requires env-provided UTXO inputs).

- **Location:** `igra-service/tests/concurrent_sessions.rs`  
  **Name:** `concurrent_sessions_timeout_independently`  
  **Coverage:** Multi-session timeout isolation with mocked transport and RPC.

- **Location:** `igra-service/tests/integration/flows/concurrent_sessions.rs`  
  **Name:** `test_interleaved_session_processing`  
  **Coverage:** Interleaved session processing with multi-session finalization.

- **Location:** `igra-service/tests/coordinator_failure.rs`  
  **Name:** `coordinator_failure_does_not_finalize`  
  **Coverage:** Coordinator failure path leaves requests pending.

- **Location:** `igra-service/tests/timeout_scenarios.rs`  
  **Name:** `collect_and_finalize_times_out_without_threshold`  
  **Coverage:** Timeout behavior when signatures are insufficient.

- **Location:** `igra-service/tests/rpc_integration.rs`  
  **Name:** `rpc_service_accepts_requests`  
  **Coverage:** RPC service wiring and basic request acceptance.
