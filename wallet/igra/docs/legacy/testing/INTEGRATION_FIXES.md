# Integration Testing Fixes and Improvements

## Overview

This document tracks what still needs to be implemented from the INTEGRATION.md recommendations. Based on a comprehensive scan of the codebase, the testing infrastructure is **functional and covers critical paths**, but several improvements would enhance test quality and maintainability.

**Current Status**: ~5,385 lines of test code across 34+ test files
- ✅ MockKaspaNode: Complete
- ✅ MockHyperlaneValidator: Complete
- ✅ Security tests: Well covered
- ✅ Storage tests: Well covered
- ⚠️ Test harness: Functional but manual
- ⚠️ PSKT determinism: Needs verification
- ⚠️ Performance tests: Stubs only

---

## Priority 1: Critical for Production Readiness

### 1.1 PSKT Determinism Cross-Signer Verification

**Status**: ❌ Missing
**Location**: Should be in `igra-service/tests/integration/determinism/pskt_cross_signer.rs`

**Issue**: While unit tests exist for PSKT building, there's no integration test that verifies all signers independently reconstruct the **exact same PSKT** from the same event and UTXO set.

**Implementation Needed**:

```rust
#[tokio::test]
async fn test_pskt_determinism_across_signers() {
    // Setup 3-node network
    let mut network = setup_test_network(3).await;

    // All nodes share same UTXO set
    let utxos = create_test_utxos(20, 5_000_000_000);
    for i in 0..3 {
        network.mock_node.add_utxos(&network.nodes[i].source_address, utxos.clone());
    }

    // Submit event to node 0 (becomes coordinator)
    let event = create_test_event(recipient, 10_000_000_000);
    let request_id = network.submit_event_to_node(0, event).await.unwrap();

    // Wait for all nodes to receive proposal
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Each node independently rebuilds PSKT
    let mut pskts = vec![];
    let mut tx_hashes = vec![];
    let mut validation_hashes = vec![];

    for i in 0..3 {
        let proposal = network.nodes[i].storage.get_proposal(&request_id).unwrap().unwrap();
        pskts.push(proposal.pskt_blob.clone());

        let request = network.nodes[i].storage.get_request(&request_id).unwrap().unwrap();
        tx_hashes.push(request.tx_template_hash);
        validation_hashes.push(request.validation_hash);
    }

    // Assert all PSKTs are byte-for-byte identical
    assert_eq!(pskts[0], pskts[1], "Node 0 and 1 PSKTs differ");
    assert_eq!(pskts[1], pskts[2], "Node 1 and 2 PSKTs differ");

    // Assert all tx_template_hashes match
    assert_eq!(tx_hashes[0], tx_hashes[1], "Node 0 and 1 tx hashes differ");
    assert_eq!(tx_hashes[1], tx_hashes[2], "Node 1 and 2 tx hashes differ");

    // Assert all validation_hashes match
    assert_eq!(validation_hashes[0], validation_hashes[1], "Node 0 and 1 validation hashes differ");
    assert_eq!(validation_hashes[1], validation_hashes[2], "Node 1 and 2 validation hashes differ");

    println!("✅ All 3 signers produced identical PSKTs");
}
```

**Why Critical**: This is the **core security property** of the system. If signers produce different PSKTs, they'll reject each other's proposals and the system will deadlock.

**Test Cases**:
- [ ] Same event, same UTXO set → identical PSKTs
- [ ] Different UTXO order from RPC → same PSKT (after sorting)
- [ ] All three fee payment modes (RecipientPays, SignersPay, Split 0.5)

---

### 1.2 Constant-Time Hash Comparison Verification

**Status**: ❌ Missing
**Location**: Should be in `igra-service/tests/integration/security/timing_attacks.rs`

**Issue**: The code uses `subtle::ConstantTimeEq` for hash comparisons, but there's no test verifying that timing is actually constant.

**Implementation Needed**:

```rust
#[test]
fn test_constant_time_hash_comparison() {
    use subtle::ConstantTimeEq;
    use std::time::Instant;

    let hash1 = [0u8; 32];
    let hash2_match = [0u8; 32];
    let hash2_differ_early = [255u8; 32]; // First byte differs
    let mut hash2_differ_late = [0u8; 32];
    hash2_differ_late[31] = 1; // Last byte differs

    // Warm up
    for _ in 0..1000 {
        let _ = hash1.ct_eq(&hash2_match).into();
        let _ = hash1.ct_eq(&hash2_differ_early).into();
        let _ = hash1.ct_eq(&hash2_differ_late).into();
    }

    // Measure matching comparison (10k iterations)
    let mut match_times = vec![];
    for _ in 0..10000 {
        let start = Instant::now();
        let _ = hash1.ct_eq(&hash2_match).into();
        match_times.push(start.elapsed().as_nanos());
    }

    // Measure differing comparison (early byte)
    let mut differ_early_times = vec![];
    for _ in 0..10000 {
        let start = Instant::now();
        let _ = hash1.ct_eq(&hash2_differ_early).into();
        differ_early_times.push(start.elapsed().as_nanos());
    }

    // Measure differing comparison (late byte)
    let mut differ_late_times = vec![];
    for _ in 0..10000 {
        let start = Instant::now();
        let _ = hash1.ct_eq(&hash2_differ_late).into();
        differ_late_times.push(start.elapsed().as_nanos());
    }

    // Statistical analysis
    let match_mean = mean(&match_times);
    let differ_early_mean = mean(&differ_early_times);
    let differ_late_mean = mean(&differ_late_times);

    let match_stddev = stddev(&match_times, match_mean);
    let differ_early_stddev = stddev(&differ_early_times, differ_early_mean);
    let differ_late_stddev = stddev(&differ_late_times, differ_late_mean);

    println!("Match:        mean={:.2}ns, stddev={:.2}ns", match_mean, match_stddev);
    println!("Differ early: mean={:.2}ns, stddev={:.2}ns", differ_early_mean, differ_early_stddev);
    println!("Differ late:  mean={:.2}ns, stddev={:.2}ns", differ_late_mean, differ_late_stddev);

    // Assert no significant timing difference
    // Allow up to 10% deviation (generous for noise)
    let early_diff_pct = ((match_mean - differ_early_mean).abs() / match_mean) * 100.0;
    let late_diff_pct = ((match_mean - differ_late_mean).abs() / match_mean) * 100.0;

    assert!(early_diff_pct < 10.0, "Early byte timing difference: {:.2}%", early_diff_pct);
    assert!(late_diff_pct < 10.0, "Late byte timing difference: {:.2}%", late_diff_pct);

    // Also assert early vs late have no significant difference
    let early_vs_late_pct = ((differ_early_mean - differ_late_mean).abs() / differ_early_mean) * 100.0;
    assert!(early_vs_late_pct < 10.0, "Early vs late timing difference: {:.2}%", early_vs_late_pct);

    println!("✅ Constant-time comparison verified");
}

fn mean(values: &[u128]) -> f64 {
    values.iter().map(|&v| v as f64).sum::<f64>() / values.len() as f64
}

fn stddev(values: &[u128], mean: f64) -> f64 {
    let variance = values.iter()
        .map(|&v| {
            let diff = v as f64 - mean;
            diff * diff
        })
        .sum::<f64>() / values.len() as f64;
    variance.sqrt()
}
```

**Why Critical**: Timing attacks can leak information about which byte differs in hash comparisons, potentially enabling replay attacks or signature forgery.

**Test Cases**:
- [ ] event_hash comparison (coordinator.rs)
- [ ] validation_hash comparison (signer.rs)
- [ ] tx_template_hash comparison (signer.rs)
- [ ] payload_hash comparison (iroh.rs transport)

---

### 1.3 3-of-5 Threshold Signing Test

**Status**: ❌ Missing
**Location**: Should be in `igra-service/tests/integration/flows/happy_path.rs`

**Issue**: Only 2-of-3 threshold tests exist. Need to verify 3-of-5 works correctly.

**Implementation Needed**:

```rust
#[tokio::test]
async fn test_3of5_threshold_all_signers_respond() {
    // Setup 5-node network with 3-of-5 threshold
    let mut network = setup_test_network_with_threshold(3, 5).await;

    // Submit event
    let event = create_test_event(recipient, 10_000_000_000);
    let request_id = network.submit_event_to_node(0, event).await.unwrap();

    // All 5 signers respond
    for i in 0..5 {
        network.nodes[i].process_proposal(&request_id).await.unwrap();
    }

    // Coordinator should collect exactly 3 signatures (threshold met)
    tokio::time::sleep(Duration::from_secs(5)).await;

    let sigs = network.nodes[0].storage
        .get_partial_sigs(&request_id)
        .unwrap();

    // Should have at least 3 signatures
    assert!(sigs.len() >= 3, "Expected at least 3 signatures, got {}", sigs.len());

    // Transaction should finalize
    let request = network.nodes[0].storage
        .get_request(&request_id)
        .unwrap()
        .unwrap();
    assert!(request.final_tx_id.is_some(), "Transaction not finalized");

    println!("✅ 3-of-5 threshold met with all signers");
}

#[tokio::test]
async fn test_3of5_threshold_exactly_three_signers() {
    // Setup 5-node network with 3-of-5 threshold
    let mut network = setup_test_network_with_threshold(3, 5).await;

    // Submit event
    let event = create_test_event(recipient, 10_000_000_000);
    let request_id = network.submit_event_to_node(0, event).await.unwrap();

    // Only 3 signers respond (exactly threshold)
    for i in 1..4 {
        network.nodes[i].process_proposal(&request_id).await.unwrap();
    }

    // Wait for finalization
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Transaction should finalize with exactly 3 signatures
    let request = network.nodes[0].storage
        .get_request(&request_id)
        .unwrap()
        .unwrap();
    assert!(request.final_tx_id.is_some(), "Transaction not finalized");

    println!("✅ 3-of-5 threshold met with exactly 3 signers");
}

#[tokio::test]
async fn test_3of5_threshold_insufficient_signers() {
    // Setup 5-node network with 3-of-5 threshold
    let mut network = setup_test_network_with_threshold(3, 5).await;
    network.set_session_timeout(Duration::from_secs(5)); // Short timeout for test

    // Submit event
    let event = create_test_event(recipient, 10_000_000_000);
    let request_id = network.submit_event_to_node(0, event).await.unwrap();

    // Only 2 signers respond (below threshold)
    for i in 1..3 {
        network.nodes[i].process_proposal(&request_id).await.unwrap();
    }

    // Wait for timeout
    tokio::time::sleep(Duration::from_secs(8)).await;

    // Transaction should NOT finalize
    let request = network.nodes[0].storage
        .get_request(&request_id)
        .unwrap()
        .unwrap();
    assert!(request.final_tx_id.is_none(), "Transaction should not finalize with 2-of-5");

    // Check timeout metric
    let timeouts = network.nodes[0].get_metric("session_timeouts_total");
    assert_eq!(timeouts, Some(1.0));

    println!("✅ 3-of-5 threshold NOT met with only 2 signers");
}
```

**Why Critical**: The system claims to support m-of-n thresholds, but only 2-of-3 is tested. Need to verify threshold logic works for other values.

---

### 1.4 Daily Volume Limit with Time Advancement

**Status**: ❌ Missing
**Location**: Should be in `igra-service/tests/integration/policy/volume_limits.rs`

**Issue**: Volume tracking is implemented and tested, but there's no test that verifies the **daily reset** behavior with time advancement.

**Implementation Needed**:

```rust
#[tokio::test]
async fn test_daily_volume_limit_with_reset() {
    let mut network = setup_test_network(3).await;

    // Configure policy: max 100 KAS per day
    network.set_policy(GroupPolicy {
        max_daily_volume_sompi: Some(100_000_000_000), // 100 KAS
        ..Default::default()
    });

    // Submit and finalize 5 x 20 KAS = 100 KAS (exactly at limit)
    for i in 0..5 {
        let event = create_test_event(recipient, 20_000_000_000);
        let request_id = network.submit_event_to_node(0, event).await.unwrap();
        network.wait_for_finalization(&request_id, Duration::from_secs(30)).await.unwrap();
    }

    // 6th event (would exceed limit) rejected
    let event_exceed = create_test_event(recipient, 1_000_000_000);
    let result = network.submit_event_to_node(0, event_exceed).await;
    assert!(result.is_err(), "Expected rejection due to volume limit");
    assert!(result.unwrap_err().to_string().contains("daily volume limit"));

    // Advance time by 24 hours + 1 second
    // Note: This requires MockClock or system time manipulation
    // For now, this is a placeholder for the test structure

    // TODO: Implement time advancement mechanism
    // Options:
    // 1. MockClock trait injected into policy enforcement
    // 2. Directly manipulate system time in test (requires privileges)
    // 3. Add "advance_time" test helper that modifies internal timestamps

    println!("⚠️  Time advancement not implemented - test incomplete");

    // After time advancement, 7th event should be accepted
    // let event_new_day = create_test_event(recipient, 20_000_000_000);
    // let result_ok = network.submit_event_to_node(0, event_new_day).await;
    // assert!(result_ok.is_ok(), "Expected acceptance after daily reset");
}
```

**Why Critical**: Volume limits are a **key security policy**. Need to verify they reset properly and don't accumulate indefinitely.

**Blocker**: Requires time abstraction in policy enforcement code. Consider:
- Injecting `Clock` trait into `PolicyEnforcer`
- Using `tokio::time::pause()` and `advance()` in tests
- Adding test-only "override timestamp" method

---

## Priority 2: Infrastructure Improvements

### 2.1 Enhanced TestNetwork Harness

**Status**: ⚠️ Basic networking exists, lacks orchestration
**Location**: `igra-service/tests/integration_harness/test_network.rs`

**Issue**: Tests manually set up nodes and wait for messages. Need high-level helpers.

**Implementation Needed**:

Add these methods to `TestNetwork`:

```rust
impl TestNetwork {
    // Wait helpers
    pub async fn wait_for_proposal(&self, request_id: &str, timeout: Duration) -> Result<()> {
        let start = Instant::now();
        loop {
            let mut all_have_proposal = true;
            for node in &self.nodes {
                if node.storage.get_proposal(request_id).unwrap().is_none() {
                    all_have_proposal = false;
                    break;
                }
            }

            if all_have_proposal {
                return Ok(());
            }

            if start.elapsed() > timeout {
                return Err(anyhow!("Timeout waiting for proposal"));
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn wait_for_threshold(&self, request_id: &str, timeout: Duration) -> Result<()> {
        let start = Instant::now();
        loop {
            let sigs = self.nodes[0].storage.get_partial_sigs(request_id).unwrap();
            if sigs.len() >= self.threshold_m {
                return Ok(());
            }

            if start.elapsed() > timeout {
                return Err(anyhow!("Timeout waiting for threshold (have {} of {})",
                    sigs.len(), self.threshold_m));
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn wait_for_finalization(&self, request_id: &str, timeout: Duration) -> Result<()> {
        let start = Instant::now();
        loop {
            if let Some(req) = self.nodes[0].storage.get_request(request_id).unwrap() {
                if req.final_tx_id.is_some() {
                    return Ok(());
                }
            }

            if start.elapsed() > timeout {
                return Err(anyhow!("Timeout waiting for finalization"));
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // Assertions
    pub async fn assert_all_nodes_have_proposal(&self, request_id: &str) {
        for (i, node) in self.nodes.iter().enumerate() {
            let proposal = node.storage.get_proposal(request_id).unwrap();
            assert!(proposal.is_some(), "Node {} missing proposal", i);
        }
    }

    pub async fn assert_signatures_collected(&self, request_id: &str, expected: usize) {
        let sigs = self.nodes[0].storage.get_partial_sigs(request_id).unwrap();
        assert_eq!(sigs.len(), expected, "Expected {} signatures, got {}", expected, sigs.len());
    }

    pub async fn assert_transaction_finalized(&self, request_id: &str) {
        let req = self.nodes[0].storage.get_request(request_id).unwrap().unwrap();
        assert!(req.final_tx_id.is_some(), "Transaction not finalized");
    }

    // Network failure injection
    pub async fn disconnect_node(&mut self, index: usize) {
        // Shutdown node's gossip/endpoint
        self.nodes[index].gossip.quit().await.ok();
        self.nodes[index].is_connected = false;
    }

    pub async fn reconnect_node(&mut self, index: usize) -> Result<()> {
        // Recreate gossip and rejoin topic
        // This is complex - may need to restart the node's service
        self.nodes[index].is_connected = true;
        Ok(())
    }
}
```

**Impact**: Reduces test boilerplate by 50-70%, makes tests more readable.

---

### 2.2 Proper TestKeyGenerator

**Status**: ❌ Only constants exist
**Location**: `igra-service/tests/integration_harness/test_keys.rs`

**Issue**: Tests use inline key generation. Need deterministic factory.

**Implementation Needed**:

```rust
pub struct TestKeyGenerator {
    seed: [u8; 32],
}

impl TestKeyGenerator {
    pub fn new(seed: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(seed.as_bytes());
        let hash = hasher.finalize();
        Self {
            seed: *hash.as_bytes(),
        }
    }

    pub fn generate_kaspa_keypair(&self, index: u32) -> (secp256k1::SecretKey, secp256k1::PublicKey) {
        let mut seed = self.seed.to_vec();
        seed.extend_from_slice(&index.to_le_bytes());
        let mut hasher = blake3::Hasher::new();
        hasher.update(&seed);
        let key_bytes = hasher.finalize();

        let secret = secp256k1::SecretKey::from_slice(key_bytes.as_bytes()).unwrap();
        let public = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret);
        (secret, public)
    }

    pub fn generate_kaspa_address(&self, index: u32, network: NetworkType) -> Address {
        let (_, pubkey) = self.generate_kaspa_keypair(index);
        let payload = &pubkey.serialize()[1..]; // Remove 0x04 prefix
        Address::new(network.into(), kaspa_addresses::Version::PubKey, payload)
    }

    pub fn generate_validator_keypair(&self, index: u32) -> (secp256k1::SecretKey, String) {
        let (secret, pubkey) = self.generate_kaspa_keypair(1000 + index); // Offset to avoid collision

        // Derive Ethereum address from pubkey
        let pubkey_bytes = &pubkey.serialize_uncompressed()[1..]; // Remove 0x04 prefix
        let mut hasher = sha3::Keccak256::new();
        hasher.update(pubkey_bytes);
        let hash = hasher.finalize();
        let eth_address = format!("0x{}", hex::encode(&hash[12..]));

        (secret, eth_address)
    }

    pub fn generate_iroh_keypair(&self, index: u32) -> (iroh::SecretKey, iroh::PublicKey) {
        let mut seed = self.seed.to_vec();
        seed.extend_from_slice(b"iroh");
        seed.extend_from_slice(&index.to_le_bytes());

        let mut hasher = blake3::Hasher::new();
        hasher.update(&seed);
        let key_bytes = hasher.finalize();

        let secret = iroh::SecretKey::from_bytes(key_bytes.as_bytes()).unwrap();
        let public = secret.public();
        (secret, public)
    }

    pub fn generate_redeem_script(&self, m: usize, n: usize) -> Vec<u8> {
        let mut pubkeys = vec![];
        for i in 0..n {
            let (_, pubkey) = self.generate_kaspa_keypair(i as u32);
            pubkeys.push(pubkey);
        }

        // Build redeem script: OP_M <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG
        build_multisig_script(m, &pubkeys)
    }
}
```

**Impact**: Enables reproducible test keys across test runs, easier debugging.

---

### 2.3 Expanded TestDataFactory

**Status**: ⚠️ Minimal helpers
**Location**: `igra-service/tests/integration_harness/test_data.rs`

**Issue**: Tests manually build events and UTXOs inline.

**Implementation Needed**:

```rust
pub struct TestDataFactory;

impl TestDataFactory {
    pub fn create_hyperlane_event(
        recipient: Address,
        amount: u64,
        nonce: u64,
    ) -> SigningEvent {
        SigningEvent {
            source: EventSource::Hyperlane,
            recipient_address: recipient.to_string(),
            amount_sompi: amount,
            nonce: Some(nonce.to_string()),
            memo: None,
            hyperlane_signatures: None, // Caller adds signatures
            ..Default::default()
        }
    }

    pub fn create_utxo_set(
        address: Address,
        count: usize,
        amount_per_utxo: u64,
    ) -> Vec<UtxoEntry> {
        (0..count).map(|i| UtxoEntry {
            amount: amount_per_utxo,
            script_public_key: ScriptPublicKey::from_address(&address),
            block_daa_score: 1000 + i as u64,
            is_coinbase: false,
            outpoint: TransactionOutpoint {
                transaction_id: TransactionId::from_slice(&blake3::hash(
                    format!("utxo-{}", i).as_bytes()
                ).as_bytes()[..32]).unwrap(),
                index: 0,
            },
        }).collect()
    }

    pub fn create_config_2of3(data_dir: &Path) -> AppConfig {
        let keygen = TestKeyGenerator::new("test-2of3");

        AppConfig {
            service: ServiceConfig {
                data_dir: data_dir.to_path_buf(),
                ..Default::default()
            },
            group: GroupConfig {
                threshold_m: 2,
                threshold_n: 3,
                member_pubkeys: (0..3)
                    .map(|i| hex::encode(keygen.generate_kaspa_keypair(i).1.serialize()))
                    .collect(),
                ..Default::default()
            },
            pskt: PsktConfig {
                redeem_script_hex: hex::encode(keygen.generate_redeem_script(2, 3)),
                sig_op_count: 2,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    pub fn create_policy_restrictive() -> GroupPolicy {
        GroupPolicy {
            allowed_destinations: vec![/* specific addresses */],
            min_amount_sompi: Some(1_000_000), // 0.001 KAS
            max_amount_sompi: Some(1_000_000_000), // 1 KAS
            max_daily_volume_sompi: Some(10_000_000_000), // 10 KAS
            require_reason: true,
        }
    }
}
```

**Impact**: Reduces test setup code, makes tests more declarative.

---

### 2.4 Transport Envelope Signing Test

**Status**: ❌ Missing
**Location**: Should be in `igra-service/tests/integration/cryptography/transport_auth.rs`

**Issue**: Iroh transport uses Ed25519 signatures, but this isn't explicitly tested.

**Implementation Needed**:

```rust
#[tokio::test]
async fn test_transport_envelope_authentication() {
    let mut network = setup_test_network(3).await;

    // Node 0 sends proposal
    let event = create_test_event(recipient, 5_000_000_000);
    let request_id = network.submit_event_to_node(0, event).await.unwrap();

    // Wait for proposal broadcast
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Capture the raw message that node 1 received
    let received_msg = network.nodes[1].get_last_received_message().unwrap();

    // Verify envelope signature from node 0
    assert!(received_msg.verify_signature(network.nodes[0].peer_id));

    // Tamper with payload
    let mut tampered = received_msg.clone();
    tampered.payload.session_id = "tampered".to_string();

    // Signature should fail verification
    assert!(!tampered.verify_signature(network.nodes[0].peer_id));

    println!("✅ Transport envelope authentication verified");
}

#[test]
fn test_envelope_signature_format() {
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let message = b"test message";
    let signature = signing_key.sign(message);

    // Verify format matches Iroh expectations
    assert_eq!(signature.to_bytes().len(), 64);

    // Verify signature
    use ed25519_dalek::Verifier;
    assert!(verifying_key.verify(message, &signature).is_ok());

    println!("✅ Ed25519 signature format verified");
}
```

**Impact**: Ensures transport-level authentication works correctly.

---

## Priority 3: Nice to Have

### 3.1 Convert Performance Tests to Real Benchmarks

**Status**: ⚠️ Stubs exist
**Location**: `igra-service/tests/integration/performance/*.rs`

**Issue**: Performance tests are smoke tests, not proper benchmarks.

**Implementation Needed**:

Use `criterion` crate for proper benchmarking:

```rust
// benches/integration_perf.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_pskt_build_latency(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mock_node = Arc::new(Mutex::new(MockKaspaNode::new()));

    // Setup with 100 UTXOs
    let utxos = TestDataFactory::create_utxo_set(test_address(), 100, 1_000_000_000);
    mock_node.lock().unwrap().add_utxos(test_address(), utxos);

    let event = TestDataFactory::create_hyperlane_event(
        recipient_address(),
        50_000_000_000,
        1,
    );

    c.bench_function("pskt_build_100_utxos", |b| {
        b.to_async(&runtime).iter(|| async {
            let pskt = build_pskt(&mock_node, &event, &test_config()).await.unwrap();
            black_box(pskt);
        });
    });
}

criterion_group!(benches, bench_pskt_build_latency);
criterion_main!(benches);
```

Add to `Cargo.toml`:
```toml
[[bench]]
name = "integration_perf"
harness = false
```

**Test Cases**:
- [ ] PSKT build with 10, 50, 100, 200 UTXOs
- [ ] Signature collection latency (2-of-3, 3-of-5)
- [ ] End-to-end flow latency (event → finalization)
- [ ] Storage operations throughput

---

### 3.2 Memory Usage Profiling Test

**Status**: ❌ Missing
**Location**: Should be in `igra-service/tests/integration/performance/memory_usage.rs`

**Implementation Needed**:

```rust
#[tokio::test]
async fn test_memory_usage_growth() {
    use sysinfo::{System, SystemExt, ProcessExt};

    let mut sys = System::new_all();
    sys.refresh_all();

    let pid = sysinfo::get_current_pid().unwrap();
    let process = sys.process(pid).unwrap();
    let initial_rss = process.memory() / 1024; // KB

    println!("Initial RSS: {} MB", initial_rss / 1024);

    let mut network = setup_test_network(3).await;

    // Process 1000 events
    for i in 0..1000 {
        let event = create_test_event(recipient, 1_000_000_000);
        let request_id = network.submit_event_to_node(0, event).await.unwrap();
        network.wait_for_finalization(&request_id, Duration::from_secs(30)).await.unwrap();

        if i % 100 == 0 {
            sys.refresh_all();
            let process = sys.process(pid).unwrap();
            let current_rss = process.memory() / 1024; // KB
            let growth = current_rss - initial_rss;
            println!("After {} events: {} MB (+{} MB)", i, current_rss / 1024, growth / 1024);
        }
    }

    sys.refresh_all();
    let process = sys.process(pid).unwrap();
    let final_rss = process.memory() / 1024; // KB
    let total_growth = final_rss - initial_rss;

    println!("Final RSS: {} MB", final_rss / 1024);
    println!("Total growth: {} MB", total_growth / 1024);

    // Assert growth < 100 MB for 1000 events
    assert!(total_growth / 1024 < 100, "Memory growth too high: {} MB", total_growth / 1024);
}
```

**Dependency**: Add `sysinfo = "0.30"` to `dev-dependencies`

---

### 3.3 Metrics Endpoint Verification

**Status**: ❌ Missing
**Location**: Should be in `igra-service/tests/integration/rpc/health_ready_metrics.rs`

**Issue**: Health check tests exist, but Prometheus `/metrics` endpoint not tested.

**Implementation Needed**:

```rust
#[tokio::test]
async fn test_metrics_endpoint() {
    let mut network = setup_test_network(3).await;
    network.nodes[0].start_http_server().await.unwrap();

    // Execute signing flow to generate metrics
    let event = create_test_event(recipient, 5_000_000_000);
    let request_id = network.submit_event_to_node(0, event).await.unwrap();
    network.wait_for_finalization(&request_id, Duration::from_secs(30)).await.unwrap();

    // Query metrics endpoint
    let client = reqwest::Client::new();
    let response = client.get("http://127.0.0.1:8088/metrics")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let metrics = response.text().await.unwrap();
    println!("Metrics:\n{}", metrics);

    // Verify expected metrics present
    assert!(metrics.contains("signing_sessions_total"), "Missing signing_sessions_total");
    assert!(metrics.contains("signer_acks_total"), "Missing signer_acks_total");
    assert!(metrics.contains("partial_sigs_total"), "Missing partial_sigs_total");

    // Verify values
    assert!(metrics.contains("signing_sessions_total{status=\"finalized\"} 1"),
        "Expected 1 finalized session");

    // Verify histogram buckets for session_duration_seconds
    assert!(metrics.contains("session_duration_seconds_bucket"),
        "Missing duration histogram");
}
```

---

### 3.4 Interleaved Session Processing Test

**Status**: ❌ Missing
**Location**: Should be in `igra-service/tests/integration/flows/concurrent_sessions.rs`

**Implementation Needed**:

```rust
#[tokio::test]
async fn test_interleaved_session_processing() {
    let mut network = setup_test_network(3).await;

    // Start session A
    let event_a = create_test_event(recipient_a, 5_000_000_000);
    let request_id_a = network.submit_event_to_node(0, event_a).await.unwrap();

    // Wait for proposal A
    network.wait_for_proposal(&request_id_a, Duration::from_secs(5)).await.unwrap();

    // Start session B before A completes
    let event_b = create_test_event(recipient_b, 10_000_000_000);
    let request_id_b = network.submit_event_to_node(0, event_b).await.unwrap();

    // Wait for proposal B
    network.wait_for_proposal(&request_id_b, Duration::from_secs(5)).await.unwrap();

    // Process both sessions on all signers
    for i in 0..3 {
        network.nodes[i].process_proposal(&request_id_a).await.unwrap();
        network.nodes[i].process_proposal(&request_id_b).await.unwrap();
    }

    // Both should finalize independently
    network.wait_for_finalization(&request_id_a, Duration::from_secs(30)).await.unwrap();
    network.wait_for_finalization(&request_id_b, Duration::from_secs(30)).await.unwrap();

    // Verify correct amounts
    let tx_a = network.mock_node.get_submitted_transaction_for_request(&request_id_a).unwrap();
    let tx_b = network.mock_node.get_submitted_transaction_for_request(&request_id_b).unwrap();

    assert_eq!(tx_a.outputs[0].value, 5_000_000_000);
    assert_eq!(tx_b.outputs[0].value, 10_000_000_000);

    println!("✅ Interleaved sessions processed correctly");
}
```

---

## Summary Table

| Item | Priority | Status | Estimated Effort | Blocker? |
|------|----------|--------|------------------|----------|
| **1.1** PSKT Determinism Cross-Signer | P1 | ❌ | 4 hours | No |
| **1.2** Constant-Time Hash Comparison | P1 | ❌ | 3 hours | No |
| **1.3** 3-of-5 Threshold Test | P1 | ❌ | 2 hours | No |
| **1.4** Daily Volume Limit | P1 | ❌ | 6 hours | Yes (needs time abstraction) |
| **2.1** Enhanced TestNetwork | P2 | ⚠️ | 8 hours | No |
| **2.2** TestKeyGenerator | P2 | ❌ | 4 hours | No |
| **2.3** TestDataFactory | P2 | ⚠️ | 3 hours | No |
| **2.4** Transport Auth Test | P2 | ❌ | 2 hours | No |
| **3.1** Criterion Benchmarks | P3 | ⚠️ | 6 hours | No |
| **3.2** Memory Profiling | P3 | ❌ | 3 hours | No |
| **3.3** Metrics Endpoint | P3 | ❌ | 2 hours | No |
| **3.4** Interleaved Sessions | P3 | ❌ | 2 hours | No |

**Total Estimated Effort**: ~45 hours (about 1 week of focused work)

---

## Recommendations

### Immediate Actions (This Week)
1. **Implement 1.1 (PSKT Determinism)** - This is the most critical test for production
2. **Implement 1.3 (3-of-5 Threshold)** - Validates core threshold logic
3. **Implement 1.2 (Constant-Time)** - Critical security property

### Next Week
4. **Design time abstraction for 1.4** - Enables volume limit testing
5. **Enhance TestNetwork (2.1)** - Will speed up all future test development
6. **Implement 2.4 (Transport Auth)** - Quick win for crypto coverage

### Future Iterations
7. **Convert to Criterion benchmarks (3.1)** - Performance baseline
8. **Memory profiling (3.2)** - Production readiness
9. **Expand TestKeyGenerator and TestDataFactory (2.2, 2.3)** - Quality of life

---

## Notes

1. **Time Abstraction Blocker**: Item 1.4 requires injecting a `Clock` trait into policy enforcement. This is a small refactor but needs careful design to avoid breaking existing code.

2. **TestNetwork Complexity**: Item 2.1 is valuable but time-consuming. Consider implementing helpers incrementally as tests need them.

3. **Performance Tests**: Current stubs are sufficient for smoke testing. Converting to Criterion is nice-to-have but not critical for production.

4. **Overall Assessment**: The test suite is **functional and covers critical security scenarios**. The gaps are mostly in **determinism verification**, **threshold variations**, and **infrastructure convenience**. None are blocking production deployment, but addressing Priority 1 items would increase confidence significantly.

---

**Document Version**: 1.0
**Last Updated**: 2025-12-31
**Status**: Ready for Review
**Next Review**: After Priority 1 items completed
