# Integration Testing Strategy for Igra

## Overview

This document describes the comprehensive integration testing strategy for the Igra threshold signing framework. The goal is to test all critical components and flows using **real infrastructure** (Iroh transport, RocksDB, cryptographic operations) while **mocking external dependencies** (Kaspa Node, Hyperlane validators) to enable deterministic, fast, and reliable automated testing.

## Testing Philosophy

### What We Test with Real Components

1. **Iroh Transport Layer**: Real P2P gossip messaging between test nodes
2. **RocksDB Storage**: Real database operations with temporary directories
3. **Cryptographic Operations**: Real secp256k1 Schnorr/ECDSA and Ed25519 signatures
4. **Configuration Management**: Real INI parsing and validation
5. **Coordination Protocol**: Full message passing (Propose → Ack → PartialSig → Finalize)
6. **Policy Enforcement**: Real policy validation logic
7. **PSKT Construction**: Real deterministic transaction building

### What We Mock

1. **Kaspa Node RPC**: Mock UTXO queries and transaction submission
2. **Hyperlane Validators**: Mock event signing with test keys
3. **External Event Sources**: Mock JSON-RPC client, file watcher
4. **Network Latency**: Controllable delays for timeout testing
5. **Clock**: Controllable time for volume tracking and session timeouts

## Test Architecture

### Test Harness Components

```
tests/
├── integration/
│   ├── harness/
│   │   ├── mod.rs                    # Main test harness
│   │   ├── mock_node.rs              # MockKaspaNode implementation
│   │   ├── mock_hyperlane.rs         # MockHyperlaneValidator implementation
│   │   ├── test_network.rs           # Multi-node Iroh test network
│   │   ├── test_keys.rs              # Deterministic key generation
│   │   ├── test_data.rs              # Sample events, UTXOs, configs
│   │   └── assertions.rs             # Custom test assertions
│   │
│   ├── flows/
│   │   ├── happy_path.rs             # Full signing flow (2-of-3, 3-of-5)
│   │   ├── coordinator_failure.rs    # Coordinator crashes mid-session
│   │   ├── timeout_handling.rs       # Insufficient signatures timeout
│   │   ├── concurrent_sessions.rs    # Multiple sessions in parallel
│   │   ├── replay_protection.rs      # Duplicate event rejection
│   │   └── policy_enforcement.rs     # Policy violations and edge cases
│   │
│   ├── determinism/
│   │   ├── pskt_stability.rs         # Same inputs → same PSKT
│   │   ├── utxo_ordering.rs          # Deterministic UTXO sorting
│   │   └── fee_calculation.rs        # Integer fee math consistency
│   │
│   ├── cryptography/
│   │   ├── threshold_signing.rs      # m-of-n signature collection
│   │   ├── event_validation.rs       # Hyperlane/LayerZero signatures
│   │   ├── transport_auth.rs         # Ed25519 envelope signing
│   │   ├── constant_time.rs          # Timing attack resistance
│   │   └── key_separation.rs         # Type-level key isolation
│   │
│   ├── coordination/
│   │   ├── proposal_broadcast.rs     # Proposer publishes to group
│   │   ├── signer_validation.rs      # Independent PSKT rebuild
│   │   ├── signature_collection.rs   # Threshold detection
│   │   ├── finalization.rs           # Transaction assembly
│   │   └── audit_trail.rs            # Storage verification
│   │
│   ├── storage/
│   │   ├── replay_prevention.rs      # Duplicate event detection
│   │   ├── volume_tracking.rs        # Daily limits enforcement
│   │   ├── audit_export.rs           # Session history portability
│   │   ├── concurrent_writes.rs      # Isolation between sessions
│   │   └── persistence.rs            # Restart recovery
│   │
│   ├── policy/
│   │   ├── destination_allowlist.rs  # Address filtering
│   │   ├── amount_limits.rs          # Min/max/velocity checks
│   │   ├── fee_validation.rs         # Fee mode enforcement
│   │   └── memo_requirements.rs      # Optional memo field
│   │
│   ├── rpc/
│   │   ├── event_submission.rs       # JSON-RPC 2.0 endpoint
│   │   ├── authentication.rs         # Token-based auth
│   │   ├── health_checks.rs          # /health and /ready endpoints
│   │   └── metrics_export.rs         # Prometheus /metrics
│   │
│   ├── performance/
│   │   ├── pskt_build_latency.rs     # Build time with 100+ UTXOs
│   │   ├── signature_throughput.rs   # Signatures per second
│   │   ├── concurrent_capacity.rs    # Max parallel sessions
│   │   └── memory_usage.rs           # Peak RSS measurement
│   │
│   └── security/
│       ├── timing_attacks.rs         # Statistical timing analysis
│       ├── replay_attacks.rs         # Capture and replay
│       ├── malicious_coordinator.rs  # Tampered proposals
│       └── dos_resistance.rs         # Flood testing
│
└── fixtures/
    ├── events/
    │   ├── hyperlane_valid.json
    │   ├── hyperlane_invalid_sig.json
    │   ├── layerzero_valid.json
    │   └── api_event.json
    ├── configs/
    │   ├── 2of3_testnet.ini
    │   ├── 3of5_mainnet.ini
    │   └── policy_strict.ini
    └── keys/
        ├── test_signing_keys.json    # Kaspa secp256k1 keys
        ├── test_validator_keys.json  # Hyperlane ECDSA keys
        └── test_iroh_keys.json       # Iroh Ed25519 keys
```

## Mock Implementation Specifications

### MockKaspaNode

Simulates Kaspa node gRPC interface without requiring a real node.

```rust
pub struct MockKaspaNode {
    utxo_set: HashMap<Address, Vec<UtxoEntry>>,
    submitted_txs: Vec<Transaction>,
    current_blue_score: u64,
}

impl MockKaspaNode {
    // Setup methods
    pub fn new() -> Self;
    pub fn add_utxos(&mut self, address: Address, utxos: Vec<UtxoEntry>);
    pub fn set_blue_score(&mut self, score: u64);

    // RPC methods (matches real kaspa_rpc_core::RpcApi)
    pub async fn get_utxos_by_addresses(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<UtxoEntry>>;

    pub async fn submit_transaction(
        &mut self,
        tx: Transaction,
    ) -> Result<TransactionId>;

    pub async fn get_block_dag_info(&self) -> Result<BlockDagInfo>;

    // Test utilities
    pub fn assert_transaction_submitted(&self, tx_id: &TransactionId);
    pub fn get_submitted_transaction(&self, tx_id: &TransactionId) -> Option<&Transaction>;
    pub fn simulate_transaction_acceptance(&mut self, tx_id: &TransactionId, blue_score: u64);
}
```

**Key Features:**
- Deterministic UTXO sets for reproducible tests
- Transaction validation (input amounts, signatures, etc.)
- Blue score progression simulation
- Thread-safe with `Arc<Mutex<Inner>>` for multi-node tests

### MockHyperlaneValidator

Simulates Hyperlane validator signing for event authentication.

```rust
pub struct MockHyperlaneValidator {
    validators: Vec<HyperlaneValidator>,
    threshold: usize,
}

pub struct HyperlaneValidator {
    address: String,              // 0x... Ethereum address
    private_key: SecretKey,       // secp256k1 ECDSA key
}

impl MockHyperlaneValidator {
    // Setup
    pub fn new(num_validators: usize, threshold: usize) -> Self;
    pub fn get_validator_addresses(&self) -> Vec<String>;

    // Event signing
    pub fn sign_event(
        &self,
        event: &SigningEvent,
        signers: &[usize],  // Which validators to sign with
    ) -> Result<Vec<String>>;  // Returns signature hex strings

    // Validation (for reference implementation verification)
    pub fn verify_event_signature(
        &self,
        event: &SigningEvent,
        signature: &str,
        validator_index: usize,
    ) -> Result<bool>;

    // Test utilities
    pub fn sign_with_quorum(&self, event: &SigningEvent) -> Vec<String>;
    pub fn sign_with_insufficient(&self, event: &SigningEvent) -> Vec<String>;
    pub fn sign_with_invalid_key(&self, event: &SigningEvent) -> Vec<String>;
}
```

**Key Features:**
- Generates deterministic validator keys from seed
- Matches real Hyperlane signature format (secp256k1 ECDSA)
- Configurable quorum (e.g., 2-of-3 validators)
- Invalid signature generation for negative testing

### TestNetwork

Creates a multi-node Iroh network with real P2P transport.

```rust
pub struct TestNetwork {
    nodes: Vec<TestNode>,
    topic: TopicId,  // Derived from group_id
}

pub struct TestNode {
    id: String,                        // "node-0", "node-1", etc.
    peer_id: PeerId,                   // Iroh peer ID
    doc: Doc,                          // Iroh document
    endpoint: Endpoint,                // Iroh endpoint
    storage: Arc<RwLock<RocksStorage>>, // Real RocksDB
    config: AppConfig,                 // Node configuration
    mock_node: Arc<Mutex<MockKaspaNode>>, // Shared mock node
}

impl TestNetwork {
    // Setup
    pub async fn new(num_nodes: usize) -> Result<Self>;
    pub async fn with_threshold(m: usize, n: usize) -> Result<Self>;

    // Node access
    pub fn node(&self, index: usize) -> &TestNode;
    pub fn node_mut(&mut self, index: usize) -> &mut TestNode;

    // Event injection
    pub async fn submit_event_to_node(
        &mut self,
        node_index: usize,
        event: SigningEvent,
    ) -> Result<String>;  // Returns request_id

    // Coordination
    pub async fn wait_for_proposal(&self, request_id: &str, timeout: Duration) -> Result<()>;
    pub async fn wait_for_threshold(&self, request_id: &str, timeout: Duration) -> Result<()>;
    pub async fn wait_for_finalization(&self, request_id: &str, timeout: Duration) -> Result<()>;

    // Assertions
    pub async fn assert_all_nodes_have_proposal(&self, request_id: &str);
    pub async fn assert_signatures_collected(&self, request_id: &str, expected: usize);
    pub async fn assert_transaction_finalized(&self, request_id: &str);

    // Failure injection
    pub async fn disconnect_node(&mut self, index: usize);
    pub async fn reconnect_node(&mut self, index: usize);
    pub async fn simulate_message_loss(&mut self, from: usize, to: usize, probability: f64);
    pub async fn inject_network_delay(&mut self, delay: Duration);

    // Cleanup
    pub async fn shutdown(self) -> Result<()>;
}

impl TestNode {
    // Coordination actions
    pub async fn propose_event(&mut self, event: SigningEvent) -> Result<String>;
    pub async fn process_proposal(&mut self, request_id: &str) -> Result<()>;
    pub async fn collect_signatures(&mut self, request_id: &str) -> Result<usize>;
    pub async fn finalize_transaction(&mut self, request_id: &str) -> Result<TransactionId>;

    // Storage queries
    pub async fn get_request(&self, request_id: &str) -> Result<Option<SigningRequest>>;
    pub async fn get_partial_signatures(&self, request_id: &str) -> Result<Vec<PartialSigRecord>>;
    pub async fn get_acks(&self, request_id: &str) -> Result<Vec<SignerAckRecord>>;

    // Metrics
    pub fn get_metric(&self, name: &str) -> Option<f64>;
}
```

**Key Features:**
- Real Iroh endpoints with in-memory transport (fast, deterministic)
- Each node has isolated RocksDB in temporary directory
- Shared MockKaspaNode (all nodes see same UTXO set)
- Network partition simulation (disconnect/reconnect)
- Message loss injection for robustness testing
- Automatic cleanup on drop

### TestKeyGenerator

Generates deterministic cryptographic keys for reproducible tests.

```rust
pub struct TestKeyGenerator {
    seed: [u8; 32],
}

impl TestKeyGenerator {
    pub fn new(seed: &str) -> Self;

    // Kaspa signing keys (secp256k1 Schnorr)
    pub fn generate_kaspa_keypair(&self, index: u32) -> (SecretKey, PublicKey);
    pub fn generate_kaspa_address(&self, index: u32, network: NetworkType) -> Address;

    // Hyperlane validator keys (secp256k1 ECDSA)
    pub fn generate_validator_keypair(&self, index: u32) -> (SecretKey, String); // Returns (key, eth_address)

    // Iroh transport keys (Ed25519)
    pub fn generate_iroh_keypair(&self, index: u32) -> (SecretKey, PeerId);

    // Redeem scripts
    pub fn generate_redeem_script(&self, m: usize, n: usize) -> Vec<u8>;
    pub fn generate_multisig_address(&self, m: usize, n: usize, network: NetworkType) -> Address;

    // HD wallet
    pub fn generate_mnemonic(&self, index: u32) -> Mnemonic;
    pub fn derive_pubkey(&self, mnemonic: &Mnemonic, path: &str) -> PublicKey;
}
```

**Key Features:**
- Deterministic key derivation from seed string
- Separate key types for each cryptographic domain
- Network-aware (testnet vs mainnet addresses)
- Reproducible across test runs

### TestDataFactory

Generates sample events, UTXOs, and configurations.

```rust
pub struct TestDataFactory;

impl TestDataFactory {
    // Events
    pub fn create_hyperlane_event(
        recipient: Address,
        amount: u64,
        nonce: u64,
    ) -> SigningEvent;

    pub fn create_layerzero_event(
        recipient: Address,
        amount: u64,
    ) -> SigningEvent;

    pub fn create_api_event(
        recipient: Address,
        amount: u64,
    ) -> SigningEvent;

    // UTXOs
    pub fn create_utxo_set(
        address: Address,
        count: usize,
        amount_per_utxo: u64,
    ) -> Vec<UtxoEntry>;

    pub fn create_fragmented_utxos(
        address: Address,
        amounts: Vec<u64>,
    ) -> Vec<UtxoEntry>;

    // Configurations
    pub fn create_config_2of3(
        data_dir: &Path,
        network: NetworkType,
    ) -> AppConfig;

    pub fn create_config_3of5(
        data_dir: &Path,
        network: NetworkType,
    ) -> AppConfig;

    pub fn create_policy_permissive() -> GroupPolicy;
    pub fn create_policy_restrictive() -> GroupPolicy;

    // Transactions
    pub fn create_pskt_from_utxos(
        utxos: Vec<UtxoEntry>,
        recipient: Address,
        amount: u64,
        fee_mode: FeePaymentMode,
    ) -> PSKT;
}
```

## Integration Test Categories

### 1. Happy Path Flows

**Test: 2-of-3 Threshold Complete Flow**
```rust
#[tokio::test]
async fn test_2of3_signing_complete_flow() {
    // Setup 3-node network with 2-of-3 threshold
    let mut network = TestNetwork::with_threshold(2, 3).await.unwrap();
    let mock_validators = MockHyperlaneValidator::new(3, 2);

    // Configure shared UTXO set (100 KAS per signer)
    for node in network.nodes.iter() {
        network.mock_node.add_utxos(
            node.config.pskt.source_addresses[0],
            TestDataFactory::create_utxo_set(node.config.pskt.source_addresses[0], 10, 10_000_000_000),
        );
    }

    // Create and sign event
    let event = TestDataFactory::create_hyperlane_event(
        test_recipient_address(),
        5_000_000_000, // 5 KAS
        1,
    );
    let signatures = mock_validators.sign_with_quorum(&event);
    event.hyperlane_signatures = Some(signatures);

    // Submit event to node 0 (becomes coordinator)
    let request_id = network.submit_event_to_node(0, event).await.unwrap();

    // Wait for proposal broadcast
    network.wait_for_proposal(&request_id, Duration::from_secs(5)).await.unwrap();

    // Assert all nodes received proposal
    network.assert_all_nodes_have_proposal(&request_id).await;

    // All nodes independently validate and sign
    for i in 0..3 {
        network.node_mut(i).process_proposal(&request_id).await.unwrap();
    }

    // Wait for threshold (2-of-3)
    network.wait_for_threshold(&request_id, Duration::from_secs(10)).await.unwrap();

    // Coordinator finalizes
    let tx_id = network.node_mut(0).finalize_transaction(&request_id).await.unwrap();

    // Assert transaction submitted to mock node
    network.mock_node.assert_transaction_submitted(&tx_id);

    // Verify transaction structure
    let tx = network.mock_node.get_submitted_transaction(&tx_id).unwrap();
    assert_eq!(tx.outputs[0].value, 5_000_000_000);
    assert_eq!(tx.outputs[0].script_public_key.script(), &test_recipient_address().payload);

    // Wait for finalization notice
    network.wait_for_finalization(&request_id, Duration::from_secs(5)).await.unwrap();

    // Assert all nodes recorded finalization
    for node in network.nodes.iter() {
        let req = node.get_request(&request_id).await.unwrap().unwrap();
        assert!(req.final_tx_id.is_some());
        assert_eq!(req.final_tx_id.unwrap(), tx_id);
    }
}
```

**Test: 3-of-5 Threshold with All Signers**
- 5 nodes, all respond
- Coordinator collects 3 signatures (ignores extra 2)
- Transaction finalized successfully

**Test: 3-of-5 Threshold with Exactly 3 Signers**
- 5 nodes, only 3 respond
- Coordinator waits for threshold
- Transaction finalized successfully

### 2. Coordinator Failure Scenarios

**Test: Coordinator Crashes After Proposal**
```rust
#[tokio::test]
async fn test_coordinator_failure_after_proposal() {
    let mut network = TestNetwork::with_threshold(2, 3).await.unwrap();

    // Setup and submit event
    let request_id = /* ... */;

    // Wait for proposal broadcast
    network.wait_for_proposal(&request_id, Duration::from_secs(5)).await.unwrap();

    // Simulate coordinator crash (node 0 disconnects)
    network.disconnect_node(0).await;

    // Remaining nodes (1, 2) still validate and sign
    for i in 1..3 {
        network.node_mut(i).process_proposal(&request_id).await.unwrap();
    }

    // Assert partial signatures stored
    for i in 1..3 {
        let sigs = network.node(i).get_partial_signatures(&request_id).await.unwrap();
        assert_eq!(sigs.len(), 1); // Each node has its own signature
    }

    // Reconnect coordinator
    network.reconnect_node(0).await;

    // Coordinator resumes, collects existing signatures
    let sig_count = network.node_mut(0).collect_signatures(&request_id).await.unwrap();
    assert_eq!(sig_count, 2); // Collected from nodes 1 and 2

    // Finalization succeeds
    let tx_id = network.node_mut(0).finalize_transaction(&request_id).await.unwrap();
    network.mock_node.assert_transaction_submitted(&tx_id);
}
```

**Test: Redundant Proposers**
- 2 nodes receive same event simultaneously
- Both build PSKTs (deterministic, should match)
- First proposal propagates, second is deduplicated
- Signing proceeds normally

### 3. Timeout Handling

**Test: Insufficient Signatures Timeout**
```rust
#[tokio::test]
async fn test_insufficient_signatures_timeout() {
    let mut network = TestNetwork::with_threshold(3, 5).await.unwrap();

    // Submit event
    let request_id = /* ... */;

    // Only 2 of 5 signers respond (below threshold)
    network.node_mut(1).process_proposal(&request_id).await.unwrap();
    network.node_mut(2).process_proposal(&request_id).await.unwrap();

    // Wait for session timeout (60 seconds)
    tokio::time::sleep(Duration::from_secs(65)).await;

    // Assert timeout in monitoring
    let monitoring = network.node(0).get_session_monitoring(&request_id).unwrap();
    assert!(monitoring.is_timed_out());

    // Assert no transaction submitted
    assert_eq!(network.mock_node.submitted_txs.len(), 0);

    // Assert metrics recorded
    assert_eq!(network.node(0).get_metric("session_timeouts_total"), Some(1.0));
}
```

**Test: Configurable Session Timeout**
- Test with `session_timeout_seconds = 30`
- Verify timeout honored
- Test with `session_timeout_seconds = 120`
- Verify longer timeout works

### 4. Concurrent Sessions

**Test: Multiple Sessions Different Events**
```rust
#[tokio::test]
async fn test_concurrent_sessions_different_events() {
    let mut network = TestNetwork::with_threshold(2, 3).await.unwrap();

    // Submit 5 events concurrently
    let mut request_ids = vec![];
    for i in 0..5 {
        let event = TestDataFactory::create_hyperlane_event(
            test_recipient_address(),
            (i + 1) * 1_000_000_000,
            i as u64,
        );
        let request_id = network.submit_event_to_node(0, event).await.unwrap();
        request_ids.push(request_id);
    }

    // Wait for all proposals
    for request_id in &request_ids {
        network.wait_for_proposal(request_id, Duration::from_secs(5)).await.unwrap();
    }

    // All nodes process all proposals
    for i in 0..3 {
        for request_id in &request_ids {
            network.node_mut(i).process_proposal(request_id).await.unwrap();
        }
    }

    // Wait for all finalizations
    for request_id in &request_ids {
        network.wait_for_finalization(request_id, Duration::from_secs(30)).await.unwrap();
    }

    // Assert all transactions submitted
    assert_eq!(network.mock_node.submitted_txs.len(), 5);

    // Assert amounts are correct
    for (i, tx) in network.mock_node.submitted_txs.iter().enumerate() {
        assert_eq!(tx.outputs[0].value, (i as u64 + 1) * 1_000_000_000);
    }

    // Assert no cross-contamination (each session isolated)
    for (i, request_id) in request_ids.iter().enumerate() {
        let req = network.node(0).get_request(request_id).await.unwrap().unwrap();
        assert_eq!(req.event.amount_sompi, (i as u64 + 1) * 1_000_000_000);
    }
}
```

**Test: Interleaved Session Processing**
- Start session A
- Start session B before A completes
- A and B sign independently
- Both finalize successfully

### 5. Replay Protection

**Test: Duplicate Event Rejection**
```rust
#[tokio::test]
async fn test_duplicate_event_rejection() {
    let mut network = TestNetwork::with_threshold(2, 3).await.unwrap();

    let event = TestDataFactory::create_hyperlane_event(
        test_recipient_address(),
        5_000_000_000,
        1,
    );

    // Submit event first time (success)
    let request_id1 = network.submit_event_to_node(0, event.clone()).await.unwrap();
    network.wait_for_finalization(&request_id1, Duration::from_secs(30)).await.unwrap();

    // Submit exact same event again (should reject)
    let result = network.submit_event_to_node(0, event.clone()).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("duplicate event"));

    // Assert only 1 transaction submitted
    assert_eq!(network.mock_node.submitted_txs.len(), 1);

    // Assert event_hash stored in all nodes
    for node in network.nodes.iter() {
        let event_hash = compute_event_hash(&event);
        let stored_event = node.storage.read().await.get_event(&event_hash).unwrap();
        assert!(stored_event.is_some());
    }
}
```

**Test: Transport Message Deduplication**
- Simulate network duplicate (same proposal received twice)
- Assert processed only once
- Verify `seen:` marker in storage

**Test: Replay After Restart**
- Submit and finalize event
- Restart node (reload RocksDB)
- Attempt to replay same event
- Assert rejection persists

### 6. PSKT Determinism

**Test: Independent PSKT Reconstruction**
```rust
#[tokio::test]
async fn test_pskt_determinism_across_signers() {
    let mut network = TestNetwork::with_threshold(2, 3).await.unwrap();

    // All nodes share same UTXO set
    let utxos = TestDataFactory::create_utxo_set(
        network.node(0).config.pskt.source_addresses[0],
        20,
        5_000_000_000,
    );
    network.mock_node.add_utxos(
        network.node(0).config.pskt.source_addresses[0],
        utxos.clone(),
    );

    let event = TestDataFactory::create_hyperlane_event(
        test_recipient_address(),
        10_000_000_000,
        1,
    );

    // Submit to node 0
    let request_id = network.submit_event_to_node(0, event.clone()).await.unwrap();
    network.wait_for_proposal(&request_id, Duration::from_secs(5)).await.unwrap();

    // Each node independently rebuilds PSKT
    let mut pskts = vec![];
    for i in 0..3 {
        let proposal = network.node(i).get_proposal(&request_id).await.unwrap().unwrap();
        pskts.push(proposal.pskt_blob.clone());
    }

    // Assert all PSKTs are byte-for-byte identical
    assert_eq!(pskts[0], pskts[1]);
    assert_eq!(pskts[1], pskts[2]);

    // Assert tx_template_hash matches
    let hash_0 = network.node(0).compute_tx_template_hash(&request_id).unwrap();
    let hash_1 = network.node(1).compute_tx_template_hash(&request_id).unwrap();
    let hash_2 = network.node(2).compute_tx_template_hash(&request_id).unwrap();
    assert_eq!(hash_0, hash_1);
    assert_eq!(hash_1, hash_2);
}
```

**Test: UTXO Ordering Stability**
- Query UTXOs in different orders from mock node
- Verify PSKT always uses same order (sorted by tx_id, then index)
- Assert deterministic output

**Test: Fee Calculation Consistency**
```rust
#[tokio::test]
async fn test_fee_calculation_determinism() {
    let fee_modes = vec![
        FeePaymentMode::RecipientPays,
        FeePaymentMode::SignersPay,
        FeePaymentMode::Split { recipient_portion: 0.33 },
        FeePaymentMode::Split { recipient_portion: 0.5 },
        FeePaymentMode::Split { recipient_portion: 0.67 },
    ];

    for fee_mode in fee_modes {
        // Build PSKT 10 times with same inputs
        let mut output_amounts = vec![];
        for _ in 0..10 {
            let pskt = TestDataFactory::create_pskt_from_utxos(
                test_utxos(),
                test_recipient_address(),
                10_000_000_000,
                fee_mode.clone(),
            );
            output_amounts.push(pskt.outputs[0].value);
        }

        // Assert all amounts identical
        assert!(output_amounts.windows(2).all(|w| w[0] == w[1]));

        // Assert integer arithmetic (no floating-point drift)
        let expected = calculate_expected_amount(10_000_000_000, fee_mode.clone());
        assert_eq!(output_amounts[0], expected);
    }
}
```

### 7. Policy Enforcement

**Test: Destination Allowlist**
```rust
#[tokio::test]
async fn test_destination_allowlist_enforcement() {
    let mut network = TestNetwork::with_threshold(2, 3).await.unwrap();

    // Configure policy with allowlist
    let allowed = test_recipient_address();
    let forbidden = test_other_address();
    network.node_mut(0).config.policy.allowed_destinations = vec![allowed.clone()];

    // Event to allowed destination (accept)
    let event_ok = TestDataFactory::create_hyperlane_event(allowed, 5_000_000_000, 1);
    let result_ok = network.submit_event_to_node(0, event_ok).await;
    assert!(result_ok.is_ok());

    // Event to forbidden destination (reject)
    let event_bad = TestDataFactory::create_hyperlane_event(forbidden, 5_000_000_000, 2);
    let result_bad = network.submit_event_to_node(0, event_bad).await;
    assert!(result_bad.is_err());
    assert!(result_bad.unwrap_err().to_string().contains("not in allowlist"));
}
```

**Test: Amount Limits**
- `min_amount_sompi`: Reject below minimum
- `max_amount_sompi`: Reject above maximum
- Valid range: Accept

**Test: Daily Volume Limits**
```rust
#[tokio::test]
async fn test_daily_volume_limit() {
    let mut network = TestNetwork::with_threshold(2, 3).await.unwrap();

    // Configure policy: max 100 KAS per day
    network.node_mut(0).config.policy.max_daily_volume_sompi = 100_000_000_000;

    // Submit and finalize 5 x 20 KAS = 100 KAS (exactly at limit)
    for i in 0..5 {
        let event = TestDataFactory::create_hyperlane_event(
            test_recipient_address(),
            20_000_000_000,
            i,
        );
        let request_id = network.submit_event_to_node(0, event).await.unwrap();
        network.wait_for_finalization(&request_id, Duration::from_secs(30)).await.unwrap();
    }

    // 6th event (would exceed limit) rejected
    let event_exceed = TestDataFactory::create_hyperlane_event(
        test_recipient_address(),
        1_000_000_000, // Even 1 KAS exceeds
        5,
    );
    let result = network.submit_event_to_node(0, event_exceed).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("daily volume limit"));

    // Fast-forward 24 hours
    network.advance_time(Duration::from_secs(86400)).await;

    // 7th event (new day) accepted
    let event_new_day = TestDataFactory::create_hyperlane_event(
        test_recipient_address(),
        20_000_000_000,
        6,
    );
    let result_ok = network.submit_event_to_node(0, event_new_day).await;
    assert!(result_ok.is_ok());
}
```

**Test: Memo Requirement**
- `require_reason = true`: Reject events without memo
- `require_reason = false`: Accept without memo

### 8. Cryptography Tests

**Test: Threshold Signature Collection**
```rust
#[tokio::test]
async fn test_threshold_signature_collection() {
    let mut network = TestNetwork::with_threshold(3, 5).await.unwrap();

    // Submit event
    let request_id = /* ... */;
    network.wait_for_proposal(&request_id, Duration::from_secs(5)).await.unwrap();

    // Collect signatures from exactly 3 signers
    network.node_mut(1).process_proposal(&request_id).await.unwrap();
    network.node_mut(2).process_proposal(&request_id).await.unwrap();
    network.node_mut(3).process_proposal(&request_id).await.unwrap();

    // Coordinator detects threshold
    let sig_count = network.node_mut(0).collect_signatures(&request_id).await.unwrap();
    assert_eq!(sig_count, 3);

    // Finalize transaction
    let tx_id = network.node_mut(0).finalize_transaction(&request_id).await.unwrap();
    let tx = network.mock_node.get_submitted_transaction(&tx_id).unwrap();

    // Verify transaction has valid signatures
    for (i, input) in tx.inputs.iter().enumerate() {
        assert_eq!(input.signature_script.len(), /* expected multisig script size */);
        // Verify signature count in redeem script
        let sig_count = parse_signature_count(&input.signature_script);
        assert_eq!(sig_count, 3);
    }
}
```

**Test: Event Signature Validation**
```rust
#[tokio::test]
async fn test_hyperlane_signature_validation() {
    let network = TestNetwork::with_threshold(2, 3).await.unwrap();
    let mock_validators = MockHyperlaneValidator::new(3, 2);

    let event = TestDataFactory::create_hyperlane_event(
        test_recipient_address(),
        5_000_000_000,
        1,
    );

    // Valid signatures (2-of-3)
    let valid_sigs = mock_validators.sign_with_quorum(&event);
    event.hyperlane_signatures = Some(valid_sigs);
    let result = network.node(0).validate_event(&event);
    assert!(result.is_ok());

    // Invalid signature (wrong key)
    let invalid_sigs = mock_validators.sign_with_invalid_key(&event);
    event.hyperlane_signatures = Some(invalid_sigs);
    let result = network.node(0).validate_event(&event);
    assert!(result.is_err());

    // Insufficient signatures (1-of-3)
    let insufficient_sigs = mock_validators.sign_with_insufficient(&event);
    event.hyperlane_signatures = Some(insufficient_sigs);
    let result = network.node(0).validate_event(&event);
    assert!(result.is_err());
}
```

**Test: Transport Envelope Signing**
```rust
#[tokio::test]
async fn test_transport_envelope_authentication() {
    let mut network = TestNetwork::with_threshold(2, 3).await.unwrap();

    // Node 0 sends proposal
    let request_id = /* ... */;
    network.wait_for_proposal(&request_id, Duration::from_secs(5)).await.unwrap();

    // Nodes 1 and 2 verify envelope signature
    let proposal_msg = network.node(1).get_received_message(&request_id).unwrap();
    assert!(proposal_msg.verify_envelope_signature(network.node(0).peer_id));

    // Tamper with envelope (should fail verification)
    let mut tampered = proposal_msg.clone();
    tampered.payload.session_id = "tampered".to_string();
    assert!(!tampered.verify_envelope_signature(network.node(0).peer_id));
}
```

**Test: Constant-Time Hash Comparison**
```rust
#[test]
fn test_constant_time_hash_comparison() {
    use std::time::Instant;

    let hash1 = [0u8; 32];
    let hash2_match = [0u8; 32];
    let hash2_differ = [255u8; 32];

    // Warm up
    for _ in 0..1000 {
        let _ = constant_time_eq(&hash1, &hash2_match);
        let _ = constant_time_eq(&hash1, &hash2_differ);
    }

    // Measure matching comparison
    let mut match_times = vec![];
    for _ in 0..10000 {
        let start = Instant::now();
        let _ = constant_time_eq(&hash1, &hash2_match);
        match_times.push(start.elapsed().as_nanos());
    }

    // Measure differing comparison
    let mut differ_times = vec![];
    for _ in 0..10000 {
        let start = Instant::now();
        let _ = constant_time_eq(&hash1, &hash2_differ);
        differ_times.push(start.elapsed().as_nanos());
    }

    // Statistical analysis
    let match_mean: f64 = match_times.iter().map(|&t| t as f64).sum::<f64>() / match_times.len() as f64;
    let differ_mean: f64 = differ_times.iter().map(|&t| t as f64).sum::<f64>() / differ_times.len() as f64;

    // Assert no significant timing difference (< 5% deviation)
    let diff_pct = ((match_mean - differ_mean).abs() / match_mean) * 100.0;
    assert!(diff_pct < 5.0, "Timing difference: {:.2}%", diff_pct);
}
```

**Test: Key Separation Enforcement**
- Compile-time test: Kaspa key type ≠ Iroh key type
- Runtime test: Verify keys never cross boundaries

### 9. Storage Tests

**Test: Audit Trail Completeness**
```rust
#[tokio::test]
async fn test_audit_trail_completeness() {
    let mut network = TestNetwork::with_threshold(2, 3).await.unwrap();

    // Execute full signing flow
    let request_id = /* ... */;
    network.wait_for_finalization(&request_id, Duration::from_secs(30)).await.unwrap();

    // Verify audit trail in node 0
    let storage = network.node(0).storage.read().await;

    // 1. Event stored
    let event = storage.get_event_by_request(&request_id).unwrap().unwrap();
    assert_eq!(event.recipient_address, test_recipient_address());

    // 2. Request stored
    let request = storage.get_request(&request_id).unwrap().unwrap();
    assert_eq!(request.event_hash, compute_event_hash(&event));
    assert!(request.final_tx_id.is_some());

    // 3. Proposal stored
    let proposal = storage.get_proposal(&request_id).unwrap().unwrap();
    assert!(!proposal.pskt_blob.is_empty());

    // 4. Request inputs stored
    let inputs = storage.get_request_inputs(&request_id).unwrap();
    assert!(!inputs.is_empty());

    // 5. Acks stored (2-of-3)
    let acks = storage.get_acks(&request_id).unwrap();
    assert_eq!(acks.len(), 2); // 2 signers acked

    // 6. Partial signatures stored (2-of-3)
    let sigs = storage.get_partial_sigs(&request_id).unwrap();
    assert_eq!(sigs.len(), 2); // 2 signers signed

    // 7. Final tx_id recorded
    assert!(request.final_tx_id.is_some());
    assert!(request.accepted_blue_score.is_some());
}
```

**Test: Session Isolation**
- Create 2 concurrent sessions
- Verify partial signatures isolated by request_id
- Verify no cross-session reads

**Test: Persistence Across Restarts**
```rust
#[tokio::test]
async fn test_persistence_across_restarts() {
    let data_dir = tempdir().unwrap();

    // First run: submit and finalize event
    {
        let mut network = TestNetwork::with_data_dir(&data_dir).await.unwrap();
        let request_id = /* ... */;
        network.wait_for_finalization(&request_id, Duration::from_secs(30)).await.unwrap();
    }

    // Second run: reload database, verify data persisted
    {
        let network = TestNetwork::with_data_dir(&data_dir).await.unwrap();
        let storage = network.node(0).storage.read().await;

        let requests = storage.get_all_requests().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].final_tx_id.is_some());
    }
}
```

**Test: Volume Tracking Accuracy**
- Submit 10 events throughout "day"
- Query volume at different timestamps
- Verify running total correct

### 10. RPC Integration Tests

**Test: Event Submission via JSON-RPC**
```rust
#[tokio::test]
async fn test_rpc_event_submission() {
    let mut network = TestNetwork::with_threshold(2, 3).await.unwrap();

    // Start JSON-RPC server on node 0
    network.node_mut(0).start_rpc_server().await.unwrap();

    let client = reqwest::Client::new();
    let event = TestDataFactory::create_hyperlane_event(
        test_recipient_address(),
        5_000_000_000,
        1,
    );

    // Submit via RPC
    let response = client.post("http://127.0.0.1:8088/rpc")
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "signing_event.submit",
            "params": [event],
            "id": 1,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let result: serde_json::Value = response.json().await.unwrap();
    let request_id = result["result"]["request_id"].as_str().unwrap();

    // Verify signing proceeds
    network.wait_for_finalization(request_id, Duration::from_secs(30)).await.unwrap();
}
```

**Test: RPC Authentication**
```rust
#[tokio::test]
async fn test_rpc_authentication() {
    let mut network = TestNetwork::with_threshold(2, 3).await.unwrap();
    network.node_mut(0).config.rpc.token = Some("secret123".to_string());
    network.node_mut(0).start_rpc_server().await.unwrap();

    let client = reqwest::Client::new();

    // Without token (reject)
    let response = client.post("http://127.0.0.1:8088/rpc")
        .json(&json!({"jsonrpc": "2.0", "method": "signing_event.submit", "params": [], "id": 1}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);

    // With correct token (accept)
    let response = client.post("http://127.0.0.1:8088/rpc")
        .header("Authorization", "Bearer secret123")
        .json(&json!({"jsonrpc": "2.0", "method": "signing_event.submit", "params": [], "id": 1}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}
```

**Test: Health Check Endpoints**
```rust
#[tokio::test]
async fn test_health_check_endpoints() {
    let network = TestNetwork::with_threshold(2, 3).await.unwrap();
    network.node(0).start_http_server().await.unwrap();

    let client = reqwest::Client::new();

    // /health (basic liveness)
    let response = client.get("http://127.0.0.1:8088/health").send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "OK");

    // /ready (readiness with dependencies)
    let response = client.get("http://127.0.0.1:8088/ready").send().await.unwrap();
    assert_eq!(response.status(), 200);
    let status: serde_json::Value = response.json().await.unwrap();
    assert_eq!(status["status"], "ready");
    assert_eq!(status["kaspa_node"], "connected");
    assert_eq!(status["iroh_transport"], "active");
}
```

**Test: Metrics Endpoint**
```rust
#[tokio::test]
async fn test_metrics_endpoint() {
    let mut network = TestNetwork::with_threshold(2, 3).await.unwrap();
    network.node(0).start_http_server().await.unwrap();

    // Execute signing flow
    let request_id = /* ... */;
    network.wait_for_finalization(&request_id, Duration::from_secs(30)).await.unwrap();

    // Query metrics
    let client = reqwest::Client::new();
    let response = client.get("http://127.0.0.1:8088/metrics").send().await.unwrap();
    assert_eq!(response.status(), 200);

    let metrics = response.text().await.unwrap();
    assert!(metrics.contains("signing_sessions_total{status=\"finalized\"} 1"));
    assert!(metrics.contains("signer_acks_total"));
    assert!(metrics.contains("partial_sigs_total"));
}
```

### 11. Performance Tests

**Test: PSKT Build Latency**
```rust
#[tokio::test]
async fn test_pskt_build_performance() {
    let mock_node = Arc::new(Mutex::new(MockKaspaNode::new()));

    // Create 100 UTXOs (realistic scenario)
    let utxos = TestDataFactory::create_utxo_set(
        test_source_address(),
        100,
        1_000_000_000,
    );
    mock_node.lock().unwrap().add_utxos(test_source_address(), utxos);

    let event = TestDataFactory::create_hyperlane_event(
        test_recipient_address(),
        50_000_000_000,
        1,
    );

    // Measure build time (10 iterations)
    let mut durations = vec![];
    for _ in 0..10 {
        let start = Instant::now();
        let pskt = build_pskt(&mock_node, &event, &test_config()).await.unwrap();
        durations.push(start.elapsed());
        assert!(!pskt.is_empty());
    }

    // Assert P50 < 100ms, P95 < 200ms
    durations.sort();
    assert!(durations[5] < Duration::from_millis(100), "P50: {:?}", durations[5]);
    assert!(durations[9] < Duration::from_millis(200), "P95: {:?}", durations[9]);
}
```

**Test: Signature Throughput**
```rust
#[tokio::test]
async fn test_signature_throughput() {
    let mut network = TestNetwork::with_threshold(3, 5).await.unwrap();

    // Submit 100 events
    let start = Instant::now();
    let mut request_ids = vec![];
    for i in 0..100 {
        let event = TestDataFactory::create_hyperlane_event(
            test_recipient_address(),
            1_000_000_000,
            i,
        );
        let request_id = network.submit_event_to_node(0, event).await.unwrap();
        request_ids.push(request_id);
    }

    // Wait for all finalizations
    for request_id in &request_ids {
        network.wait_for_finalization(request_id, Duration::from_secs(120)).await.unwrap();
    }

    let elapsed = start.elapsed();
    let throughput = 100.0 / elapsed.as_secs_f64();

    println!("Throughput: {:.2} signatures/sec", throughput);
    assert!(throughput > 1.0, "Throughput too low: {:.2}", throughput);
}
```

**Test: Concurrent Session Capacity**
```rust
#[tokio::test]
async fn test_concurrent_session_capacity() {
    let mut network = TestNetwork::with_threshold(2, 3).await.unwrap();

    // Launch 50 concurrent sessions
    let mut handles = vec![];
    for i in 0..50 {
        let mut network = network.clone();
        let handle = tokio::spawn(async move {
            let event = TestDataFactory::create_hyperlane_event(
                test_recipient_address(),
                1_000_000_000,
                i,
            );
            let request_id = network.submit_event_to_node(0, event).await.unwrap();
            network.wait_for_finalization(&request_id, Duration::from_secs(60)).await.unwrap();
        });
        handles.push(handle);
    }

    // Wait for all sessions
    let results = futures::future::join_all(handles).await;

    // Assert all succeeded
    let success_count = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(success_count, 50, "Only {} of 50 sessions succeeded", success_count);
}
```

**Test: Memory Usage**
```rust
#[tokio::test]
async fn test_memory_usage() {
    // Track peak RSS throughout test
    let initial_rss = get_rss_mb();

    let mut network = TestNetwork::with_threshold(2, 3).await.unwrap();

    // Process 1000 events
    for i in 0..1000 {
        let event = TestDataFactory::create_hyperlane_event(
            test_recipient_address(),
            1_000_000_000,
            i,
        );
        let request_id = network.submit_event_to_node(0, event).await.unwrap();
        network.wait_for_finalization(&request_id, Duration::from_secs(30)).await.unwrap();

        // Sample RSS every 100 events
        if i % 100 == 0 {
            let current_rss = get_rss_mb();
            println!("RSS after {} events: {} MB", i, current_rss);
        }
    }

    let final_rss = get_rss_mb();
    let growth = final_rss - initial_rss;

    // Assert memory growth < 100 MB
    assert!(growth < 100.0, "Memory growth: {:.2} MB", growth);
}
```

### 12. Security Tests

**Test: Malicious Coordinator Tampered PSKT**
```rust
#[tokio::test]
async fn test_malicious_coordinator_tampered_pskt() {
    let mut network = TestNetwork::with_threshold(2, 3).await.unwrap();

    let event = TestDataFactory::create_hyperlane_event(
        test_recipient_address(),
        5_000_000_000,
        1,
    );

    // Node 0 proposes, but tampers with recipient address
    let request_id = network.node_mut(0).propose_event(event.clone()).await.unwrap();

    // Manually tamper with PSKT in storage before broadcasting
    {
        let mut storage = network.node_mut(0).storage.write().await;
        let mut proposal = storage.get_proposal(&request_id).unwrap().unwrap();

        // Change recipient to attacker address
        let tampered_pskt = tamper_pskt_recipient(&proposal.pskt_blob, attacker_address());
        proposal.pskt_blob = tampered_pskt;
        storage.update_proposal(&request_id, proposal).unwrap();
    }

    // Broadcast tampered proposal
    network.node_mut(0).broadcast_proposal(&request_id).await.unwrap();

    // Signers rebuild PSKT and detect mismatch
    let result_1 = network.node_mut(1).process_proposal(&request_id).await;
    let result_2 = network.node_mut(2).process_proposal(&request_id).await;

    // Both signers reject (validation_hash mismatch)
    assert!(result_1.is_err());
    assert!(result_2.is_err());
    assert!(result_1.unwrap_err().to_string().contains("validation_hash mismatch"));

    // No signatures collected
    let sig_count = network.node_mut(0).collect_signatures(&request_id).await.unwrap();
    assert_eq!(sig_count, 0);
}
```

**Test: Replay Attack Simulation**
```rust
#[tokio::test]
async fn test_replay_attack_simulation() {
    let mut network = TestNetwork::with_threshold(2, 3).await.unwrap();

    // Capture legitimate signing flow
    let event = TestDataFactory::create_hyperlane_event(
        test_recipient_address(),
        5_000_000_000,
        1,
    );
    let request_id = network.submit_event_to_node(0, event.clone()).await.unwrap();
    network.wait_for_finalization(&request_id, Duration::from_secs(30)).await.unwrap();

    // Attacker captures event and tries to replay
    let replay_result = network.submit_event_to_node(0, event.clone()).await;
    assert!(replay_result.is_err());
    assert!(replay_result.unwrap_err().to_string().contains("duplicate event"));

    // Attacker captures transport message and replays
    let proposal_msg = network.node(1).get_last_received_message().unwrap();
    network.inject_message(proposal_msg.clone()).await;

    // Verify deduplication (seen: marker prevents reprocessing)
    let reprocess_count = network.node(1).get_metric("messages_deduplicated_total").unwrap();
    assert_eq!(reprocess_count, 1.0);
}
```

**Test: DoS Resistance**
```rust
#[tokio::test]
async fn test_dos_resistance_invalid_events() {
    let mut network = TestNetwork::with_threshold(2, 3).await.unwrap();

    // Flood with 1000 invalid events (invalid signatures)
    let start = Instant::now();
    for i in 0..1000 {
        let event = TestDataFactory::create_hyperlane_event(
            test_recipient_address(),
            1_000_000_000,
            i,
        );
        // Intentionally invalid signature
        event.hyperlane_signatures = Some(vec!["0xdeadbeef".to_string()]);

        let result = network.submit_event_to_node(0, event).await;
        assert!(result.is_err());
    }
    let elapsed = start.elapsed();

    // Assert rejection is fast (< 1ms per event average)
    assert!(elapsed < Duration::from_secs(1), "Rejection too slow: {:?}", elapsed);

    // Assert no resource exhaustion (memory, file descriptors)
    let rss_mb = get_rss_mb();
    assert!(rss_mb < 200.0, "Memory exhaustion: {} MB", rss_mb);
}
```

## CI/CD Integration

### GitHub Actions Workflow

```yaml
name: Integration Tests

on:
  push:
    branches: [master]
  pull_request:
    branches: [master]

jobs:
  integration:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
        rust: [stable, nightly]

    steps:
      - uses: actions/checkout@v3

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: ${{ matrix.rust }}
          override: true

      - name: Cache dependencies
        uses: actions/cache@v3
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

      - name: Run unit tests
        run: cargo test --lib --release

      - name: Run integration tests (flows)
        run: cargo test --test integration --release -- flows::

      - name: Run integration tests (determinism)
        run: cargo test --test integration --release -- determinism::

      - name: Run integration tests (cryptography)
        run: cargo test --test integration --release -- cryptography::

      - name: Run integration tests (coordination)
        run: cargo test --test integration --release -- coordination::

      - name: Run integration tests (storage)
        run: cargo test --test integration --release -- storage::

      - name: Run integration tests (policy)
        run: cargo test --test integration --release -- policy::

      - name: Run integration tests (security)
        run: cargo test --test integration --release -- security::

      - name: Run performance benchmarks
        run: cargo bench --bench integration_perf

      - name: Generate coverage report
        run: |
          cargo install cargo-tarpaulin
          cargo tarpaulin --out Xml --release

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          file: ./cobertura.xml
```

## Local Development Workflow

### Running Full Test Suite

```bash
# Run all integration tests
cargo test --test integration --release

# Run specific test category
cargo test --test integration --release -- flows::
cargo test --test integration --release -- cryptography::

# Run with detailed output
cargo test --test integration --release -- --nocapture

# Run single test
cargo test --test integration --release test_2of3_signing_complete_flow
```

### Running Performance Tests

```bash
# Run all benchmarks
cargo bench --bench integration_perf

# Run specific benchmark
cargo bench --bench integration_perf pskt_build_latency

# Generate flamegraph
cargo flamegraph --bench integration_perf -- --bench
```

### Test Data Management

```bash
# Generate fresh test fixtures
cargo run --bin generate-test-fixtures

# Validate existing fixtures
cargo test --test validate_fixtures

# Clean up temporary test data
cargo clean-test-data
```

## Test Coverage Goals

| Category            | Target Coverage | Current | Status |
|---------------------|-----------------|---------|--------|
| Unit Tests          | 80%             | 70%     | 🟡     |
| Integration Tests   | 90%             | 75%     | 🟡     |
| Happy Path Flows    | 100%            | 100%    | ✅     |
| Failure Scenarios   | 90%             | 80%     | 🟡     |
| Cryptography        | 100%            | 90%     | 🟡     |
| Policy Enforcement  | 100%            | 85%     | 🟡     |
| Performance Tests   | N/A             | 60%     | 🟡     |
| Security Tests      | 100%            | 75%     | 🟡     |

## Open Questions and Next Steps

### Phase 1: Complete Mock Infrastructure
1. ✅ MockKaspaNode implementation
2. ✅ MockHyperlaneValidator implementation
3. ✅ TestNetwork harness with real Iroh
4. ✅ TestKeyGenerator for deterministic keys
5. ✅ TestDataFactory for fixtures

### Phase 2: Happy Path Coverage
6. ✅ 2-of-3 complete flow
7. ✅ 3-of-5 complete flow
8. ✅ Fee payment modes (RecipientPays, SignersPay, Split)
9. ✅ Event sources (Hyperlane, LayerZero, API)

### Phase 3: Failure Scenarios
10. ⚠️ Coordinator failure after proposal
11. ⚠️ Timeout with insufficient signatures
12. ⚠️ Network partition and recovery
13. ⚠️ Redundant proposers

### Phase 4: Security Hardening
14. ⚠️ Constant-time hash comparison verification
15. ⚠️ Malicious coordinator detection
16. ⚠️ Replay attack prevention
17. ⚠️ DoS resistance

### Phase 5: Performance Validation
18. ⚠️ PSKT build latency benchmarks
19. ⚠️ Signature throughput tests
20. ⚠️ Concurrent session capacity
21. ⚠️ Memory usage profiling

### Phase 6: Cross-Platform Determinism
22. ❌ WASM32 compatibility
23. ❌ Big-endian vs little-endian hash consistency

## Appendix: Test Environment Setup

### Required Dependencies

```toml
[dev-dependencies]
tokio = { version = "1", features = ["full", "test-util"] }
tempfile = "3"
serde_json = "1"
hex = "0.4"
sha2 = "0.10"
secp256k1 = "0.27"
ed25519-dalek = "2"
iroh = { version = "0.23", features = ["test-utils"] }
criterion = "0.5"
proptest = "1"
quickcheck = "1"
```

### Test Configuration

```ini
# tests/fixtures/configs/test_2of3.ini
[service]
node_rpc_url = mock://localhost
data_dir = ${TEMP_DIR}

[pskt]
source_addresses = kaspatest:qz1,kaspatest:qz2
redeem_script_hex = 522102...52ae
sig_op_count = 2
fee_payment_mode = recipient_pays

[group]
threshold_m = 2
threshold_n = 3

[iroh]
network_id = 999  # Test network
```

---

**Document Version:** 1.0
**Last Updated:** 2025-12-30
**Status:** Draft for Review
**Next Review:** After Phase 1 completion
