# Igra V1 Development TODOs

**Version:** V1 (Threshold Multisig Only)
**Last Updated:** 2025-12-28
**Target:** Production-ready threshold multisig signing for Kaspa

---

## Executive Summary

The implementation has **strong foundational work** (~3,400 lines) with core threshold multisig functionality in place. This document outlines the remaining work to reach V1 production readiness.

**Current Status:** ~70% complete for V1 threshold multisig
- ✅ PSKT building and multisig signing complete
- ✅ Storage, transport, and coordination primitives in place
- ⚠️ Missing automated coordination loop
- ⚠️ Policy enforcement not wired
- ⚠️ Minimal testing coverage

**Time to Production:** 3-5 weeks (15-25 developer days)

---

## Architecture Overview

### Unified Signer/Coordinator Model

**IMPORTANT:** This system uses a **unified architecture** where every node is both a signer AND a potential coordinator:

- **Every node runs identical software** - no separate "coordinator" vs "signer" binaries
- **Coordinator role is ephemeral** - any node can propose a signing session (becoming the coordinator for that specific session)
- **All nodes respond to proposals** - when a node receives a proposal from another node, it validates and signs
- **Multiple nodes can propose** - for redundancy, multiple nodes can have `rpc.enabled = true` to receive external events
- **Pure response mode** - nodes with `rpc.enabled = false` only respond to proposals from others

### Typical 3-of-5 Deployment:
```
┌─────────────────────────────────────────────────────────────┐
│  Bridge Operator Node 1 (RPC enabled)                       │
│  - Receives Hyperlane events via JSON-RPC                   │
│  - Proposes signing sessions                                │
│  - Signs when others propose                                │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Bridge Operator Node 2 (RPC enabled) - Backup proposer     │
│  - Receives Hyperlane events via JSON-RPC                   │
│  - Proposes signing sessions (redundancy)                   │
│  - Signs when others propose                                │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Signer Node 3 (RPC disabled) - Pure signer                 │
│  - Only responds to proposals from peers                    │
│  - Validates and signs PSKTs                                │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Signer Node 4 (RPC disabled) - Pure signer                 │
│  - Only responds to proposals from peers                    │
│  - Validates and signs PSKTs                                │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Signer Node 5 (RPC disabled) - Pure signer                 │
│  - Only responds to proposals from peers                    │
│  - Validates and signs PSKTs                                │
└─────────────────────────────────────────────────────────────┘

Threshold: Any 3 signatures finalize the transaction
```

**Key Benefits:**
- **No single coordinator** - any proposal node can fail without blocking the group
- **Simplified operations** - same binary, same config structure for all nodes
- **Flexible topology** - adjust which nodes can propose via `rpc.enabled` flag
- **Fault tolerance** - multiple proposers provide redundancy

---

## 1. Critical Missing Features (Blocks V1 Production)

### 1.1 Automated Coordination Loop ❌ **HIGH PRIORITY**

**Architecture Note:** In this system, **every signer is also a potential coordinator**. The "coordinator" role is **ephemeral** - any signer can propose a signing session (becoming the coordinator for that session). All nodes run identical software and can both propose sessions AND respond to proposals from other signers.

**Status:** Service binary can build PSKTs and finalize manually, but NO background task to automatically respond to proposals from other signers.

**Current Behavior:**
- A signer can manually build PSBT in test mode (acting as coordinator)
- Manual finalization via env vars (`KASPA_FINALIZE_PSKT_JSON`)
- No daemon mode that automatically responds to proposals from peers

**What's Needed:**

**File:** `igra-service/src/bin/kaspa-threshold-service.rs`

Add background coordination task that handles BOTH roles:

```rust
async fn coordination_loop(
    config: Arc<Config>,
    transport: Arc<IrohTransport>,
    storage: Arc<RocksStorage>,
    coordinator: Arc<Coordinator>,
    signer: Arc<Signer>,
) -> Result<()> {
    info!("Starting coordination loop (proposal handler + signer responder)...");

    // Subscribe to group proposals from ANY signer (including ourselves)
    let mut proposal_stream = transport.subscribe_proposals(&config.iroh.group_id).await?;

    while let Some(envelope) = proposal_stream.next().await {
        let my_peer_id = &config.iroh.peer_id;

        match envelope.payload {
            TransportMessage::Propose(proposal) => {
                // If this is OUR proposal, collect signatures
                if proposal.coordinator_peer_id == *my_peer_id {
                    info!("This is our proposal, collecting signatures...");
                    tokio::spawn(collect_and_finalize(
                        config.clone(),
                        transport.clone(),
                        coordinator.clone(),
                        proposal,
                    ));
                } else {
                    // This is someone else's proposal, validate and sign
                    info!(
                        "Received proposal from {}: request_id={}",
                        proposal.coordinator_peer_id, proposal.request_id
                    );

                    // Validate proposal
                    match signer.validate_proposal(&proposal, &config.policy).await {
                        Ok(_) => {
                            info!("Proposal validated, signing PSKT...");

                            // Sign PSKT
                            let sig_result = signer.sign_pskt(&proposal.pskt).await?;

                            // Submit partial signature
                            transport.publish_partial_sig(
                                proposal.session_id,
                                sig_result,
                            ).await?;

                            info!("Partial signature submitted");
                        }
                        Err(e) => {
                            warn!("Proposal validation failed: {}", e);

                            // Publish rejection
                            transport.publish_rejection(
                                proposal.session_id,
                                e.to_string(),
                            ).await?;
                        }
                    }
                }
            }
            TransportMessage::PartialSig(partial_sig) => {
                // If we're the coordinator for this session, collect this signature
                if let Some(session) = storage.get_session(&partial_sig.session_id)? {
                    if session.coordinator_peer_id == *my_peer_id {
                        info!("Received partial signature from {}", partial_sig.signer_peer_id);
                        storage.store_partial_sig(partial_sig)?;
                    }
                }
            }
            TransportMessage::Ack(ack) => {
                // Track acknowledgments
                info!("Received ack from {}", ack.signer_peer_id);
                storage.store_ack(ack)?;
            }
            TransportMessage::Finalize(finalization) => {
                // All signers see final transaction
                info!(
                    "Transaction finalized: tx_id={}",
                    finalization.tx_id.to_hex()
                );
                storage.store_finalization(finalization)?;
            }
        }
    }

    Ok(())
}

async fn collect_and_finalize(
    config: Arc<Config>,
    transport: Arc<IrohTransport>,
    coordinator: Arc<Coordinator>,
    proposal: StoredProposal,
) -> Result<()> {
    // Wait for threshold signatures
    let timeout = Duration::from_secs(config.policy.session_timeout_seconds);
    let signatures = transport.collect_signatures(
        proposal.session_id,
        config.pskt.sig_op_count as usize,
        timeout,
    ).await?;

    if signatures.len() >= config.pskt.sig_op_count as usize {
        info!("Threshold reached, finalizing transaction...");

        // Finalize transaction
        let final_tx = coordinator.finalize_transaction(&proposal.pskt, signatures)?;

        // Broadcast to Kaspa network
        let tx_id = coordinator.broadcast_transaction(final_tx).await?;

        info!("Transaction broadcast: {}", tx_id.to_hex());

        // Publish finalization message
        transport.publish_finalization(proposal.session_id, tx_id).await?;
    } else {
        warn!("Threshold not reached: {}/{}", signatures.len(), config.pskt.sig_op_count);
    }

    Ok(())
}
```

**Integration in main():**

```rust
#[tokio::main]
async fn main() -> Result<()> {
    // ... existing config loading ...

    // Initialize both coordinator and signer (all nodes have both capabilities)
    let coordinator = Arc::new(Coordinator::new(
        config.clone(),
        transport.clone(),
        storage.clone(),
        node.clone(),
    ));

    let signer = Arc::new(Signer::new(
        config.clone(),
        transport.clone(),
        storage.clone(),
        node.clone(),
    ));

    // Start coordination loop (handles both roles)
    let loop_handle = tokio::spawn(coordination_loop(
        config.clone(),
        transport.clone(),
        storage.clone(),
        coordinator.clone(),
        signer.clone(),
    ));

    // Start JSON-RPC server for event ingestion
    // (any signer can receive external events and propose sessions)
    let rpc_handle = if config.rpc.enabled {
        Some(tokio::spawn(start_rpc_server(
            config.clone(),
            coordinator.clone(),
        )))
    } else {
        None
    };

    // Wait for shutdown signal
    info!("Service running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;

    // Cleanup
    loop_handle.abort();
    if let Some(handle) = rpc_handle {
        handle.abort();
    }

    Ok(())
}
```

**Configuration Addition:**

Add to `igra-core/src/config.rs`:

```rust
pub struct RpcConfig {
    pub addr: String,
    pub token: Option<String>,
    pub enabled: bool,  // NEW: allow disabling RPC for signers that only respond
}

pub struct PolicyConfig {
    // ... existing fields ...
    pub session_timeout_seconds: u64,  // NEW: timeout for collecting signatures
}
```

**Estimated Effort:** 4-6 days (200-300 lines)

**Files to Modify:**
- `igra-service/src/bin/kaspa-threshold-service.rs` (main loop logic)
- `igra-core/src/config.rs` (add RPC enabled flag, session timeout)
- `docs/service/README.md` (document unified architecture)

---

### 1.2 Policy Enforcement ⚠️ **MEDIUM PRIORITY**

**Status:** `GroupPolicy` model exists but NOT enforced in validation flows.

**Current State:**
Model defined in `igra-core/src/model.rs:182-209`:
```rust
pub struct GroupPolicy {
    pub allowed_destinations: Vec<String>,
    pub min_amount: u64,
    pub max_amount: u64,
    pub max_daily_volume: u64,
    pub require_memo: bool,
    pub metadata: PolicyMetadata,
}
```

**What's Needed:**

**File:** `igra-core/src/coordination/signer.rs`

Add policy enforcement in `validate_proposal()`:

```rust
impl Signer {
    pub async fn validate_proposal(
        &self,
        proposal: &StoredProposal,
        policy: &GroupPolicy,
    ) -> ThresholdResult<()> {
        // Existing validation...
        self.validate_hashes(proposal)?;

        // NEW: Policy enforcement
        self.enforce_policy(&proposal.signing_event, policy).await?;

        Ok(())
    }

    async fn enforce_policy(
        &self,
        event: &SigningEvent,
        policy: &GroupPolicy,
    ) -> ThresholdResult<()> {
        // Check destination allowlist
        if !policy.allowed_destinations.is_empty() {
            if !policy.allowed_destinations.contains(&event.destination_address) {
                return Err(ThresholdError::DestinationNotAllowed(
                    event.destination_address.clone()
                ));
            }
        }

        // Check amount limits
        if event.amount_sompi < policy.min_amount {
            return Err(ThresholdError::AmountTooLow {
                amount: event.amount_sompi,
                min: policy.min_amount,
            });
        }

        if event.amount_sompi > policy.max_amount {
            return Err(ThresholdError::AmountTooHigh {
                amount: event.amount_sompi,
                max: policy.max_amount,
            });
        }

        // Check velocity limit (daily volume)
        let today_start = self.get_day_start_timestamp();
        let daily_volume = self.storage.get_volume_since(today_start)?;

        if daily_volume + event.amount_sompi > policy.max_daily_volume {
            return Err(ThresholdError::VelocityLimitExceeded {
                current: daily_volume,
                limit: policy.max_daily_volume,
            });
        }

        // Check memo requirement
        if policy.require_memo && event.metadata.reason.is_none() {
            return Err(ThresholdError::MemoRequired);
        }

        Ok(())
    }

    fn get_day_start_timestamp(&self) -> u64 {
        // Get current day start in Unix nanos
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let nanos_per_day = 24 * 60 * 60 * 1_000_000_000u64;
        (now / nanos_per_day) * nanos_per_day
    }
}
```

**File:** `igra-core/src/storage/rocks.rs`

Add volume tracking:

```rust
impl RocksStorage {
    pub fn get_volume_since(&self, timestamp_nanos: u64) -> ThresholdResult<u64> {
        let mut total = 0u64;

        // Iterate over all finalized requests since timestamp
        let iter = self.db.iterator(rocksdb::IteratorMode::Start);

        for item in iter {
            let (key, value) = item.map_err(|e| ThresholdError::StorageError(e.to_string()))?;

            if key.starts_with(b"req:") {
                let req: SigningRequest = bincode::deserialize(&value)
                    .map_err(|e| ThresholdError::StorageError(e.to_string()))?;

                if req.timestamp_nanos >= timestamp_nanos
                    && req.decision == Some(RequestDecision::Finalized) {
                    total += req.signing_event.amount_sompi;
                }
            }
        }

        Ok(total)
    }
}
```

**Configuration Addition:**

Update `igra-core/src/config.rs` to parse policy from INI:

```ini
[policy]
allowed_destinations = kaspatest:addr1,kaspatest:addr2
min_amount = 1000000           # 0.01 KAS
max_amount = 100000000000      # 1000 KAS
max_daily_volume = 500000000000 # 5000 KAS per day
require_memo = true
```

**Estimated Effort:** 3-5 days (150-200 lines)

**Files to Modify:**
- `igra-core/src/coordination/signer.rs` (add enforcement)
- `igra-core/src/storage/rocks.rs` (add volume tracking)
- `igra-core/src/config.rs` (parse policy config)
- `igra-core/src/lib.rs` (add error variants)

---

### 1.3 Testing Infrastructure ❌ **HIGH PRIORITY**

**Status:** Only 3 test files, all ignored by default:
- `tests/iroh_transport.rs` (requires live peers)
- `tests/rpc_integration.rs` (requires live node)
- `tests/v1_service_integration.rs` (5KB test)

**What's Needed:**

Create comprehensive test suite:

```
igra-core/tests/
├── unit/
│   ├── pskt_building.rs          # PSKT construction determinism
│   ├── multisig_signing.rs       # Threshold signing correctness
│   ├── hashes.rs                 # Hash computation tests
│   ├── policy_enforcement.rs     # Policy validation
│   ├── storage.rs                # RocksDB CRUD operations
│   └── event_validation.rs       # Event source validation
├── integration/
│   ├── full_signing_flow.rs      # Complete propose-sign-finalize flow
│   ├── event_ingestion.rs        # Event pipeline end-to-end
│   └── replay_protection.rs      # Duplicate event handling
└── mocks/
    ├── mock_node.rs              # Mock Kaspa RPC client
    ├── mock_transport.rs         # Mock Iroh transport
    └── test_utils.rs             # Shared test utilities
```

**Example Test File:** `igra-core/tests/unit/pskt_building.rs`

```rust
use igra_core::pskt::builder::PsktBuilder;
use igra_core::model::SigningEvent;
use kaspa_consensus_core::tx::Transaction;

#[test]
fn test_deterministic_pskt_construction() {
    // Create identical signing events
    let event1 = create_test_event("kaspatest:qz...", 50_000_000_000);
    let event2 = create_test_event("kaspatest:qz...", 50_000_000_000);

    // Create identical UTXO sets
    let utxos = create_test_utxos(100_000_000_000);

    // Build PSKTs independently
    let pskt1 = PsktBuilder::new(event1, utxos.clone()).build().unwrap();
    let pskt2 = PsktBuilder::new(event2, utxos.clone()).build().unwrap();

    // Verify identical transactions
    assert_eq!(pskt1.unsigned_tx, pskt2.unsigned_tx);
    assert_eq!(pskt1.inputs, pskt2.inputs);

    // Verify validation hashes match
    assert_eq!(
        pskt1.compute_validation_hash(),
        pskt2.compute_validation_hash()
    );
}

#[test]
fn test_pskt_output_amounts() {
    let event = create_test_event("kaspatest:qz...", 50_000_000_000);
    let utxos = create_test_utxos(100_000_000_000);

    let pskt = PsktBuilder::new(event, utxos).build().unwrap();

    // Verify output amounts (RecipientPays mode)
    assert_eq!(pskt.unsigned_tx.outputs.len(), 2);

    // Output[0]: recipient (amount - fee)
    let recipient_output = &pskt.unsigned_tx.outputs[0];
    assert!(recipient_output.value < 50_000_000_000); // Less due to fee

    // Output[1]: change back to signers
    let change_output = &pskt.unsigned_tx.outputs[1];
    assert!(change_output.value > 49_000_000_000); // Remaining funds

    // Total outputs + fee should equal inputs
    let total_out = recipient_output.value + change_output.value;
    assert_eq!(total_out + estimated_fee, 100_000_000_000);
}

fn create_test_event(dest: &str, amount: u64) -> SigningEvent {
    // Helper to create consistent test events
    todo!()
}

fn create_test_utxos(total: u64) -> Vec<UtxoEntry> {
    // Helper to create consistent UTXO sets
    todo!()
}
```

**Example Integration Test:** `igra-core/tests/integration/full_signing_flow.rs`

```rust
use igra_core::coordination::{Coordinator, Signer};
use igra_core::transport::mock::MockTransport;

#[tokio::test]
async fn test_full_signing_flow() {
    // Setup
    let transport = Arc::new(MockTransport::new());
    let storage = Arc::new(create_test_storage());

    let coordinator = Coordinator::new(
        create_test_config(),
        transport.clone(),
        storage.clone(),
    );

    let signer1 = Signer::new(create_test_signer_config(1), transport.clone(), storage.clone());
    let signer2 = Signer::new(create_test_signer_config(2), transport.clone(), storage.clone());
    let signer3 = Signer::new(create_test_signer_config(3), transport.clone(), storage.clone());

    // Coordinator proposes signing session
    let event = create_test_event("kaspatest:qz...", 50_000_000_000);
    let session_id = coordinator.propose_from_event(event).await.unwrap();

    // Signers receive and validate
    let proposal = transport.get_proposal(session_id).unwrap();

    // Signer 1 signs
    let sig1 = signer1.sign_pskt(&proposal.pskt).await.unwrap();
    transport.publish_signature(session_id, sig1).await.unwrap();

    // Signer 2 signs
    let sig2 = signer2.sign_pskt(&proposal.pskt).await.unwrap();
    transport.publish_signature(session_id, sig2).await.unwrap();

    // Threshold reached (2-of-3)
    let signatures = transport.collect_signatures(session_id, 2).await.unwrap();

    // Coordinator finalizes
    let final_tx = coordinator.finalize_transaction(&proposal.pskt, signatures).unwrap();

    // Verify final transaction
    assert!(final_tx.inputs.iter().all(|i| !i.signature_script.is_empty()));

    // Optionally broadcast (mock node would accept)
    let tx_id = coordinator.broadcast_transaction(final_tx).await.unwrap();
    assert!(!tx_id.is_zero());
}
```

**Mock Transport:** `igra-core/src/transport/mock.rs`

```rust
pub struct MockTransport {
    proposals: Arc<Mutex<HashMap<Hash, StoredProposal>>>,
    signatures: Arc<Mutex<HashMap<Hash, Vec<PartialSig>>>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self {
            proposals: Arc::new(Mutex::new(HashMap::new())),
            signatures: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn get_proposal(&self, session_id: Hash) -> Option<StoredProposal> {
        self.proposals.lock().unwrap().get(&session_id).cloned()
    }

    pub async fn collect_signatures(&self, session_id: Hash, threshold: usize) -> Result<Vec<PartialSig>> {
        loop {
            let sigs = self.signatures.lock().unwrap();
            if let Some(sig_list) = sigs.get(&session_id) {
                if sig_list.len() >= threshold {
                    return Ok(sig_list.clone());
                }
            }
            drop(sigs);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

#[async_trait]
impl Transport for MockTransport {
    // Implement Transport trait methods
}
```

**Estimated Effort:** 8-12 days (800-1200 lines)

**Files to Create:**
- `igra-core/tests/unit/*.rs` (6 files)
- `igra-core/tests/integration/*.rs` (3 files)
- `igra-core/src/transport/mock.rs` (mock implementation)
- `igra-core/tests/mocks/*.rs` (test utilities)

---

## 2. Refactoring Needs

### 2.1 Error Types ⚠️ **MEDIUM PRIORITY**

**Status:** `ThresholdError` too generic, makes debugging difficult.

**Current State:** `igra-core/src/lib.rs`
```rust
pub enum ThresholdError {
    Unimplemented(String),
    Message(String),
}
```

**What's Needed:**

Replace with structured error types:

```rust
#[derive(Debug, Clone, thiserror::Error)]
pub enum ThresholdError {
    // Event errors
    #[error("Event already processed: {0}")]
    EventReplayed(String),

    #[error("Event signature verification failed")]
    EventSignatureInvalid,

    #[error("Event expired at {expired_at}, current time {current_time}")]
    EventExpired { expired_at: u64, current_time: u64 },

    // Policy errors
    #[error("Destination not in allowlist: {0}")]
    DestinationNotAllowed(String),

    #[error("Amount {amount} below minimum {min}")]
    AmountTooLow { amount: u64, min: u64 },

    #[error("Amount {amount} exceeds maximum {max}")]
    AmountTooHigh { amount: u64, max: u64 },

    #[error("Daily volume limit exceeded: current={current}, limit={limit}")]
    VelocityLimitExceeded { current: u64, limit: u64 },

    #[error("Memo required for this transaction")]
    MemoRequired,

    // PSKT errors
    #[error("PSKT validation failed: {0}")]
    PsktValidationFailed(String),

    #[error("PSKT mismatch: expected {expected}, got {actual}")]
    PsktMismatch { expected: String, actual: String },

    #[error("Insufficient UTXOs to cover amount + fee")]
    InsufficientUTXOs,

    #[error("Transaction hash mismatch")]
    TransactionMismatch,

    // Signing errors
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Threshold not met: required {required}, received {received}")]
    ThresholdNotMet { required: u16, received: u16 },

    #[error("Invalid signature for input {input_index}")]
    InvalidSignature { input_index: usize },

    // Transport errors
    #[error("Message already seen (replay protection)")]
    MessageReplayed,

    #[error("Envelope signature verification failed")]
    SignatureVerificationFailed,

    #[error("Invalid peer identity")]
    InvalidPeerIdentity,

    // Storage errors
    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    // Configuration errors
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    // Node RPC errors
    #[error("Node RPC error: {0}")]
    NodeRpcError(String),

    #[error("Node not synced")]
    NodeNotSynced,

    // Unimplemented features
    #[error("Feature not implemented: {0}")]
    Unimplemented(String),
}
```

**Add `thiserror` Dependency:**

Update `igra-core/Cargo.toml`:
```toml
[dependencies]
thiserror = "2.0"
```

**Refactor Call Sites:**

Update all `Err(ThresholdError::Message(...))` to use specific variants.

**Estimated Effort:** 3-4 days (100-150 lines refactor across codebase)

**Files to Modify:**
- `igra-core/src/lib.rs` (error enum)
- `igra-core/src/**/*.rs` (update error usage)
- `igra-core/Cargo.toml` (add thiserror)

---

### 2.2 Group ID Derivation ⚠️ **MEDIUM PRIORITY**

**Status:** Spec defines deterministic group_id computation (§5.1.1), but no implementation exists.

**What's Needed:**

**File:** `igra-core/src/group_id.rs` (new file)

```rust
use blake3::Hasher as Blake3Hasher;
use crate::model::{GroupConfig, Hash};

/// Compute deterministic group ID from configuration
///
/// Per spec §5.1.1, group_id = BLAKE3(threshold || pubkeys || protocol || network || metadata)
pub fn compute_group_id(config: &GroupConfig) -> Hash {
    let mut hasher = Blake3Hasher::new();

    // Threshold (m-of-n)
    hasher.update(&config.threshold_m.to_le_bytes());
    hasher.update(&config.threshold_n.to_le_bytes());

    // Sorted public keys (deterministic ordering)
    let mut pubkeys = config.pubkeys.clone();
    pubkeys.sort();
    for pk in &pubkeys {
        hasher.update(pk.serialize_compressed());
    }

    // Protocol type
    let protocol_bytes = b"threshold"; // V1 only supports threshold multisig
    hasher.update(protocol_bytes);

    // Network ID
    hasher.update(&[config.network_id]);

    // Fee payment mode (V1: part of group identity)
    let fee_mode_bytes = match config.fee_payment_mode {
        FeePaymentMode::RecipientPays => b"recipient_pays",
        FeePaymentMode::SignersPay => b"signers_pay",
        FeePaymentMode::Split { recipient_portion } => {
            hasher.update(b"split");
            hasher.update(&recipient_portion.to_le_bytes());
            b""
        }
    };
    if !fee_mode_bytes.is_empty() {
        hasher.update(fee_mode_bytes);
    }

    // Finality threshold (confirmations required)
    hasher.update(&config.finality_blue_score_threshold.to_le_bytes());

    // Static fee rate (V1: immutable)
    hasher.update(&config.fee_rate_sompi_per_gram.to_le_bytes());

    // Dust threshold
    hasher.update(&config.dust_threshold_sompi.to_le_bytes());

    // Session timeout
    hasher.update(&config.session_timeout_seconds.to_le_bytes());

    // Metadata (canonical encoding)
    if let Some(ref metadata) = config.metadata {
        hasher.update(metadata.creation_timestamp.to_le_bytes());
        if let Some(ref name) = metadata.group_name {
            hasher.update(name.as_bytes());
        }
        hasher.update(&metadata.policy_version.to_le_bytes());
    }

    // Finalize hash
    let hash_bytes = hasher.finalize();
    Hash::from_bytes(*hash_bytes.as_bytes())
}

/// Verify that a group_id matches the expected configuration
pub fn verify_group_id(config: &GroupConfig, claimed_group_id: &Hash) -> bool {
    let computed = compute_group_id(config);
    computed == *claimed_group_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_group_id() {
        let config1 = create_test_config();
        let config2 = create_test_config(); // Identical

        let id1 = compute_group_id(&config1);
        let id2 = compute_group_id(&config2);

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_group_id_uniqueness() {
        let mut config1 = create_test_config();
        let mut config2 = create_test_config();

        // Change threshold
        config2.threshold_m = 3;

        let id1 = compute_group_id(&config1);
        let id2 = compute_group_id(&config2);

        assert_ne!(id1, id2);
    }
}
```

**Integration:**

Update `igra-service/src/bin/kaspa-threshold-service.rs` to verify group_id on startup:

```rust
// After loading config
let computed_group_id = compute_group_id(&config.group);
let configured_group_id = Hash::from_hex(&config.iroh.group_id)?;

if computed_group_id != configured_group_id {
    warn!(
        "Group ID mismatch! Computed: {}, Configured: {}",
        computed_group_id.to_hex(),
        configured_group_id.to_hex()
    );
    warn!("This may indicate configuration drift. Proceed with caution.");
}
```

**Estimated Effort:** 2-3 days (100-150 lines)

**Files to Create:**
- `igra-core/src/group_id.rs` (new module)

**Files to Modify:**
- `igra-core/src/lib.rs` (export module)
- `igra-service/src/bin/kaspa-threshold-service.rs` (verification on startup)

---

### 2.3 Fee Payment Modes ⚠️ **LOW-MEDIUM PRIORITY**

**Status:** Only `RecipientPays` implemented. Spec defines three modes (§6B.2).

**Current State:** PSKT builder implicitly uses `RecipientPays` (fee deducted from recipient amount).

**What's Needed:**

**File:** `igra-core/src/model.rs`

Add `FeePaymentMode` to `EventMetadata`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetadata {
    pub reason: Option<String>,
    pub fee_payment_mode: FeePaymentMode,  // NEW
    // ... existing fields
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeePaymentMode {
    /// Recipient pays: fee deducted from amount
    RecipientPays,

    /// Signers pay: fee paid from change output
    SignersPay,

    /// Split fee: recipient pays portion, signers pay remainder
    Split {
        /// Portion paid by recipient (0.0 to 1.0)
        recipient_portion: f64,
    },
}

impl Default for FeePaymentMode {
    fn default() -> Self {
        FeePaymentMode::RecipientPays
    }
}
```

**File:** `igra-core/src/pskt/builder.rs`

Update PSKT construction to handle all modes:

```rust
impl PsktBuilder {
    fn compute_output_amounts(&self, fee: u64) -> ThresholdResult<(u64, u64)> {
        let total_input = self.selected_utxos.iter().sum::<u64>();

        match self.event.metadata.fee_payment_mode {
            FeePaymentMode::RecipientPays => {
                // Recipient receives: amount - fee
                let recipient = self.event.amount_sompi
                    .checked_sub(fee)
                    .ok_or(ThresholdError::InsufficientAmount)?;

                // Change: total_input - amount (full refund to signers)
                let change = total_input
                    .checked_sub(self.event.amount_sompi)
                    .ok_or(ThresholdError::InsufficientFunds)?;

                Ok((recipient, change))
            }

            FeePaymentMode::SignersPay => {
                // Recipient receives: full amount
                let recipient = self.event.amount_sompi;

                // Change: total_input - amount - fee
                let change = total_input
                    .checked_sub(self.event.amount_sompi + fee)
                    .ok_or(ThresholdError::InsufficientFunds)?;

                Ok((recipient, change))
            }

            FeePaymentMode::Split { recipient_portion } => {
                // Validate portion
                if recipient_portion < 0.0 || recipient_portion > 1.0 {
                    return Err(ThresholdError::ConfigError(
                        "recipient_portion must be 0.0 to 1.0".to_string()
                    ));
                }

                // Split fee proportionally
                let recipient_fee = (fee as f64 * recipient_portion) as u64;
                let signer_fee = fee - recipient_fee;

                let recipient = self.event.amount_sompi
                    .checked_sub(recipient_fee)
                    .ok_or(ThresholdError::InsufficientAmount)?;

                let change = total_input
                    .checked_sub(self.event.amount_sompi + signer_fee)
                    .ok_or(ThresholdError::InsufficientFunds)?;

                Ok((recipient, change))
            }
        }
    }
}
```

**Configuration:**

Add to INI config:

```ini
[pskt]
fee_payment_mode = recipient_pays  # or "signers_pay" or "split:0.5"
```

**Estimated Effort:** 2-3 days (80-120 lines)

**Files to Modify:**
- `igra-core/src/model.rs` (add FeePaymentMode enum)
- `igra-core/src/pskt/builder.rs` (update output calculation)
- `igra-core/src/config.rs` (parse fee mode from INI)

---

## 3. Nice-to-Have Improvements

### 3.1 Transaction Monitoring ⚠️ **LOW PRIORITY**

**Status:** Proposer node can submit TX but doesn't monitor confirmation.

**What's Needed:**

**File:** `igra-core/src/coordination/monitoring.rs` (new file)

```rust
use std::time::Duration;
use tokio::time::sleep;

pub struct TransactionMonitor {
    node: Arc<dyn NodeRpc>,
    min_confirmations: u64,
    poll_interval: Duration,
}

impl TransactionMonitor {
    pub fn new(node: Arc<dyn NodeRpc>, min_confirmations: u64) -> Self {
        Self {
            node,
            min_confirmations,
            poll_interval: Duration::from_secs(5),
        }
    }

    /// Monitor transaction until it reaches required confirmations
    pub async fn monitor_until_confirmed(
        &self,
        tx_id: Hash,
    ) -> ThresholdResult<TransactionStatus> {
        info!("Monitoring transaction: {}", tx_id);

        loop {
            // Query transaction status
            let tx = self.node.get_transaction(tx_id).await?;

            if tx.is_accepted {
                // Get current blue score
                let current_blue_score = self.node.get_blue_score().await?;
                let confirmations = current_blue_score.saturating_sub(tx.accepted_blue_score);

                info!(
                    "Transaction {} confirmations: {} / {}",
                    tx_id, confirmations, self.min_confirmations
                );

                if confirmations >= self.min_confirmations {
                    info!("Transaction {} fully confirmed", tx_id);
                    return Ok(TransactionStatus::Confirmed {
                        accepted_blue_score: tx.accepted_blue_score,
                        confirmations,
                    });
                }
            } else if tx.is_rejected {
                warn!("Transaction {} rejected by mempool", tx_id);
                return Ok(TransactionStatus::Rejected);
            }

            sleep(self.poll_interval).await;
        }
    }
}

#[derive(Debug, Clone)]
pub enum TransactionStatus {
    Pending,
    Accepted { blue_score: u64 },
    Confirmed { accepted_blue_score: u64, confirmations: u64 },
    Rejected,
}
```

**Integration:**

Update coordinator to optionally monitor after broadcast:

```rust
// In coordinator.rs
pub async fn broadcast_and_monitor(
    &self,
    tx: Transaction,
    wait_for_confirmation: bool,
) -> ThresholdResult<(Hash, TransactionStatus)> {
    let tx_id = self.broadcast_transaction(tx).await?;

    if wait_for_confirmation {
        let monitor = TransactionMonitor::new(
            self.node.clone(),
            self.config.finality_blue_score_threshold,
        );
        let status = monitor.monitor_until_confirmed(tx_id).await?;
        Ok((tx_id, status))
    } else {
        Ok((tx_id, TransactionStatus::Pending))
    }
}
```

**Estimated Effort:** 2-3 days (80-120 lines)

**Files to Create:**
- `igra-core/src/coordination/monitoring.rs` (new module)

**Files to Modify:**
- `igra-core/src/coordination/coordinator.rs` (add monitoring option)

---

### 3.2 Configuration Validation ⚠️ **LOW PRIORITY**

**Status:** Config loaded from INI but not validated for consistency.

**What's Needed:**

**File:** `igra-core/src/config.rs`

Add validation method:

```rust
impl Config {
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate threshold
        if self.pskt.sig_op_count == 0 {
            errors.push("sig_op_count must be > 0".to_string());
        }

        // Validate addresses
        for addr in &self.pskt.source_addresses {
            if let Err(e) = Address::try_from(addr.as_str()) {
                errors.push(format!("Invalid source address {}: {}", addr, e));
            }
        }

        // Validate network consistency
        let network = self.service.network();
        for addr in &self.pskt.source_addresses {
            if let Ok(parsed) = Address::try_from(addr.as_str()) {
                if parsed.prefix != network.prefix() {
                    errors.push(format!(
                        "Address {} network mismatch: expected {}, got {}",
                        addr, network.prefix(), parsed.prefix
                    ));
                }
            }
        }

        // Validate policy limits
        if let Some(ref policy) = self.policy {
            if policy.min_amount > policy.max_amount {
                errors.push("min_amount cannot exceed max_amount".to_string());
            }

            if policy.max_amount > policy.max_daily_volume {
                errors.push("max_amount cannot exceed max_daily_volume".to_string());
            }
        }

        // Validate Iroh config
        if self.iroh.group_id.len() != 64 {
            errors.push("group_id must be 32 bytes (64 hex chars)".to_string());
        }

        if self.iroh.verifier_keys.is_empty() {
            errors.push("verifier_keys cannot be empty".to_string());
        }

        // Validate RPC config
        if self.rpc.enabled && self.rpc.addr.is_empty() {
            errors.push("RPC enabled but no address configured".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}
```

**Call in main:**

```rust
// In kaspa-threshold-service.rs main()
if let Err(errors) = config.validate() {
    error!("Configuration validation failed:");
    for err in errors {
        error!("  - {}", err);
    }
    std::process::exit(1);
}
```

**Estimated Effort:** 1-2 days (50-80 lines)

**Files to Modify:**
- `igra-core/src/config.rs` (add validation)
- `igra-service/src/bin/kaspa-threshold-service.rs` (call validation)

---

### 3.3 LayerZero Integration ⚠️ **LOW PRIORITY**

**Status:** `EventSource::LayerZero` variant exists but no validation logic.

**What's Needed:**

**File:** `igra-core/src/validation/layerzero.rs` (new file)

```rust
use secp256k1::{Secp256k1, Message, ecdsa::Signature};
use crate::model::{SigningEvent, EventSource};

pub struct LayerZeroValidator {
    endpoint_pubkeys: Vec<secp256k1::PublicKey>,
}

impl LayerZeroValidator {
    pub fn new(endpoint_pubkeys: Vec<secp256k1::PublicKey>) -> Self {
        Self { endpoint_pubkeys }
    }

    pub fn verify_event(&self, event: &SigningEvent) -> ThresholdResult<()> {
        // Extract LayerZero-specific fields
        let (chain_id, endpoint, nonce) = match &event.event_source {
            EventSource::LayerZero { chain_id, endpoint, nonce } => {
                (chain_id, endpoint, nonce)
            }
            _ => return Err(ThresholdError::Message("Not a LayerZero event".to_string())),
        };

        // Compute message hash (LayerZero-specific format)
        let message_hash = compute_layerzero_message_hash(
            *chain_id,
            endpoint,
            *nonce,
            &event.destination_address,
            event.amount_sompi,
        );

        // Verify signature against any configured endpoint pubkey
        let secp = Secp256k1::verification_only();
        let message = Message::from_slice(&message_hash)?;
        let signature = Signature::from_compact(&event.signature_hex)?;

        for pubkey in &self.endpoint_pubkeys {
            if secp.verify_ecdsa(&message, &signature, pubkey).is_ok() {
                return Ok(()); // Valid signature found
            }
        }

        Err(ThresholdError::EventSignatureInvalid)
    }
}

fn compute_layerzero_message_hash(
    chain_id: u16,
    endpoint: &str,
    nonce: u64,
    destination: &str,
    amount: u64,
) -> [u8; 32] {
    // LayerZero-specific message format
    // TODO: Implement according to LayerZero spec
    todo!()
}
```

**Configuration:**

Add to INI:

```ini
[layerzero]
endpoint_pubkeys = 0x...,0x...
```

**Estimated Effort:** 1-2 days (50-80 lines)

**Files to Create:**
- `igra-core/src/validation/layerzero.rs` (new module)

**Files to Modify:**
- `igra-core/src/config.rs` (parse LayerZero config)
- `igra-service/src/service/json_rpc.rs` (call validator)

---

## 4. Documentation Needs

### 4.1 Deployment Guide ⚠️ **MEDIUM PRIORITY**

**File:** `docs/service/DEPLOYMENT.md` (new file)

Create comprehensive deployment guide covering:
- Prerequisites (Kaspa node with --utxoindex)
- Group setup (generating keys, agreeing on group_id)
- Node deployment (all nodes run identical software)
- Configuring which nodes can propose (RPC enabled vs disabled)
- Monitoring and health checks
- Troubleshooting common issues

**Key Architecture Points to Document:**
- Every node is a signer AND potential coordinator
- Coordinator role is ephemeral (per-session)
- Any node with `rpc.enabled = true` can receive external events and propose sessions
- All nodes respond to proposals from any other node
- No separate "coordinator" vs "signer" binaries

**Estimated Effort:** 2-3 days

---

### 4.2 Integration Guide ⚠️ **LOW PRIORITY**

**File:** `docs/service/INTEGRATION.md` (new file)

Create guide for integrators covering:
- JSON-RPC API usage with examples
- Hyperlane event format
- LayerZero event format
- Error handling
- Retry logic
- Security considerations

**Estimated Effort:** 1-2 days

---

### 4.3 Security Documentation ⚠️ **MEDIUM PRIORITY**

**File:** `SECURITY.md` (new file)

Document:
- Key separation (Kaspa signing vs Iroh transport vs Hyperlane validation)
- Replay protection mechanisms
- Policy enforcement
- Audit trail format
- Threat model
- Best practices for operators

**Estimated Effort:** 2-3 days

---

## 5. Priority Matrix

### 🔴 **Critical (Blocks V1 Production)**

| Priority | Task | Effort | Impact |
|----------|------|--------|--------|
| 1 | Automated Signer Loop | 4-6 days | **HIGH** - Required for daemon mode |
| 2 | Testing Infrastructure | 8-12 days | **HIGH** - Confidence for production |
| 3 | Deployment Guide | 2-3 days | **HIGH** - Operators need this |

**Subtotal:** 14-21 days

---

### 🟡 **High Priority (V1 Quality)**

| Priority | Task | Effort | Impact |
|----------|------|--------|--------|
| 4 | Policy Enforcement | 3-5 days | **MEDIUM** - Security feature |
| 5 | Error Type Refactor | 3-4 days | **MEDIUM** - Better debugging |
| 6 | Group ID Derivation | 2-3 days | **MEDIUM** - Spec compliance |
| 7 | Security Documentation | 2-3 days | **MEDIUM** - Audit requirement |

**Subtotal:** 10-15 days

---

### 🟢 **Medium Priority (V1 Polish)**

| Priority | Task | Effort | Impact |
|----------|------|--------|--------|
| 8 | Fee Payment Modes | 2-3 days | **LOW** - Flexibility feature |
| 9 | Transaction Monitoring | 2-3 days | **LOW** - Operational visibility |
| 10 | Config Validation | 1-2 days | **LOW** - Prevent misconfig |
| 11 | Integration Guide | 1-2 days | **LOW** - Developer UX |

**Subtotal:** 6-10 days

---

### ⚪ **Low Priority (Nice-to-Have)**

| Priority | Task | Effort | Impact |
|----------|------|--------|--------|
| 12 | LayerZero Integration | 1-2 days | **LOW** - Additional event source |

**Subtotal:** 1-2 days

---

## 6. Total Effort Summary

### Minimum Viable V1 (Critical Only)
**Time:** 14-21 days (3-4 weeks)
- Automated signer loop
- Testing infrastructure
- Deployment guide

### Production-Quality V1 (Critical + High)
**Time:** 24-36 days (5-7 weeks)
- Everything in Critical
- Policy enforcement
- Error handling improvements
- Group ID derivation
- Security documentation

### Polished V1 (Critical + High + Medium)
**Time:** 30-46 days (6-9 weeks)
- Everything in Production-Quality
- Fee payment modes
- Transaction monitoring
- Configuration validation
- Integration guide

---

## 7. Recommended Implementation Sequence

### Week 1-2: Core Infrastructure
1. ✅ Automated Signer Loop (4-6 days)
2. ✅ Error Type Refactor (3-4 days)

### Week 3-4: Testing & Validation
3. ✅ Testing Infrastructure - Unit Tests (4-6 days)
4. ✅ Testing Infrastructure - Integration Tests (4-6 days)

### Week 5-6: Production Features
5. ✅ Policy Enforcement (3-5 days)
6. ✅ Group ID Derivation (2-3 days)

### Week 7: Documentation & Polish
7. ✅ Deployment Guide (2-3 days)
8. ✅ Security Documentation (2-3 days)
9. ✅ Config Validation (1-2 days)

### Week 8-9: Optional Enhancements
10. ⚪ Fee Payment Modes (2-3 days)
11. ⚪ Transaction Monitoring (2-3 days)
12. ⚪ Integration Guide (1-2 days)

---

## 8. Success Criteria for V1 Production

### Code Quality
- [ ] All critical features implemented
- [ ] Unit test coverage > 70%
- [ ] Integration tests for happy path + error cases
- [ ] No `unwrap()` or `expect()` in production code paths
- [ ] All `TODO` comments resolved or documented

### Functionality
- [ ] Any node can propose signing sessions (ephemeral coordinator role)
- [ ] Signers automatically respond to proposals
- [ ] Threshold signing works with 2-of-3, 3-of-5, etc.
- [ ] Policy enforcement prevents unauthorized transactions
- [ ] Replay protection prevents duplicate events
- [ ] Audit trail complete and exportable

### Operations
- [ ] Deployment guide complete with examples
- [ ] Security documentation reviewed
- [ ] Configuration validation prevents bad setups
- [ ] Logging sufficient for debugging
- [ ] Metrics exposed for monitoring

### Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual end-to-end test on testnet
- [ ] Load testing with 100+ events
- [ ] Chaos testing (coordinator failure, network partition)

---

## 9. Known Limitations (V1)

These are **intentional** limitations for V1, deferred to future versions:

1. **Multi-recipient transactions** - V2 feature (§6B.3)
2. **Dynamic fee estimation** - V2 feature
3. **Member rotation** - V4 feature
4. **Protocol migration** - V4 feature (Multisig → FROST)
5. **Human approval workflows** - V4 feature
6. **Hardware wallet integration** - V4 feature
7. **Subnetwork support** - V4 feature

---

## 10. Post-V1 Roadmap (Future Versions)

### V1.1 (Minor Enhancements - 2-3 weeks)
- LayerZero integration
- Enhanced monitoring dashboard
- Performance optimizations
- Additional policy rules

### V2 (Multi-Recipient - 1-2 months)
- Multi-recipient transactions (batch payments)
- Dynamic fee estimation
- Split fee payment modes
- Enhanced policy engine

### V3 (Advanced Cryptography - 2-3 months)
- FROST MPC backend integration
- MuSig2 backend integration
- Protocol migration tooling

### V4 (Enterprise Features - 3-4 months)
- Member rotation without fund movement
- Human approval workflows
- Hardware wallet integration
- Governance module

---

## Appendix A: File Checklist

### Files to Create
- [ ] `igra-core/src/group_id.rs`
- [ ] `igra-core/src/coordination/monitoring.rs`
- [ ] `igra-core/src/transport/mock.rs`
- [ ] `igra-core/src/validation/layerzero.rs`
- [ ] `igra-core/tests/unit/pskt_building.rs`
- [ ] `igra-core/tests/unit/multisig_signing.rs`
- [ ] `igra-core/tests/unit/hashes.rs`
- [ ] `igra-core/tests/unit/policy_enforcement.rs`
- [ ] `igra-core/tests/unit/storage.rs`
- [ ] `igra-core/tests/unit/event_validation.rs`
- [ ] `igra-core/tests/integration/full_signing_flow.rs`
- [ ] `igra-core/tests/integration/event_ingestion.rs`
- [ ] `igra-core/tests/integration/replay_protection.rs`
- [ ] `igra-core/tests/mocks/mock_node.rs`
- [ ] `igra-core/tests/mocks/test_utils.rs`
- [ ] `docs/service/DEPLOYMENT.md`
- [ ] `docs/service/INTEGRATION.md`
- [ ] `SECURITY.md`

### Files to Modify
- [ ] `igra-service/src/bin/kaspa-threshold-service.rs` (signer loop)
- [ ] `igra-core/src/coordination/signer.rs` (policy enforcement)
- [ ] `igra-core/src/storage/rocks.rs` (volume tracking)
- [ ] `igra-core/src/config.rs` (new config fields)
- [ ] `igra-core/src/lib.rs` (error refactor)
- [ ] `igra-core/src/model.rs` (FeePaymentMode)
- [ ] `igra-core/src/pskt/builder.rs` (fee modes)
- [ ] `igra-core/Cargo.toml` (add thiserror)

---

## Appendix B: Testing Strategy

### Unit Tests (Target: 70% coverage)
- PSKT deterministic construction
- Hash computation correctness
- Multisig signature generation/verification
- Policy validation logic
- Storage CRUD operations
- Event validation

### Integration Tests
- Full propose-validate-sign-finalize flow (2-of-3 threshold)
- Event ingestion pipeline
- Replay protection enforcement
- Network partition handling
- Proposer node failure (another node takes over)

### Manual Testing Scenarios
1. **Happy Path:** 3 signers, 2-of-3 threshold, successful transaction
2. **Policy Rejection:** Signer rejects transaction outside allowlist
3. **Insufficient Threshold:** Only 1-of-3 signers respond, session times out
4. **Replay Attack:** Submit same event twice, verify rejection
5. **Proposer Failure:** Proposer node crashes mid-session, verify timeout and retry with different proposer
6. **Network Partition:** Signers temporarily disconnected, verify recovery

### Load Testing
- 100+ events per hour
- Multiple concurrent sessions
- Memory/CPU profiling

---

## Appendix C: Configuration Examples (Production)

### Example 1: Node that can propose AND respond (Bridge Operator Node)

```ini
# Node with RPC enabled - can receive external events and propose sessions
[service]
node_rpc_url = grpc://kaspa-node.internal:16110
data_dir = /var/lib/igra

[pskt]
source_addresses = kaspa:qz1a2b3c...,kaspa:qz4d5e6f...
redeem_script_hex = 522102...2103...52ae
sig_op_count = 2
fee_payment_mode = recipient_pays

[policy]
allowed_destinations = kaspa:qr...,kaspa:qr...
min_amount = 1000000
max_amount = 100000000000
max_daily_volume = 500000000000
require_memo = true
session_timeout_seconds = 120

[runtime]
test_mode = false

[signing]
backend = threshold

[rpc]
enabled = true              # Enable RPC to receive external events
addr = 0.0.0.0:8088
token = <secure-token>

[iroh]
peer_id = bridge-operator-1
group_id = 0101010101010101010101010101010101010101010101010101010101010101
verifier_keys = bridge-operator-1:0x...,signer-2:0x...,signer-3:0x...
network_id = 0
bootstrap = base32-endpoint-id-2,base32-endpoint-id-3
bind_port = 11204

[hyperlane]
validators = 0x...,0x...
events_dir = /var/lib/igra/hyperlane-events  # Optional: local file watcher

[layerzero]
endpoint_pubkeys = 0x...,0x...
```

### Example 2: Node that only responds (Pure Signer Node)

```ini
# Node with RPC disabled - only responds to proposals from other nodes
[service]
node_rpc_url = grpc://kaspa-node.internal:16110
data_dir = /var/lib/igra

[pskt]
source_addresses = kaspa:qz1a2b3c...,kaspa:qz4d5e6f...
redeem_script_hex = 522102...2103...52ae
sig_op_count = 2
fee_payment_mode = recipient_pays

[policy]
allowed_destinations = kaspa:qr...,kaspa:qr...
min_amount = 1000000
max_amount = 100000000000
max_daily_volume = 500000000000
require_memo = true
session_timeout_seconds = 120

[runtime]
test_mode = false

[signing]
backend = threshold

[rpc]
enabled = false             # Disable RPC - this node only responds to peers
addr = 127.0.0.1:8088       # Still need addr for potential future use
token = <secure-token>

[iroh]
peer_id = signer-2
group_id = 0101010101010101010101010101010101010101010101010101010101010101
verifier_keys = bridge-operator-1:0x...,signer-2:0x...,signer-3:0x...
network_id = 0
bootstrap = base32-endpoint-id-1,base32-endpoint-id-3
bind_port = 11205           # Different port from other nodes

[hyperlane]
validators = 0x...,0x...

[layerzero]
endpoint_pubkeys = 0x...,0x...
```

### Deployment Pattern: 3-of-5 Threshold Group

**Typical Setup:**
- **2 nodes with RPC enabled** (can propose) - Bridge operators
- **3 nodes with RPC disabled** (only respond) - Pure signers
- Threshold: any 3 signatures required

**Benefits:**
- Multiple nodes can initiate signing sessions (redundancy)
- Pure signers focus on validation and signing
- Event processing load distributed across proposal nodes

---

**END OF TODO-dev.md**
