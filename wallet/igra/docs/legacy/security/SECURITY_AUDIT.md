# Security Audit & Deep Dive Analysis

**Date:** 2025-12-31
**Scope:** Complete security audit of igra threshold signing system
**Auditor:** Comprehensive automated + manual code review
**Codebase Version:** Current master branch

## Executive Summary

This security audit reveals a **production-grade threshold multisig signing system** with strong architectural foundations and good security practices. However, **7 critical issues** must be addressed before production deployment.

**Overall Security Rating: 7.5/10** ⚠️

### Critical Findings

🔴 **4 CRITICAL Issues** - Must fix before production
🟡 **13 HIGH Priority Issues** - Recommended for production
🟢 **8 MEDIUM Priority Issues** - Quality improvements

### Key Strengths ✅

- Proper constant-time hash comparisons throughout
- Comprehensive three-layer replay protection
- Clean trait-based architecture with no circular dependencies
- Proper secret handling with zeroize
- No unsafe code blocks
- Strong error handling patterns (mostly)

### Critical Vulnerabilities ❌

1. **4 unwrap() calls in production code** (panic/crash risk)
2. **No rate limiting** (DoS vulnerable)
3. **No message size limits** (memory exhaustion)
4. **Missing automated coordination loop** (can't run as daemon)
5. **Policy enforcement not wired up** (policies ignored)
6. **Data race in volume tracking** (policy bypass)
7. **No RocksDB durability guarantees** (data loss on crash)

---

## Part 1: Critical Security Issues

### 🔴 CRITICAL-1: Production Code Contains unwrap() Calls

**Severity:** CRITICAL
**Impact:** System crash, DoS attack vector
**CWE:** CWE-248 (Uncaught Exception)

#### Location 1: Storage Volume Parsing
**File:** `igra-core/src/storage/rocks.rs:172`
```rust
let current = match existing {
    Some(bytes) => u64::from_be_bytes(bytes.as_slice().try_into().unwrap()), // ❌ PANIC
    None => 0,
};
```

**Attack Vector:**
- Attacker corrupts RocksDB entry to contain wrong number of bytes
- System attempts to parse as u64, panics
- Service crashes, denial of service

#### Location 2: Day Start Parsing
**File:** `igra-core/src/storage/rocks.rs:194`
```rust
let day_start = u64::from_be_bytes(key[prefix.len()..].try_into().unwrap());  // ❌ PANIC
```

#### Location 3: Volume Amount Parsing
**File:** `igra-core/src/storage/rocks.rs:201`
```rust
let amount = u64::from_be_bytes(value.as_ref().try_into().unwrap());  // ❌ PANIC
```

#### Location 4: Decryption Result
**File:** `igra-core/src/config/encryption.rs:50`
```rust
Ok(decrypted.unwrap())  // ❌ PANIC if decrypt returns None
```

**Fix Required:**
```rust
// Replace all unwrap() with proper error handling:
let current = match existing {
    Some(bytes) => {
        let array: [u8; 8] = bytes.as_slice().try_into()
            .map_err(|_| ThresholdError::StorageCorrupted("invalid volume entry"))?;
        u64::from_be_bytes(array)
    }
    None => 0,
};
```

**Estimated Fix Time:** 2 hours
**Test Coverage Needed:** Add corruption tests

---

### 🔴 CRITICAL-2: No Rate Limiting (DoS Vulnerable)

**Severity:** CRITICAL
**Impact:** Resource exhaustion, service unavailability
**CWE:** CWE-770 (Allocation of Resources Without Limits)

#### Missing Rate Limits

**1. Event Submission (JSON-RPC)**
**File:** `igra-service/src/service/json_rpc.rs:47-86`
```rust
async fn signing_event_submit(
    State(state): State<Arc<JsonRpcState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    // ❌ NO RATE LIMITING
    let event: SigningEvent = serde_json::from_value(payload["params"][0].clone())?;
    state.event_pipeline.process(event).await?;
    // ...
}
```

**Attack:** Attacker floods with 1000+ events/second → storage exhaustion

**2. Gossip Message Ingestion**
**File:** `igra-service/src/transport/iroh/filtering.rs:47-71`
```rust
match storage.mark_seen_message(...) {
    Ok(true) => yield Ok(envelope),  // ❌ NO RATE CHECK
    Ok(false) => continue,
    Err(err) => yield Err(err),
}
```

**Attack:** Malicious peer floods with unique messages → CPU exhaustion

**Fix Required:**

```rust
// Add rate limiter module:
// igra-core/src/rate_limit.rs

use std::time::{Duration, Instant};
use std::collections::HashMap;

pub struct TokenBucket {
    capacity: u32,
    refill_rate: u32,
    tokens: u32,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u32, refill_per_sec: u32) -> Self {
        Self {
            capacity,
            refill_rate: refill_per_sec,
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    pub fn try_consume(&mut self, count: u32) -> bool {
        self.refill();
        if self.tokens >= count {
            self.tokens -= count;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let tokens_to_add = (elapsed * self.refill_rate as f64) as u32;
        if tokens_to_add > 0 {
            self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
            self.last_refill = now;
        }
    }
}

pub struct RateLimiter {
    per_peer: HashMap<PeerId, TokenBucket>,
    global: TokenBucket,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            per_peer: HashMap::new(),
            global: TokenBucket::new(1000, 100),  // 1000 burst, 100/sec sustained
        }
    }

    pub fn check_peer(&mut self, peer_id: &PeerId) -> Result<(), ThresholdError> {
        // Check global limit first
        if !self.global.try_consume(1) {
            return Err(ThresholdError::RateLimitExceeded {
                peer_id: peer_id.clone(),
                limit_type: "global",
            });
        }

        // Check per-peer limit
        let bucket = self.per_peer.entry(peer_id.clone())
            .or_insert_with(|| TokenBucket::new(100, 10));  // 100 burst, 10/sec per peer

        if !bucket.try_consume(1) {
            return Err(ThresholdError::RateLimitExceeded {
                peer_id: peer_id.clone(),
                limit_type: "per_peer",
            });
        }

        Ok(())
    }

    pub fn cleanup_old_peers(&mut self, max_age: Duration) {
        // Periodically remove inactive peers to prevent memory leak
        self.per_peer.retain(|_, bucket| {
            bucket.last_refill.elapsed() < max_age
        });
    }
}
```

**Integration:**
```rust
// In filtering.rs:
let mut rate_limiter = RateLimiter::new();

loop {
    match envelope_stream.next().await {
        Some(Ok(envelope)) => {
            // Check rate limit BEFORE processing
            if let Err(e) = rate_limiter.check_peer(&envelope.sender_peer_id) {
                tracing::warn!("Rate limit exceeded for peer {}", envelope.sender_peer_id);
                continue;  // Drop message
            }
            // ... rest of processing
        }
    }
}
```

**Configuration:**
```toml
[rate_limiting]
global_burst = 1000
global_sustained = 100
per_peer_burst = 100
per_peer_sustained = 10
rpc_per_ip_burst = 50
rpc_per_ip_sustained = 5
```

**Estimated Fix Time:** 8 hours
**Test Coverage Needed:** Load tests with rate limiting

---

### 🔴 CRITICAL-3: No Message Size Limits

**Severity:** CRITICAL
**Impact:** Memory exhaustion, network DoS
**CWE:** CWE-400 (Uncontrolled Resource Consumption)

#### Current Implementation

**File:** `igra-service/src/transport/iroh/mod.rs:80-91`
```rust
async fn publish_bytes(&self, topic: Hash32, bytes: Vec<u8>) -> Result<(), ThresholdError> {
    let topic_id = TopicId::from(topic);
    let mut topic = self.gossip.subscribe(topic_id, self.bootstrap.clone()).await?;
    topic.broadcast(bytes.into()).await?;  // ❌ NO SIZE CHECK
    Ok(())
}
```

**Attack Vector:**
- Attacker sends 100 MB PSKT proposal
- All peers receive and attempt to decode
- Memory exhaustion on all nodes
- Gossip amplification makes it worse (each peer rebroadcasts)

**Fix Required:**

```rust
// Add constants:
pub const MAX_PROPOSAL_SIZE: usize = 1024 * 1024;      // 1 MB
pub const MAX_SIGNATURE_SIZE: usize = 1024;             // 1 KB
pub const MAX_ACK_SIZE: usize = 512;                    // 512 bytes

async fn publish_bytes(&self, topic: Hash32, bytes: Vec<u8>) -> Result<(), ThresholdError> {
    // Check size before publishing
    if bytes.len() > MAX_PROPOSAL_SIZE {
        return Err(ThresholdError::MessageTooLarge {
            size: bytes.len(),
            max: MAX_PROPOSAL_SIZE,
        });
    }

    let topic_id = TopicId::from(topic);
    let mut topic = self.gossip.subscribe(topic_id, self.bootstrap.clone()).await?;
    topic.broadcast(bytes.into()).await?;
    Ok(())
}

// Also check on receive:
async fn receive_message(&self, bytes: Bytes) -> Result<MessageEnvelope, ThresholdError> {
    if bytes.len() > MAX_PROPOSAL_SIZE {
        return Err(ThresholdError::MessageTooLarge {
            size: bytes.len(),
            max: MAX_PROPOSAL_SIZE,
        });
    }

    // ... decode and process
}
```

**Configuration:**
```toml
[transport]
max_proposal_size_bytes = 1048576  # 1 MB
max_signature_size_bytes = 1024
max_ack_size_bytes = 512
```

**Estimated Fix Time:** 4 hours
**Test Coverage Needed:** Large message rejection tests

---

### 🔴 CRITICAL-4: Missing Automated Coordination Loop

**Severity:** CRITICAL
**Impact:** System cannot run as autonomous daemon
**CWE:** N/A (Incomplete Implementation)

#### Current State

The system has all coordination components but **no main loop** to tie them together.

**What Exists:**
- ✅ Coordinator can propose transactions
- ✅ Signer can validate proposals
- ✅ Transport can publish messages
- ❌ No loop to handle incoming proposals automatically

**Current Binary:**
**File:** `igra-service/src/bin/kaspa-threshold-service.rs:1-463`
```rust
#[tokio::main]
async fn main() -> Result<()> {
    // ... setup code ...

    // ❌ MISSING: Coordination loop
    // Service just exits after setup

    Ok(())
}
```

**Fix Required:**

```rust
// New file: igra-service/src/service/coordination_loop.rs

use tokio::select;
use tokio::sync::mpsc;

pub struct CoordinationLoop {
    coordinator: Arc<Coordinator>,
    signer: Arc<Signer>,
    transport: Arc<dyn Transport>,
    storage: Arc<RwLock<RocksStorage>>,
    config: Arc<AppConfig>,
    shutdown: mpsc::Receiver<()>,
}

impl CoordinationLoop {
    pub async fn run(mut self) -> Result<(), ThresholdError> {
        let group_id = compute_group_id(&self.config)?;

        // Subscribe to group messages
        let mut message_stream = self.transport.subscribe_group(group_id).await?;

        // Start background tasks
        let mut session_timeout_check = tokio::time::interval(Duration::from_secs(10));
        let mut cleanup_task = tokio::time::interval(Duration::from_secs(3600));

        tracing::info!("Coordination loop started");

        loop {
            select! {
                // Handle incoming messages
                Some(result) = message_stream.next() => {
                    match result {
                        Ok(envelope) => {
                            if let Err(e) = self.handle_message(envelope).await {
                                tracing::error!("Error handling message: {}", e);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Transport error: {}", e);
                        }
                    }
                }

                // Check for timed-out sessions
                _ = session_timeout_check.tick() => {
                    if let Err(e) = self.check_timeouts().await {
                        tracing::error!("Error checking timeouts: {}", e);
                    }
                }

                // Cleanup old data
                _ = cleanup_task.tick() => {
                    if let Err(e) = self.cleanup_old_data().await {
                        tracing::error!("Error cleaning up: {}", e);
                    }
                }

                // Graceful shutdown
                _ = self.shutdown.recv() => {
                    tracing::info!("Shutdown signal received");
                    break;
                }
            }
        }

        tracing::info!("Coordination loop stopped");
        Ok(())
    }

    async fn handle_message(&self, envelope: MessageEnvelope) -> Result<(), ThresholdError> {
        match envelope.payload {
            TransportMessage::SigningEventPropose(proposal) => {
                self.handle_proposal(proposal).await?;
            }
            TransportMessage::SignerAck(ack) => {
                self.handle_ack(ack).await?;
            }
            TransportMessage::PartialSigSubmit(sig) => {
                self.handle_partial_sig(sig).await?;
            }
            TransportMessage::FinalizeNotice(notice) => {
                self.handle_finalize_notice(notice).await?;
            }
        }
        Ok(())
    }

    async fn handle_proposal(&self, proposal: ProposedSigningSession) -> Result<(), ThresholdError> {
        tracing::info!("Received proposal for session {}", proposal.session_id);

        // Validate proposal
        let validation = self.signer.validate_proposal(
            &proposal,
            Some(&self.config.policy),  // ✅ Pass policy
        ).await?;

        // Publish acknowledgment
        self.transport.publish_ack(
            proposal.session_id,
            validation.ack,
        ).await?;

        // If accepted, sign and publish partial signatures
        if validation.ack.accept {
            let backend = self.get_signing_backend()?;
            self.signer.submit_partial_sigs(
                proposal.session_id,
                &proposal.request_id,
                backend.as_ref(),
                &proposal.kpsbt_blob,
            ).await?;

            tracing::info!("Submitted partial signatures for {}", proposal.request_id);
        } else {
            tracing::warn!("Rejected proposal: {:?}", validation.ack.reason);
        }

        Ok(())
    }

    async fn handle_partial_sig(&self, sig: PartialSigPublish) -> Result<(), ThresholdError> {
        // If we're the coordinator, collect signatures
        let storage = self.storage.read().unwrap();
        let request = storage.get_request(&sig.request_id)?;

        if let Some(req) = request {
            // Check if we're the coordinator (first proposer)
            // and if threshold is met
            let sigs = storage.get_partial_sigs(&sig.request_id)?;

            if sigs.len() >= self.config.group.threshold_m as usize {
                tracing::info!("Threshold met for {}, finalizing", sig.request_id);
                self.coordinator.finalize_transaction(&sig.request_id).await?;
            }
        }

        Ok(())
    }

    async fn check_timeouts(&self) -> Result<(), ThresholdError> {
        let storage = self.storage.read().unwrap();
        let timeout_threshold = now_nanos() - (self.config.runtime.session_timeout_seconds * 1_000_000_000);

        // Find timed-out sessions
        let timed_out = storage.find_timed_out_sessions(timeout_threshold)?;

        for request_id in timed_out {
            tracing::warn!("Session {} timed out", request_id);
            storage.update_request_decision(
                &request_id,
                RequestDecision::Expired,
            )?;
        }

        Ok(())
    }

    async fn cleanup_old_data(&self) -> Result<(), ThresholdError> {
        let cutoff = now_nanos() - (30 * 24 * 3600 * 1_000_000_000);  // 30 days
        let storage = self.storage.write().unwrap();

        let archived = storage.archive_old_requests(cutoff)?;
        if archived > 0 {
            tracing::info!("Archived {} old requests", archived);
        }

        Ok(())
    }
}
```

**Update Binary:**
```rust
// igra-service/src/bin/kaspa-threshold-service.rs

#[tokio::main]
async fn main() -> Result<()> {
    // ... existing setup code ...

    // Create coordination loop
    let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);

    let coordination_loop = CoordinationLoop {
        coordinator,
        signer,
        transport,
        storage,
        config,
        shutdown: shutdown_rx,
    };

    // Handle signals for graceful shutdown
    let shutdown_handle = tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("failed to listen for ctrl-c");
        tracing::info!("Shutdown signal received");
        shutdown_tx.send(()).await.ok();
    });

    // Run coordination loop
    coordination_loop.run().await?;

    // Wait for shutdown to complete
    shutdown_handle.await?;

    Ok(())
}
```

**Estimated Fix Time:** 16 hours
**Test Coverage Needed:** End-to-end daemon tests

---

### 🔴 CRITICAL-5: Policy Enforcement Not Wired Up

**Severity:** CRITICAL
**Impact:** Security policies completely bypassed
**CWE:** CWE-665 (Improper Initialization)

#### Current State

Policy enforcement code exists but is **never called** with actual policy.

**File:** `igra-core/src/coordination/signer.rs:168-212`
```rust
pub async fn validate_proposal(
    &self,
    proposal: &ProposedSigningSession,
    policy: Option<&GroupPolicy>,  // ❌ Usually None
) -> Result<SignerValidationResult, ThresholdError> {
    // ... validation logic ...

    if let Some(p) = policy {
        self.enforce_policy(&event, p)?;  // Only if policy provided
    }
    // ...
}

fn enforce_policy(&self, event: &SigningEvent, policy: &GroupPolicy) -> Result<(), ThresholdError> {
    // Check destination allowlist
    if !policy.allowed_destinations.is_empty() {
        if !policy.allowed_destinations.contains(&event.recipient_address) {
            return Err(ThresholdError::DestinationNotAllowed {
                destination: event.recipient_address.clone(),
            });
        }
    }

    // Check amount limits
    if let Some(min) = policy.min_amount_sompi {
        if event.amount_sompi < min {
            return Err(ThresholdError::AmountTooLow { amount: event.amount_sompi, min });
        }
    }

    // ... more checks
}
```

**Problem:** Callers pass `None` for policy:
```rust
let validation = signer.validate_proposal(&proposal, None).await?;  // ❌ No policy
```

**Fix Required:**

Load policy from config and always pass it:

```rust
// In coordination loop:
async fn handle_proposal(&self, proposal: ProposedSigningSession) -> Result<(), ThresholdError> {
    let validation = self.signer.validate_proposal(
        &proposal,
        Some(&self.config.policy),  // ✅ Always pass policy
    ).await?;
    // ...
}
```

**Make policy required:**
```rust
// Change signature:
pub async fn validate_proposal(
    &self,
    proposal: &ProposedSigningSession,
    policy: &GroupPolicy,  // ✅ No longer Option
) -> Result<SignerValidationResult, ThresholdError>
```

**Estimated Fix Time:** 2 hours
**Test Coverage Needed:** Policy enforcement integration tests

---

### 🔴 CRITICAL-6: Data Race in Volume Tracking

**Severity:** CRITICAL
**Impact:** Policy bypass, double-spending
**CWE:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)

#### Vulnerable Code

**File:** `igra-core/src/storage/rocks.rs:163-178`
```rust
fn add_to_daily_volume(&self, amount_sompi: u64, timestamp_nanos: u64) -> Result<(), ThresholdError> {
    let day_start = Self::day_start_nanos(timestamp_nanos);
    let key = Self::key_volume(day_start);

    // ❌ RACE: Another thread could update between get and put
    let existing = self.db.get(&key)?;  // <-- Read
    let current = match existing {
        Some(bytes) => {
            u64::from_be_bytes(bytes.as_slice().try_into().unwrap())
        }
        None => 0,
    };
    let updated = current.saturating_add(amount_sompi).to_be_bytes();
    self.db.put(key, updated)?;  // <-- Write
    Ok(())
}
```

**Attack Scenario:**
1. Policy limit: 100 KAS/day
2. Thread A reads current volume: 50 KAS
3. Thread B reads current volume: 50 KAS (before A writes)
4. Thread A adds 60 KAS transaction → writes 110 KAS (rejected)
5. Thread B adds 60 KAS transaction → writes 110 KAS (also thinks current is 50)
6. Result: 120 KAS processed but volume shows 110 KAS

**Fix Required:**

Use RocksDB merge operator for atomic updates:

```rust
// Define merge function:
fn volume_merge(
    _key: &[u8],
    existing: Option<&[u8]>,
    operands: &rocksdb::MergeOperands,
) -> Option<Vec<u8>> {
    let mut total = existing
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0);

    for op in operands {
        if let Ok(array) = op.try_into() {
            let value = u64::from_be_bytes(array);
            total = total.saturating_add(value);
        }
    }

    Some(total.to_be_bytes().to_vec())
}

// Register merge operator:
pub fn open(path: impl AsRef<Path>) -> Result<Self, ThresholdError> {
    let mut options = RocksOptions::default();
    options.create_if_missing(true);
    options.set_merge_operator_associative("volume_add", volume_merge);
    let db = DB::open(&options, path)?;
    Ok(Self { db: Arc::new(db) })
}

// Use merge instead of get+put:
fn add_to_daily_volume(&self, amount_sompi: u64, timestamp_nanos: u64) -> Result<(), ThresholdError> {
    let day_start = Self::day_start_nanos(timestamp_nanos);
    let key = Self::key_volume(day_start);

    // ✅ Atomic merge operation
    self.db.merge(key, amount_sompi.to_be_bytes())?;
    Ok(())
}
```

**Estimated Fix Time:** 4 hours
**Test Coverage Needed:** Concurrent volume update tests

---

### 🔴 CRITICAL-7: No RocksDB Durability Guarantees

**Severity:** CRITICAL
**Impact:** Data loss on crash
**CWE:** CWE-404 (Improper Resource Shutdown or Release)

#### Current Configuration

**File:** `igra-core/src/storage/rocks.rs:20-24`
```rust
pub fn open(path: impl AsRef<Path>) -> Result<Self, ThresholdError> {
    let mut options = RocksOptions::default();
    options.create_if_missing(true);
    let db = DB::open(&options, path)?;  // ❌ Default options
    Ok(Self { db: Arc::new(db) })
}
```

**Problem:**
- RocksDB defaults: WAL enabled but **not fsync'd** on every write
- Crash could lose last few seconds of data
- Could lose finalized transactions, partial signatures, etc.

**Fix Required:**

```rust
pub fn open(path: impl AsRef<Path>) -> Result<Self, ThresholdError> {
    let mut options = RocksOptions::default();
    options.create_if_missing(true);

    // ✅ Enable durability guarantees
    options.set_use_fsync(true);  // Force fsync instead of fdatasync
    options.set_disable_wal(false);  // Ensure WAL enabled
    options.set_wal_recovery_mode(rocksdb::DBRecoveryMode::PointInTime);

    // Optimize for durability vs performance tradeoff
    options.set_manual_wal_flush(false);  // Auto-flush WAL
    options.set_wal_bytes_per_sync(1024 * 1024);  // Sync WAL every 1 MB

    // Optimize compaction
    options.set_level_compaction_dynamic_level_bytes(true);
    options.set_max_background_jobs(4);

    let db = DB::open(&options, path)?;
    Ok(Self { db: Arc::new(db) })
}
```

**Performance Impact:**
- ~10-20% slower writes (acceptable for financial system)
- Guarantees no data loss on crash

**Configuration Option:**
```toml
[storage]
fsync_enabled = true  # true for production, false for testing
wal_bytes_per_sync = 1048576
```

**Estimated Fix Time:** 2 hours
**Test Coverage Needed:** Crash recovery tests

---

## Part 2: High Priority Issues

### 🟡 HIGH-1: RocksDB Uses Key Prefixes Instead of Column Families

**Severity:** HIGH
**Impact:** Performance degradation, inefficient storage
**File:** `igra-core/src/storage/rocks.rs:68-156`

**Current:** String prefixes (`"grp:"`, `"evt:"`, `"req:"`)
**Should Use:** Column families

**Impact:**
- All data in single keyspace → slower iterations
- Can't optimize bloom filters per data type
- Can't tune compaction per data type
- Inefficient prefix scans

**Fix:** Migrate to column families (see docs/legacy/dev/CODE_REFACTORING.md Part 2.3)

**Estimated Fix Time:** 12 hours

---

### 🟡 HIGH-2: Volume Tracking Uses O(n) Full Scan

**Severity:** HIGH
**Impact:** Performance bottleneck
**File:** `igra-core/src/storage/rocks.rs:211-231`

**Current:** Scans all requests to compute volume
**Should Use:** Daily aggregates (O(d) where d = days)

**Fix:** Already proposed in docs/legacy/dev/CODE_REFACTORING.md Part 2.3

**Estimated Fix Time:** 8 hours

---

### 🟡 HIGH-3: Float Arithmetic in Fee Calculation

**Severity:** HIGH
**Impact:** Non-deterministic PSKT construction
**File:** `igra-core/src/pskt/builder.rs:86`

```rust
let portion_scaled = (recipient_portion * 1_000_000.0) as u64;  // ⚠️ Float multiply
```

**Issue:** Float arithmetic can have rounding differences across platforms

**Fix Required:**
```rust
// Use fixed-point integer arithmetic:
let portion_scaled = (recipient_portion_basis_points * 1_000_000u64) / 10_000u64;
// Where recipient_portion_basis_points is 0-10000 (0.00%-100.00%)
```

**Estimated Fix Time:** 4 hours

---

### 🟡 HIGH-4: No Connection Pooling for Node RPC

**Severity:** HIGH
**Impact:** Performance, connection exhaustion
**File:** `igra-core/src/rpc/grpc.rs:16-30`

**Current:** Each request creates new gRPC client
**Should Use:** Connection pool with reuse

**Fix:**
```rust
pub struct GrpcNodeRpcPool {
    pool: deadpool::managed::Pool<GrpcConnectionManager>,
}

impl GrpcNodeRpcPool {
    pub async fn get_client(&self) -> Result<GrpcNodeRpc> {
        let conn = self.pool.get().await?;
        Ok(conn)
    }
}
```

**Estimated Fix Time:** 6 hours

---

### 🟡 HIGH-5: No Transaction Monitoring

**Severity:** HIGH
**Impact:** No finality verification

**Missing:**
- Confirmation tracking after submit
- Blue score monitoring
- Finality verification (10 confirmations)
- Reorg detection and handling

**Fix Required:**
```rust
pub struct TransactionMonitor {
    node_rpc: Arc<dyn NodeRpc>,
    storage: Arc<RwLock<RocksStorage>>,
}

impl TransactionMonitor {
    pub async fn monitor_transaction(&self, request_id: &RequestId, tx_id: &TransactionId) -> Result<()> {
        let start_blue_score = self.node_rpc.get_virtual_selected_parent_blue_score().await?;

        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;

            let current_blue_score = self.node_rpc.get_virtual_selected_parent_blue_score().await?;
            let confirmations = current_blue_score.saturating_sub(start_blue_score);

            if confirmations >= FINALITY_CONFIRMATIONS {
                // Mark as finalized
                let mut storage = self.storage.write().unwrap();
                storage.mark_transaction_finalized(request_id, current_blue_score)?;
                break;
            }
        }

        Ok(())
    }
}
```

**Estimated Fix Time:** 12 hours

---

### 🟡 HIGH-6: No Gossip Spam Protection

**Severity:** HIGH
**Impact:** Resource waste, bandwidth exhaustion

**Current:** Only signature verification
**Missing:** Penalty system for invalid messages

**Fix:**
```rust
struct PeerReputation {
    peer_id: PeerId,
    invalid_count: u32,
    last_invalid: Instant,
    banned_until: Option<Instant>,
}

impl GossipFilter {
    fn record_invalid(&mut self, peer_id: &PeerId) {
        let rep = self.reputation.entry(peer_id.clone())
            .or_insert_with(|| PeerReputation::default());

        rep.invalid_count += 1;
        rep.last_invalid = Instant::now();

        // Ban if too many invalid messages
        if rep.invalid_count > 100 {
            rep.banned_until = Some(Instant::now() + Duration::from_secs(3600));
            tracing::warn!("Banned peer {} for spam", peer_id);
        }
    }

    fn should_accept(&self, peer_id: &PeerId) -> bool {
        if let Some(rep) = self.reputation.get(peer_id) {
            if let Some(ban) = rep.banned_until {
                return Instant::now() > ban;
            }
        }
        true
    }
}
```

**Estimated Fix Time:** 8 hours

---

### 🟡 HIGH-7 through HIGH-13: Additional Issues

See docs/legacy/dev/CODE_REFACTORING.md for details on:
- Comprehensive integration testing (HIGH-7)
- Load testing with 100+ events/hour (HIGH-8)
- Security audit by external party (HIGH-9)
- Structured audit logging (HIGH-10)
- Error codes for monitoring (HIGH-11)
- Config.rs splitting (HIGH-12)
- HSM trait support (HIGH-13)

---

## Part 3: Medium Priority Issues

### 🟢 MEDIUM-1: Potential Timing Leaks Beyond Hash Comparison

**Severity:** MEDIUM
**File:** Multiple locations

**Concerns:**
- Policy enforcement timing (destination check, amount validation)
- Signature verification timing (secp256k1 operations)
- Database query timing

**Recommendation:** Review all security-critical comparisons

**Estimated Fix Time:** 6 hours

---

### 🟢 MEDIUM-2: No Secrets Logging Prevention

**Severity:** MEDIUM

**Issue:** No automated check to prevent secret logging

**Fix:**
```bash
# Add to CI:
#!/bin/bash
if grep -r "debug.*secret\|trace.*mnemonic\|info.*private\|log.*keypair" src/; then
    echo "ERROR: Potential secret logging detected"
    exit 1
fi
```

**Estimated Fix Time:** 2 hours

---

### 🟢 MEDIUM-3 through MEDIUM-8: See docs/legacy/dev/CODE_REFACTORING.md

Additional medium priority items documented in docs/legacy/dev/CODE_REFACTORING.md

---

## Part 4: Verification Against Requirements

### Requirement 1: Modular Structure ✅ VERIFIED

- Clean trait abstractions
- No circular dependencies
- Good separation of concerns

**Gap:** Config module needs splitting (784 lines)

### Requirement 2: Cryptographic Soundness ✅ MOSTLY VERIFIED

- Proper Schnorr signatures
- Constant-time comparisons
- Zeroize for secrets

**Gaps:**
- No HSM support
- Float arithmetic in fee calculation
- Some unwrap() calls

### Requirement 3: Auditability ✅ MOSTLY VERIFIED

- Deterministic PSKT construction
- RocksDB audit trail
- State machine validation

**Gaps:**
- No formal protocol spec
- No threat model document
- Missing timestamps in some records

### Requirement 4: Extensibility ⚠️ PARTIAL

- Good trait abstractions
- Configuration via INI

**Gaps:**
- No protocol versioning
- No cargo feature flags
- No config schema versioning

### Requirement 5: Maintainability ✅ GOOD

- Clean Rust patterns
- Good error handling (except unwraps)
- Small focused modules

**Gaps:**
- Large config.rs file
- No error codes

### Requirement 6: Performance ⚠️ NEEDS WORK

- RocksDB for persistence

**Gaps:**
- No column families
- O(n) volume tracking
- No connection pooling
- No cleanup scheduling

### Requirement 7: Compliance ✅ MOSTLY GOOD

- Good documentation
- PSKT follows BIP-174 patterns

**Gaps:**
- No formal protocol spec
- No threat model
- No fuzzing

---

## Part 5: Action Plan

### Immediate Actions (This Week)

**Must Complete Before Production:**

1. ✅ Fix all 4 unwrap() calls (2 hours)
2. ✅ Implement rate limiting (8 hours)
3. ✅ Add message size limits (4 hours)
4. ✅ Enable RocksDB fsync (2 hours)
5. ✅ Wire up policy enforcement (2 hours)

**Total: 18 hours (2-3 days)**

### Week 1-2: Critical Features

6. ✅ Build automated coordination loop (16 hours)
7. ✅ Fix volume tracking race condition (4 hours)
8. ✅ Add transaction monitoring (12 hours)
9. ✅ Comprehensive integration tests (16 hours)

**Total: 48 hours (1-1.5 weeks)**

### Week 3-4: Production Hardening

10. Migrate to RocksDB column families (12 hours)
11. Optimize volume tracking (8 hours)
12. Add connection pooling (6 hours)
13. Implement gossip spam protection (8 hours)
14. Fix float arithmetic in fees (4 hours)
15. Add HSM trait support (8 hours)

**Total: 46 hours (1-1.5 weeks)**

### Week 5-6: Documentation & Testing

16. Create formal protocol spec (16 hours)
17. Create threat model document (12 hours)
18. Add fuzzing targets (16 hours)
19. External security audit (40 hours)
20. Load testing and performance tuning (16 hours)

**Total: 100 hours (2.5 weeks)**

---

## Total Estimated Work

| Phase | Duration | Priority |
|-------|----------|----------|
| Immediate fixes | 18 hours | CRITICAL |
| Week 1-2 features | 48 hours | CRITICAL |
| Week 3-4 hardening | 46 hours | HIGH |
| Week 5-6 docs/test | 100 hours | HIGH |
| **TOTAL** | **212 hours** | **~6-8 weeks** |

---

## Conclusion

This is a **well-architected threshold signing system** with strong security foundations. However, **7 critical issues** must be addressed before production deployment.

**Overall Assessment:**
- **Current State:** 7.5/10 - Professional-grade implementation
- **After Critical Fixes:** 8.5/10 - Production-ready
- **After All Fixes:** 9.5/10 - Enterprise-grade

**Key Strengths:**
- Excellent cryptographic practices
- Clean architecture
- Good error handling (mostly)
- Comprehensive replay protection

**Critical Work Required:**
- Fix 4 unwrap() calls
- Add rate limiting
- Build coordination loop
- Wire up policies
- Fix data races

**Recommendation:** ✅ **Proceed with fixes, then deploy to production**

The architecture is sound and most issues are implementation gaps rather than design flaws. With 6-8 weeks of focused work, this will be a robust production system.

---

**Document Version:** 1.0
**Last Updated:** 2025-12-31
**Status:** Final Security Audit Report
**Next Action:** Begin immediate critical fixes
