# Anti-Entropy Enhancement for CRDT Coordination

## Overview

Anti-entropy is a background synchronization mechanism that ensures all nodes eventually converge to the same state, even when gossip messages are lost or nodes were offline.

**Prerequisite:** This document assumes the core CRDT implementation from `CRDT-IMPLEMENTATION-GUIDE.md` is complete.

---

## 1. What is Anti-Entropy?

### The Problem

Gossip-based broadcast works well in the happy path:
```
Signer A signs → broadcasts EventState → Signers B,C,D,E receive → merge
```

But messages can be lost:
- Network blip during broadcast
- Signer was offline/restarting
- UDP packet dropped (iroh uses QUIC, but still)
- Signer joined late after event was processed

Result: One signer has signatures that others don't know about.

### The Solution

Anti-entropy is periodic state comparison between peers:
```
Every N seconds:
  Pick a random peer
  Send: "Here's a summary of what I have"
  Peer responds: "Here's what you're missing"
  Merge the missing data
```

This guarantees eventual consistency even with message loss.

### Why "Anti-Entropy"?

The term comes from thermodynamics. Entropy = disorder. In distributed systems, entropy means state divergence between nodes. Anti-entropy actively fights this divergence.

---

## 2. Why Use Anti-Entropy?

### When You Need It

| Scenario | Gossip Only | With Anti-Entropy |
|----------|-------------|-------------------|
| All nodes online, no packet loss | Works | Works |
| One node restarts mid-session | May miss signatures | Recovers |
| Network partition heals | States diverged | Converges |
| Late joiner to signing group | Misses history | Catches up |
| High packet loss environment | Unreliable | Reliable |

### When You Don't Need It

- Small group (3-5 signers) with reliable network
- Short session timeouts (signatures expire quickly anyway)
- Acceptable to retry failed sessions

### Recommendation

For production systems handling real value: **implement anti-entropy**. The cost is low (periodic background sync) and the benefit is guaranteed consistency.

---

## 3. Anti-Entropy Strategies

### 3.1 Full State Exchange (Simple, Not Scalable)

```
A → B: "Here's ALL my data"
B → A: "Here's ALL my data"
Both merge everything
```

**Pros:** Simple
**Cons:** O(n) bandwidth per sync, wasteful

### 3.2 Merkle Tree Comparison (Complex, Scalable)

```
A → B: "Root hash of my merkle tree is X"
B → A: "Mine is Y, let's compare subtrees"
... recursive comparison ...
Exchange only differing leaves
```

**Pros:** O(log n) for finding differences
**Cons:** Complex implementation, overkill for small datasets

### 3.3 Digest-Based Exchange (Recommended)

```
A → B: "I have events [hash1, hash2, hash3] with signature counts [5, 3, 7]"
B → A: "Send me hash2 (I only have 2 sigs) and hash3 (I don't have it)"
A → B: Sends full state for hash2 and hash3
```

**Pros:** Simple, efficient for our use case
**Cons:** Digest computation per sync

**This is what we'll implement.**

---

## 4. Implementation Design

### 4.1 Message Types

Add to `igra-core/src/infrastructure/transport/iroh/messages.rs`:

```rust
/// Summary of events this node knows about
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateSyncRequest {
    /// Map of (event_hash, tx_template_hash) -> signature count
    pub event_digests: Vec<EventDigest>,
    /// Timestamp for distributed protocol consistency
    pub timestamp_nanos: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventDigest {
    pub event_hash: Hash32,
    pub tx_template_hash: Hash32,
    pub signature_count: u32,
    pub is_completed: bool,
}

/// Response with full state for requested events
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateSyncResponse {
    /// Full CRDT states for events the requester needs
    pub event_states: Vec<EventCrdtState>,
    /// Events the responder wants from requester
    pub requested_events: Vec<(Hash32, Hash32)>, // (event_hash, tx_template_hash)
}
```

### 4.2 Sync Protocol Flow

```
┌─────────────┐                      ┌─────────────┐
│  Signer A   │                      │  Signer B   │
└──────┬──────┘                      └──────┬──────┘
       │                                    │
       │  StateSyncRequest                  │
       │  [event1: 5 sigs, event2: 3 sigs]  │
       │───────────────────────────────────>│
       │                                    │
       │                    Compare with local state:
       │                    - event1: I have 5 sigs (same)
       │                    - event2: I have 4 sigs (more!)
       │                    - event3: I have 2 sigs (A missing)
       │                                    │
       │  StateSyncResponse                 │
       │  [event2: full state,              │
       │   event3: full state]              │
       │   requested: [event1 if A has more]│
       │<───────────────────────────────────│
       │                                    │
       │  Merge received states             │
       │  Send requested events if any      │
       │                                    │
```

### 4.3 Anti-Entropy Loop

Add to `igra-service/src/service/coordination/anti_entropy.rs`:

```rust
use crate::service::flow::ServiceFlow;
use igra_core::foundation::{Hash32, PeerId, ThresholdError};
use igra_core::infrastructure::storage::rocks::RocksStorage;
use igra_core::infrastructure::transport::iroh::messages::{EventDigest, StateSyncRequest};
use igra_core::infrastructure::transport::iroh::traits::Transport;
use log::{debug, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;

/// Configuration for anti-entropy sync
pub struct AntiEntropyConfig {
    /// How often to sync with a peer (default: 30 seconds)
    pub sync_interval: Duration,
    /// Only sync events newer than this (default: 1 hour)
    pub max_event_age: Duration,
    /// Maximum events to include in digest (default: 100)
    pub max_digest_size: usize,
}

impl Default for AntiEntropyConfig {
    fn default() -> Self {
        Self {
            sync_interval: Duration::from_secs(30),
            max_event_age: Duration::from_secs(3600),
            max_digest_size: 100,
        }
    }
}

/// Runs the anti-entropy background loop
pub async fn run_anti_entropy_loop(
    config: AntiEntropyConfig,
    transport: Arc<dyn Transport>,
    storage: Arc<RocksStorage>,
    local_peer_id: PeerId,
    group_id: Hash32,
    known_peers: Arc<tokio::sync::RwLock<Vec<PeerId>>>,
) -> Result<(), ThresholdError> {
    let mut ticker = interval(config.sync_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    info!(
        "anti-entropy loop started interval_secs={} max_age_secs={} peer_id={}",
        config.sync_interval.as_secs(),
        config.max_event_age.as_secs(),
        local_peer_id
    );

    loop {
        ticker.tick().await;

        // Pick a random peer
        let peers = known_peers.read().await;
        if peers.is_empty() {
            debug!("no peers available for anti-entropy sync");
            continue;
        }
        let peer_idx = rand::random::<usize>() % peers.len();
        let target_peer = peers[peer_idx].clone();
        drop(peers);

        if target_peer == local_peer_id {
            continue;
        }

        // Build digest of recent events
        let digest = match build_event_digest(&storage, &config) {
            Ok(d) => d,
            Err(err) => {
                warn!("failed to build event digest error={}", err);
                continue;
            }
        };

        debug!(
            "sending anti-entropy sync request to={} event_count={}",
            target_peer,
            digest.len()
        );

        // Send sync request
        let request = StateSyncRequest {
            event_digests: digest,
            timestamp_nanos: now_nanos(),
        };

        if let Err(err) = transport.send_sync_request(group_id, target_peer.clone(), request).await {
            warn!(
                "failed to send sync request to={} error={}",
                target_peer, err
            );
        }
    }
}

fn build_event_digest(
    storage: &RocksStorage,
    config: &AntiEntropyConfig,
) -> Result<Vec<EventDigest>, ThresholdError> {
    let cutoff_ns = now_nanos().saturating_sub(config.max_event_age.as_nanos() as u64);
    let mut digests = Vec::new();

    // Iterate recent event CRDTs
    for event_crdt in storage.list_recent_event_crdts(cutoff_ns, config.max_digest_size)? {
        digests.push(EventDigest {
            event_hash: event_crdt.event_hash,
            tx_template_hash: event_crdt.tx_template_hash,
            signature_count: event_crdt.signatures.len() as u32,
            is_completed: event_crdt.completed_at_ns.is_some(),
        });
    }

    Ok(digests)
}

fn now_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
```

### 4.4 Sync Request Handler

Add to the coordination loop message handler:

```rust
TransportMessage::StateSyncRequest(req) => {
    let response = handle_sync_request(&storage, &req)?;

    // Send response back to requester
    transport.send_sync_response(
        envelope.session_id,
        envelope.sender_peer_id.clone(),
        response,
    ).await?;
}

TransportMessage::StateSyncResponse(resp) => {
    // Merge received event states
    for event_state in resp.event_states {
        if let Err(err) = merge_remote_state(&storage, &flow, event_state).await {
            warn!("failed to merge sync response state error={}", err);
        }
    }

    // Send any requested events back
    for (event_hash, tx_template_hash) in resp.requested_events {
        if let Some(state) = storage.get_event_crdt(&event_hash, &tx_template_hash)? {
            transport.send_event_state(
                envelope.session_id,
                envelope.sender_peer_id.clone(),
                state,
            ).await?;
        }
    }
}
```

Handler implementation:

```rust
fn handle_sync_request(
    storage: &RocksStorage,
    req: &StateSyncRequest,
) -> Result<StateSyncResponse, ThresholdError> {
    let mut event_states = Vec::new();
    let mut requested_events = Vec::new();

    for digest in &req.event_digests {
        match storage.get_event_crdt(&digest.event_hash, &digest.tx_template_hash)? {
            Some(local_state) => {
                let local_sig_count = local_state.signatures.len() as u32;

                if local_sig_count > digest.signature_count {
                    // We have more signatures, send our state
                    event_states.push(local_state.to_wire_format());
                } else if local_sig_count < digest.signature_count {
                    // They have more signatures, request their state
                    requested_events.push((digest.event_hash, digest.tx_template_hash));
                }
                // If equal, no action needed
            }
            None => {
                // We don't have this event at all, request it
                requested_events.push((digest.event_hash, digest.tx_template_hash));
            }
        }
    }

    // Also check for events we have that they didn't mention
    // (they might be missing entire events)
    let our_recent = storage.list_recent_event_crdts(
        req.timestamp_nanos.saturating_sub(3600_000_000_000), // 1 hour window
        100,
    )?;

    for our_event in our_recent {
        let dominated = req.event_digests.iter().any(|d| {
            d.event_hash == our_event.event_hash &&
            d.tx_template_hash == our_event.tx_template_hash
        });

        if !dominated {
            // They don't know about this event, include it
            event_states.push(our_event.to_wire_format());
        }
    }

    Ok(StateSyncResponse {
        event_states,
        requested_events,
    })
}
```

### 4.5 Storage Additions

Add to `igra-core/src/infrastructure/storage/rocks/engine.rs`:

```rust
/// List recent event CRDTs for anti-entropy digest
pub fn list_recent_event_crdts(
    &self,
    min_timestamp_ns: u64,
    limit: usize,
) -> Result<Vec<EventCrdt>, ThresholdError> {
    let cf = self.cf_handle(schema::CF_EVENT_CRDT)?;
    let mut results = Vec::new();

    let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
    for item in iter {
        let (_, value) = item.map_err(|e| ThresholdError::Storage(e.to_string()))?;
        let crdt: EventCrdt = bincode::deserialize(&value)
            .map_err(|e| ThresholdError::Serialization(e.to_string()))?;

        // Filter by timestamp
        let event_ts = crdt.signatures.values()
            .map(|s| s.timestamp_nanos)
            .max()
            .unwrap_or(0);

        if event_ts >= min_timestamp_ns {
            results.push(crdt);
            if results.len() >= limit {
                break;
            }
        }
    }

    Ok(results)
}
```

### 4.6 Transport Additions

Add to `Transport` trait:

```rust
/// Send anti-entropy sync request to a specific peer
async fn send_sync_request(
    &self,
    group_id: Hash32,
    target_peer: PeerId,
    request: StateSyncRequest,
) -> Result<(), ThresholdError>;

/// Send anti-entropy sync response to a specific peer
async fn send_sync_response(
    &self,
    session_id: SessionId,
    target_peer: PeerId,
    response: StateSyncResponse,
) -> Result<(), ThresholdError>;
```

---

## 5. Implementation Steps

### Step 1: Add Message Types

**File:** `igra-core/src/infrastructure/transport/iroh/messages.rs`

1. Add `EventDigest` struct
2. Update `StateSyncRequest` with `event_digests` field
3. Update `StateSyncResponse` with `event_states` and `requested_events` fields

### Step 2: Add Storage Method

**File:** `igra-core/src/infrastructure/storage/rocks/engine.rs`

1. Add `list_recent_event_crdts()` method
2. Add index by timestamp if needed for performance

### Step 3: Add Transport Methods

**File:** `igra-core/src/infrastructure/transport/iroh/traits.rs`

1. Add `send_sync_request()` to trait
2. Add `send_sync_response()` to trait

**File:** `igra-core/src/infrastructure/transport/iroh/node.rs`

1. Implement `send_sync_request()`
2. Implement `send_sync_response()`

### Step 4: Create Anti-Entropy Loop

**File:** `igra-service/src/service/coordination/anti_entropy.rs` (new file)

1. Create `AntiEntropyConfig` struct
2. Implement `run_anti_entropy_loop()`
3. Implement `build_event_digest()`

### Step 5: Add Message Handlers

**File:** `igra-service/src/service/coordination/loop.rs`

1. Add handler for `StateSyncRequest`
2. Add handler for `StateSyncResponse`
3. Implement `handle_sync_request()`

### Step 6: Integrate with Service Startup

**File:** `igra-service/src/service/mod.rs` or startup code

1. Spawn anti-entropy loop as background task
2. Pass configuration from `AppConfig`
3. Share `known_peers` list with discovery mechanism

### Step 7: Add Configuration

**File:** `igra-core/src/infrastructure/config/mod.rs`

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AntiEntropyConfig {
    /// Enable anti-entropy sync (default: true)
    pub enabled: bool,
    /// Sync interval in seconds (default: 30)
    pub sync_interval_seconds: u64,
    /// Max event age in seconds (default: 3600)
    pub max_event_age_seconds: u64,
}

impl Default for AntiEntropyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sync_interval_seconds: 30,
            max_event_age_seconds: 3600,
        }
    }
}
```

### Step 8: Add Tests

**File:** `igra-core/tests/unit/anti_entropy_test.rs`

```rust
#[test]
fn test_digest_comparison() {
    // Test that digest correctly identifies missing/extra signatures
}

#[test]
fn test_sync_request_response() {
    // Test full request/response cycle
}

#[test]
fn test_bidirectional_sync() {
    // Test that both peers converge after sync
}
```

**File:** `igra-service/tests/integration/anti_entropy_e2e.rs`

```rust
#[tokio::test]
async fn test_offline_node_catches_up() {
    // 1. Start 3 nodes
    // 2. Stop node C
    // 3. Nodes A, B process event and reach threshold
    // 4. Restart node C
    // 5. Wait for anti-entropy sync
    // 6. Verify node C has all signatures
}

#[tokio::test]
async fn test_partition_recovery() {
    // 1. Start 5 nodes
    // 2. Partition: [A, B] and [C, D, E]
    // 3. Both partitions partially sign same event
    // 4. Heal partition
    // 5. Wait for anti-entropy
    // 6. Verify all nodes converge
}
```

---

## 6. Verification Checklist

- [ ] `StateSyncRequest` correctly summarizes local state
- [ ] `StateSyncResponse` includes missing events
- [ ] Bidirectional sync works (both sides update)
- [ ] Anti-entropy loop runs at configured interval
- [ ] Offline node catches up after restart
- [ ] Network partition recovery works
- [ ] Performance acceptable (sync completes in < 1 second)
- [ ] No duplicate signatures after sync
- [ ] Completed events not re-processed
- [ ] Logging shows sync activity

---

## 7. Tuning Guide

### Sync Interval

| Environment | Recommended Interval |
|-------------|---------------------|
| Development | 5-10 seconds |
| Testnet | 15-30 seconds |
| Mainnet | 30-60 seconds |

Lower interval = faster convergence, more bandwidth
Higher interval = slower convergence, less bandwidth

### Max Event Age

Keep events in digest for at least:
- `session_timeout_seconds * 2` (to catch stragglers)
- Or based on your business requirements for event validity

### Digest Size Limit

- 100 events is reasonable for most cases
- Each digest entry is ~72 bytes (two Hash32 + u32 + bool)
- 100 events = ~7KB per sync request

---

## 8. Monitoring

Add metrics for observability:

```rust
// In metrics module
pub struct AntiEntropyMetrics {
    pub sync_requests_sent: Counter,
    pub sync_responses_received: Counter,
    pub events_recovered: Counter,
    pub signatures_recovered: Counter,
    pub sync_latency_ms: Histogram,
}
```

Log format for sync events:

```
INFO anti-entropy sync completed peer={peer_id} events_sent={n} events_received={m} sigs_recovered={k} latency_ms={t}
```

---

*Document Version: 1.0*
*Created: 2026-01-13*
*Depends on: CRDT-IMPLEMENTATION-GUIDE.md*
