# FIXES_CRDT_GOSSIP_VALIDATION.md

Security and consistency fixes for CRDT gossip path.

---

## Problem Summary

Three related issues exist in the CRDT gossip path that can lead to:
1. **Security bypass**: Signing events without verifying source proof (Hyperlane/LayerZero signatures)
2. **DB inconsistency**: Volume tracking breaks for gossip-only events
3. **TX mismatch attack**: Signing a transaction that doesn't match the verified event

---

## Problem 1: Source Proof Not Verified on Gossip Path

### What Happens

When an event arrives via **local RPC** (from Hyperlane relayer):
```
RPC → submit_signing_event() → message_verifier.verify() → sign
```

When an event arrives via **CRDT gossip** (from another signer):
```
Gossip → handle_crdt_broadcast() → maybe_sign_and_broadcast() → sign
```

The gossip path **skips** `message_verifier.verify()`.

### Why This Is a Security Problem

A malicious peer could broadcast a fabricated event with:
- Fake Hyperlane message
- Invalid or missing ISM signatures
- Tampered amount/destination

Honest signers would sign this fabricated event because they trust the CRDT state without verifying the source proof themselves.

### Code Location

**Local RPC path** (`application/event_processor.rs:98`):
```rust
let report = ctx.message_verifier.verify(&stored_event)?;
if report.valid {
    // proceed to sign
} else {
    return Err(ThresholdError::EventSignatureInvalid);
}
```

**Gossip path** (`igra-service/src/service/coordination/crdt_handler.rs:340`):
```rust
// MISSING: message_verifier.verify() call
validate_before_signing(flow, &app_config.policy, &policy_event).await?;
// proceeds to sign without source verification
```

### The Fix

In `crdt_handler.rs`, before calling `sign_and_broadcast_local()`, add source proof verification:

```rust
// In maybe_sign_and_broadcast(), after reconstructing StoredEvent from CRDT:

// Verify source proof (Hyperlane ISM signatures, LayerZero endpoint signatures, etc.)
let message_verifier = flow.ctx.message_verifier.clone();
let report = message_verifier.verify(&stored_event)?;
if !report.valid {
    log::warn!(
        "gossip event failed source verification event_id={} reason={:?}",
        hex::encode(event_id),
        report.failure_reason
    );
    return Err(ThresholdError::EventSignatureInvalid);
}

// Now safe to sign
sign_and_broadcast_local(...).await?;
```

### Why This Fix Is Secure

1. **Same validation as RPC path**: Every signer independently verifies the source proof using the same `MessageVerifier` logic
2. **No trust in peers**: Signers don't trust that other peers verified correctly - each verifies for themselves
3. **Fail-safe**: If verification fails, the signer refuses to sign and logs a warning
4. **Audit trail**: Failed verifications can be audited

---

## Problem 2: StoredEvent Not Inserted for Gossip-Only Events

### What Happens

When an event arrives via **local RPC**:
```rust
// application/event_processor.rs:88
ctx.storage.insert_event(event_id, stored_event.clone())?;  // ✓ Inserted
ctx.storage.merge_event_crdt(&event_id, &tx_template_hash, ...)?;
```

When an event arrives via **CRDT gossip**:
```rust
// crdt_handler.rs
storage.merge_event_crdt(&event_id, &tx_template_hash, ...)?;
// insert_event() is NOT called
```

### Why This Is a Problem

Volume tracking depends on the `events` table:

```rust
// infrastructure/storage/rocks/engine.rs:502-504
pub fn mark_event_completed(...) {
    if let Some(event) = self.get_event(event_id)? {  // Returns None for gossip-only!
        self.add_to_daily_volume(event.event.amount_sompi, event.received_at_nanos)?;
    }
}
```

**Consequence**: If a signer only receives an event via gossip (their local relayer is down), the event amount is NOT added to daily volume. This means:
- Rate limiting can be bypassed
- Policy enforcement is incomplete
- Daily volume reports are incorrect

### Scenario

```
Time 0: Event E for 1000 KAS submitted
        - Signer-1: receives via RPC → insert_event() ✓ → volume tracked
        - Signer-2: receives via gossip only → NO insert_event() → volume NOT tracked

Time 1: Event completes, both signers call mark_event_completed()
        - Signer-1: get_event() returns Some → adds 1000 to volume ✓
        - Signer-2: get_event() returns None → volume unchanged ✗

Result: Signer-2's volume tracking is 1000 KAS lower than reality
```

### The Fix

In `crdt_handler.rs`, when processing gossip with `signing_material`, also insert the event:

```rust
// In handle_crdt_broadcast() or maybe_sign_and_broadcast():

if let Some(material) = &incoming_state.signing_material {
    // Reconstruct StoredEvent from CRDT material
    let stored_event = StoredEvent {
        event: material.event.clone(),
        audit: material.audit.clone(),
        proof: material.proof.clone(),
        received_at_nanos: now_nanos,
    };

    // Insert into events table (idempotent - won't overwrite if exists)
    // This ensures volume tracking works even for gossip-only events
    let _ = storage.insert_event_if_not_exists(event_id, stored_event);
}
```

**Note**: Use `insert_event_if_not_exists()` or similar idempotent operation to avoid overwriting if the event was already inserted via RPC.

### Why This Fix Is Correct

1. **Consistent state**: Both RPC and gossip paths result in the same DB state
2. **Idempotent**: If RPC already inserted, gossip won't overwrite
3. **Volume tracking works**: `get_event()` will return `Some` for all events
4. **No race conditions**: Both paths can run concurrently without issues

---

## Problem 3: TX Template Not Verified Against Event Data

### What Happens

When an event arrives via **local RPC**, the signer builds the PSKT themselves:
```rust
// application/event_processor.rs:200-204
let pskt_config = resolve_pskt_config(&ctx.config, &stored_event)?;  // Uses event's destination/amount
let (_selection, build) = build_pskt_from_rpc(ctx.rpc.as_ref(), &pskt_config).await?;
let kpsbt_blob = serialize_pskt(&signer_pskt)?;
let tx_template_hash = tx_template_hash(&signer_pskt)?;
```

By construction, the TX matches the event (destination, amount).

When an event arrives via **CRDT gossip**, the signer receives:
- `signing_material` - event data (destination_address, amount_sompi, proof)
- `kpsbt_blob` - pre-built transaction from another peer
- `tx_template_hash` - hash of the transaction

The signer does NOT verify that `kpsbt_blob` outputs match `signing_material`.

### Why This Is a Critical Security Problem

**Attack scenario**:
```
1. Attacker creates valid Hyperlane event: "send 100 KAS to Alice"
2. Attacker builds malicious TX: "send 100 KAS to Attacker"
3. Attacker computes tx_template_hash of malicious TX
4. Attacker broadcasts CRDT with:
   - signing_material: valid event (to Alice)
   - kpsbt_blob: malicious TX (to Attacker)
   - tx_template_hash: hash of malicious TX

5. Victim receives gossip:
   - Verifies Hyperlane proof → VALID ✓
   - Verifies policy → PASSES ✓
   - Signs kpsbt_blob → SIGNS MALICIOUS TX ✗

Result: Funds sent to attacker instead of Alice
```

The `tx_template_hash` doesn't help because attacker controls both the TX and its hash.

### Code Location

**RPC path** - TX built from event, matches by construction:
```rust
// event_processor.rs:200-204
let pskt_config = resolve_pskt_config(&ctx.config, &stored_event)?;
pskt_config.outputs = vec![PsktOutput {
    address: event.audit.destination_raw.clone(),  // From event
    amount_sompi: event.event.amount_sompi          // From event
}];
let (_selection, build) = build_pskt_from_rpc(ctx.rpc.as_ref(), &pskt_config).await?;
```

**Gossip path** - TX received, NOT verified against event:
```rust
// crdt_handler.rs (conceptual)
let kpsbt_blob = stored_crdt.kpsbt_blob;  // Received from peer
// NO VERIFICATION that kpsbt_blob outputs match signing_material
sign_pskt(deserialize(kpsbt_blob), &keypair)?;  // Signs whatever was received
```

### The Fix

**Option A: Rebuild TX locally (recommended)**

Each signer rebuilds the TX from event data and verifies hash matches:

```rust
// In maybe_sign_and_broadcast():

// 1. Rebuild PSKT from event data (same as RPC path)
let pskt_config = resolve_pskt_config(&config.service, &stored_event)?;
let (_selection, build) = build_pskt_from_rpc(rpc.as_ref(), &pskt_config).await?;
let local_pskt = to_signer(build.pskt);
let local_tx_hash = tx_template_hash(&local_pskt)?;

// 2. Verify hash matches what we received
if local_tx_hash != *tx_template_hash {
    log::warn!(
        "tx_template_hash mismatch: local={} received={} event_id={}",
        hex::encode(local_tx_hash),
        hex::encode(tx_template_hash),
        hex::encode(event_id)
    );
    return Err(ThresholdError::PsktMismatch);
}

// 3. Sign our locally-built TX (not the received one)
let signed = sign_pskt(local_pskt, &keypair)?;
```

**Option B: Verify outputs in received PSKT**

Parse received TX and verify outputs match event:

```rust
// In maybe_sign_and_broadcast():

let received_pskt = deserialize_pskt_signer(&kpsbt_blob)?;

// Verify outputs match event
let outputs = &received_pskt.pskt().outputs;
if outputs.len() != 1 {
    return Err(ThresholdError::Message("unexpected output count".to_string()));
}

let expected_address = Address::try_from(material.audit.destination_raw.as_str())?;
let actual_address = &outputs[0].script_public_key;
if !address_matches_script(&expected_address, actual_address) {
    log::warn!(
        "output address mismatch: expected={} actual={:?}",
        material.audit.destination_raw,
        actual_address
    );
    return Err(ThresholdError::Message("tx output address mismatch".to_string()));
}

if outputs[0].value != material.event.amount_sompi {
    log::warn!(
        "output amount mismatch: expected={} actual={}",
        material.event.amount_sompi,
        outputs[0].value
    );
    return Err(ThresholdError::Message("tx output amount mismatch".to_string()));
}
```

### Recommended Approach: Option A

Option A (rebuild TX locally) is preferred because:
1. **Deterministic**: Same inputs → same TX (if RPC returns consistent UTXOs)
2. **Defense in depth**: No parsing of untrusted data
3. **Simpler**: Reuse existing `build_pskt_from_rpc()` logic
4. **Catches more issues**: Verifies entire TX, not just outputs

### Why This Fix Is Secure

1. **No trust in received TX**: Each signer builds TX independently from verified event data
2. **Hash commitment**: `tx_template_hash` commits to entire TX including outputs
3. **Consensus on TX**: All honest signers compute same hash from same event → they agree or reject
4. **Attacker cannot forge**: Changing any output changes hash, causing mismatch

### Edge Case: UTXO Set Divergence

If signers see different UTXO sets (node sync lag), they may build different TXs:
- Signer-1 sees UTXOs {A, B} → builds TX-1 with inputs A,B
- Signer-2 sees UTXOs {A, B, C} → builds TX-2 with inputs A,B,C

This causes `tx_template_hash` mismatch, which is **correct behavior**:
- Signers should not sign TXs they can't verify
- Retry after nodes sync

This is already handled by `set_event_active_template_hash()` which locks in the first hash.

---

## Combined Fix Location

All three fixes should be applied in `igra-service/src/service/coordination/crdt_handler.rs`, in the `maybe_sign_and_broadcast()` function:

```rust
async fn maybe_sign_and_broadcast(
    flow: &CoordinationFlow,
    event_id: &Hash32,
    tx_template_hash: &Hash32,
) -> Result<(), ThresholdError> {
    let storage = flow.ctx.storage.clone();
    let stored_crdt = storage.get_event_crdt(event_id, tx_template_hash)?
        .ok_or_else(|| ThresholdError::Message("missing CRDT state".to_string()))?;

    // Extract signing material
    let material = stored_crdt.signing_material.as_ref()
        .ok_or_else(|| ThresholdError::Message("missing signing material in CRDT".to_string()))?;

    let now_nanos = crate::foundation::now_nanos();

    // FIX 2: Ensure event is in events table for volume tracking
    let stored_event = StoredEvent {
        event: material.event.clone(),
        audit: material.audit.clone(),
        proof: material.proof.clone(),
        received_at_nanos: now_nanos,
    };
    storage.insert_event_if_not_exists(*event_id, stored_event.clone())?;

    // FIX 1: Verify source proof before signing
    let report = flow.ctx.message_verifier.verify(&stored_event)?;
    if !report.valid {
        log::warn!(
            "gossip event failed source verification event_id={} reason={:?}",
            hex::encode(event_id),
            report.failure_reason
        );
        return Err(ThresholdError::EventSignatureInvalid);
    }

    // Existing policy validation
    validate_before_signing(flow, &app_config.policy, &policy_event).await?;

    // FIX 3: Rebuild TX locally and verify hash matches
    let pskt_config = resolve_pskt_config(&flow.config.service, &stored_event)?;
    let (_selection, build) = build_pskt_from_rpc(flow.ctx.rpc.as_ref(), &pskt_config).await?;
    let local_pskt = to_signer(build.pskt);
    let local_tx_hash = tx_template_hash(&local_pskt)?;

    if local_tx_hash != *tx_template_hash {
        log::warn!(
            "tx_template_hash mismatch: local={} received={} event_id={}",
            hex::encode(local_tx_hash),
            hex::encode(tx_template_hash),
            hex::encode(event_id)
        );
        return Err(ThresholdError::PsktMismatch);
    }

    // Sign our locally-built TX (not the received kpsbt_blob)
    sign_and_broadcast_local(flow, event_id, &local_tx_hash, &local_pskt).await
}
```

**Key point**: We sign `local_pskt` (built from verified event), NOT the received `kpsbt_blob`.

---

## Storage Interface Change

Add to `Storage` trait:

```rust
/// Insert event only if it doesn't already exist.
/// Returns Ok(true) if inserted, Ok(false) if already existed.
fn insert_event_if_not_exists(&self, event_id: Hash32, event: StoredEvent) -> Result<bool, ThresholdError>;
```

Implementation in `rocks/engine.rs`:

```rust
fn insert_event_if_not_exists(&self, event_id: Hash32, event: StoredEvent) -> Result<bool, ThresholdError> {
    if self.get_event(&event_id)?.is_some() {
        return Ok(false);  // Already exists
    }
    self.insert_event(event_id, event)?;
    Ok(true)
}
```

---

## Testing

### Test Case 1: Gossip-Only Event Verification

```
1. Signer-1 receives valid event via RPC, signs, broadcasts CRDT
2. Signer-2 receives CRDT gossip (no local RPC)
3. Verify: Signer-2 calls message_verifier.verify() before signing
4. Verify: Signer-2 has event in events table
5. Complete transaction
6. Verify: Both signers have same daily volume
```

### Test Case 2: Malicious Gossip Rejection

```
1. Attacker broadcasts CRDT with invalid Hyperlane proof
2. Honest signer receives gossip
3. Verify: message_verifier.verify() returns invalid
4. Verify: Signer does NOT sign
5. Verify: Warning logged
```

### Test Case 3: Volume Consistency

```
1. Set daily limit to 10000 KAS
2. Process 5 events of 2000 KAS each via gossip only
3. Verify: Daily volume is 10000 KAS
4. Verify: 6th event rejected by rate limiting
```

### Test Case 4: Malicious TX Rejection

```
1. Attacker creates valid event: "send 100 KAS to Alice"
2. Attacker builds TX: "send 100 KAS to Attacker"
3. Attacker broadcasts CRDT with mismatched event/TX
4. Honest signer receives gossip
5. Verify: Signer rebuilds TX locally from event data
6. Verify: tx_template_hash mismatch detected
7. Verify: Signer does NOT sign
8. Verify: PsktMismatch error returned
```

### Test Case 5: Normal Gossip Flow Works

```
1. Signer-1 receives valid event via RPC
2. Signer-1 builds TX, signs, broadcasts CRDT
3. Signer-2 receives CRDT via gossip
4. Verify: Signer-2 rebuilds TX from event
5. Verify: tx_template_hash matches
6. Verify: Signer-2 signs successfully
7. Transaction completes
```

---

## Security Analysis

| Attack Vector | Before Fix | After Fix |
|---------------|------------|-----------|
| Fabricated event via gossip | Signed without verification | Rejected by source proof check |
| Tampered amount in signing_material | Signed with wrong amount | Rejected - proof won't match |
| Rate limit bypass via gossip | Volume not tracked | Volume tracked correctly |
| Inconsistent state between signers | Possible | Consistent via insert_if_not_exists |
| Malicious TX with valid event | Signed wrong TX | Rejected - local TX hash differs |
| TX outputs don't match event | Funds sent to attacker | Rejected - rebuild TX from event |

---

## Files to Modify

| File | Change |
|------|--------|
| `igra-service/src/service/coordination/crdt_handler.rs` | Add verification, insert_event, and TX rebuild logic |
| `igra-core/src/infrastructure/storage/traits.rs` | Add `insert_event_if_not_exists()` |
| `igra-core/src/infrastructure/storage/rocks/engine.rs` | Implement `insert_event_if_not_exists()` |
| `igra-core/src/application/event_processor.rs` | Export `resolve_pskt_config()` for reuse |

### New Imports Needed in crdt_handler.rs

```rust
use crate::application::event_processor::resolve_pskt_config;
use crate::infrastructure::rpc::kaspa_integration::build_pskt_from_rpc;
use crate::domain::pskt::multisig::{to_signer, tx_template_hash};
```

---

*Generated: 2025-01-13*
