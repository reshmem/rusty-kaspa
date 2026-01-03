# Kaspa Threshold Signing Coordination Spec

**Status:** Draft v0.3  
**Target stack:** `rusty-kaspa-wallet v1.0+` (embedded per signer) + `rusty-kaspa v1.0+` node + Iroh (gossip/pubsub)  
**Official SDK:** rusty-kaspa v1.x (Kaspa official node and wallet implementation)  
**Signing backends:** (A) Multisig (m-of-n) → (B) FROST MPC (m-of-n) → (C) MuSig2 (n-of-n)  
**Implementation sequence:** Multisig first, then FROST MPC, then MuSig2  
**Event sources:** Cross-chain bridges (Hyperlane, LayerZero), oracles, APIs

---

## 1. Scope

**Official SDK:** This specification is built on **rusty-kaspa v1.x**, the official production-ready Kaspa implementation maintained by the Kaspa core team. All node and wallet operations leverage rusty-kaspa v1.x APIs.

This document specifies a **signing coordination protocol** for Kaspa that:
- Processes **abstract signing events** from multiple sources (cross-chain bridges, oracles, APIs) containing `{destination_address, amount, metadata}`.
- Converts signing events into **fully signed Kaspa transactions** using a threshold group.
- Supports three interchangeable signing modes:
  1) **Multisig (m-of-n)** - threshold enforced by script/spend conditions
  2) **FROST MPC (m-of-n)** - threshold enforced by 3rd party MPC library (black box)
  3) **MuSig2 (n-of-n)** - all signers required, produces single aggregate signature (3rd party lib)

**Implementation roadmap:**
1. **Phase 1:** Multisig (m-of-n) - establishes coordination layer, event model, embedded wallet integration
2. **Phase 2:** FROST MPC (m-of-n) - adds flexible threshold with 3rd party MPC (e.g., Sodot)
3. **Phase 3:** MuSig2 (n-of-n) - adds efficient n-of-n with 3rd party lib (e.g., secp256k1-zkp)

**Key properties:**
- **secp256k1 Schnorr signatures** for Kaspa keys
- **MPC/MuSig2 as black-box** - all cryptographic protocols handled by external libraries
- Each signer runs **embedded rusty-kaspa-wallet** to independently construct and validate transactions
- **P2P pubsub** (Iroh gossip) for coordination
- **PSBT-like packaging** with Kaspa extensions
- **Event replay protection** with persistent storage

**Key abstraction:** Signing events are source-agnostic; signers agree on `{destination, amount, event_id}`, then independently construct **identical Kaspa transactions** using embedded wallets.

---

## 2. Goals

1. **Source-agnostic event processing:** Ethereum (Hyperlane/LayerZero), Cosmos IBC, APIs, manual triggers
2. **Signer autonomy:** Each signer independently constructs Kaspa TX from event using embedded wallet + validates against local node
3. **MPC library agnosticism:** FROST (or other MPC) is pluggable black-box
4. **Minimal trust:** Any signer may coordinate; protocol remains correct under coordinator failure
5. **Replay resistance:** Prevent re-processing of events and double-signing
6. **Deterministic TX construction:** All signers construct identical Kaspa transactions from same event

---

## 3. Non-goals

- Wallet UX, policy UI, human approval flows (integrations on top)
- Transaction intent confidentiality beyond transport encryption
- **MPC/MuSig2 implementation details** (nonces, rounds, aggregation - delegated to 3rd party libraries)
- DKG/key generation (handled by MPC/MuSig2 libraries)
- On-chain multisig script design
- Event source monitoring (bridge listeners, oracle clients)

---

## 4. Entities and Trust Model

### 4.1 Roles
**Signer:** Holds signing share/key. Runs:
- **Embedded rusty-kaspa-wallet** (deterministic TX construction)
- Local kaspa node (validation, UTXO queries, broadcast)
- Coordination agent (Iroh pubsub)
- Local persistence (anti-replay + audit)
- MPC library client (FROST mode - e.g., Sodot SDK)
- MuSig2 library client (MuSig2 mode - e.g., secp256k1-zkp, libsecp256k1-rs with MuSig2 module)

**Coordinator (ephemeral):** Any signer who initiates session:
- Receives abstract signing event (from bridge, oracle, API)
- Proposes event for group processing
- Collects validations, partial sigs / MPC outputs
- Finalises and broadcasts

**Event Source (external):** Hyperlane relayer, LayerZero endpoint, API gateway
- Produces: `SigningEvent { event_id, destination, amount, metadata }`
- Untrusted by default

### 4.2 Trust assumptions
Signers trust:
- Own embedded wallet's deterministic TX construction
- Own node's consensus state (UTXO set, DAG, blue score)
- Local policy (threshold, allowlist, limits)
- **MPC library correctness** (for FROST - e.g., Sodot)
- **MuSig2 library correctness** (for MuSig2 - e.g., secp256k1-zkp)

Signers do NOT trust:
- Event sources (must validate authenticity + policy)
- Coordinator (verify all artifacts locally)
- Other signers' TX construction (must match own wallet's output)

---

## 5. Group Identity and Topics (Iroh Gossip)

### 5.1 Group Topic (static)
Long-lived topic for controlling group:
- **GroupTopicId** = `BLAKE3("kaspa-sign/v1" || network_id || group_id)`
- `network_id`: 0=mainnet, 1=testnet, 2=devnet, 3=simnet
- `group_id`: **Deterministic hash of group configuration** (see §5.1.1)

**Purpose:** Announce sign requests, publish policy updates, session discovery

#### 5.1.1 Group ID Derivation

**Group ID is a deterministic hash of group configuration:**

```rust
group_id = BLAKE3(
    threshold_m ||
    threshold_n ||
    sorted(pubkeys[]) ||           // Sorted lexicographically
    protocol_type ||               // "multisig" | "frost" | "musig2"
    network_id ||
    fee_payment_mode ||            // V1: part of group identity (immutable)
    finality_blue_score_threshold || // V1: constant, part of group identity
    group_metadata
)

struct GroupMetadata {
    creation_timestamp: u64,       // Unix nanos
    group_name: Option<String>,    // Human-readable identifier
    policy_version: u32,           // Policy schema version (V1 = 1)
    fee_rate_sompi_per_gram: u64,  // V1: static fee rate (immutable)
    dust_threshold_sompi: u64,     // V1: minimum output value
    min_recipient_amount_sompi: u64, // V1: minimum payment amount
    session_timeout_seconds: u64,  // V1: timeout for signing sessions
    extra: Map<String, Value>,     // Extensible metadata
}
```

**Example computation:**
```rust
fn compute_group_id(config: &GroupConfig) -> Hash {
    let mut hasher = Blake3Hasher::new();
    
    // Threshold
    hasher.update(&config.threshold_m.to_le_bytes());
    hasher.update(&config.threshold_n.to_le_bytes());
    
    // Sorted public keys (deterministic)
    let mut pubkeys = config.pubkeys.clone();
    pubkeys.sort();  // Lexicographic sort
    for pubkey in &pubkeys {
        hasher.update(pubkey.as_bytes());
    }
    
    // Protocol type
    let protocol_bytes = match config.protocol {
        Protocol::Multisig => b"multisig",
        Protocol::Frost => b"frost",
        Protocol::MuSig2 => b"musig2",
    };
    hasher.update(protocol_bytes);
    
    // Network
    hasher.update(&[config.network_id]);
    
    // Fee payment mode (V1: immutable)
    let fee_mode_bytes = match config.fee_payment_mode {
        FeePaymentMode::RecipientPays => b"recipient_pays",
        FeePaymentMode::SignersPay => b"signers_pay",
        FeePaymentMode::Split { recipient_portion } => {
            hasher.update(b"split");
            hasher.update(&recipient_portion.to_le_bytes());
            b""
        },
        _ => b"recipient_pays",
    };
    hasher.update(fee_mode_bytes);
    
    // Finality threshold (V1: immutable)
    hasher.update(&config.finality_blue_score_threshold.to_le_bytes());
    
    // Metadata (canonical binary encoding)
    let metadata_bytes = serialize_metadata_canonical(&config.metadata)?;
    hasher.update(&metadata_bytes);
    
    hasher.finalize()
}
```

**V1 Immutable Parameters (part of group_id):**
- Threshold (m, n)
- Public keys (sorted list)
- Protocol type (multisig, frost, musig2)
- Network ID
- **Fee payment mode** (RecipientPays, SignersPay, Split)
- **Finality threshold** (blue score confirmations)
- **Static fee rate** (sompi per gram)
- **Dust threshold** (minimum output value)
- **Minimum recipient amount**
- **Session timeout**

**Properties:**
- **Deterministic:** Same config → same group_id
- **Unique:** Different configs → different group_id (with high probability)
- **Binding:** group_id commits to all immutable parameters
- **Immutable:** Changing any parameter requires new group_id (new group, fund movement)

**Use cases:**
- Multi-protocol support: Same pubkeys, different protocols → different group_ids
- Protocol migration: Multisig → FROST → MuSig2 requires new group
- Threshold changes: 3-of-5 → 4-of-5 requires new group
- Member rotation: Add/remove pubkeys requires new group
- Fee policy changes: RecipientPays → SignersPay requires new group (V1 limitation)

**V1 Limitation:** All parameters are immutable. Future versions may support policy updates without group migration.

### 5.2 Session Topic (ephemeral)
Per-signing-request session:
- **SessionId** = `BLAKE3(GroupTopicId || request_id || coordinator_peer_id || timestamp)`
- **SessionTopicId** = `BLAKE3("kaspa-sign/session/v1" || SessionId)`

**Purpose:** Exchange KPSBT, validations, partial sigs, finalisation

---

## 6. Abstract Signing Event Model

### 6.1 SigningEvent structure

Source-agnostic event representation:

```rust
struct SigningEvent {
    event_id: Hash,              // Globally unique, source-specific
    event_source: EventSource,   // Origin identifier
    destination: String,         // Kaspa address (bech32m)
    amount: u64,                 // sompi (1 KAS = 10^8 sompi)
    metadata: EventMetadata,     // Source-specific context
    timestamp: u64,              // Unix nanos
    signature: Vec<u8>,          // Optional: source auth
}

enum EventSource {
    Hyperlane { chain_id: u32, contract: Address, message_id: Hash },
    LayerZero { chain_id: u16, endpoint: Address, nonce: u64 },
    CosmosIBC { channel: String, sequence: u64 },
    API { endpoint: String, request_id: UUID },
    Manual { operator: PublicKey },
}

struct EventMetadata {
    source_tx_hash: Option<Hash>,
    memo: Option<String>,
    priority: u8,
    extra: Map<String, Value>,
}
```

### 6.2 Event validation requirements

Each signer MUST validate:
1. **Authenticity:** Verify `event_source` signature (if applicable)
2. **Uniqueness:** Check `event_id` not seen (replay protection)
3. **Policy compliance:**
   - `destination` in allowlist
   - `amount` within per-tx and velocity limits
   - `event_source` authorized
4. **Format validity:** `destination` is valid Kaspa address for network

### 6.3 Deterministic transaction construction

Each signer's embedded rusty-kaspa-wallet produces **identical** Kaspa transactions:

**Input selection (deterministic):**
```
1. Query wallet UTXO set
2. Sort UTXOs: (amount DESC, age DESC) - deterministic order
3. Greedy select until amount + fee covered
4. Reject if insufficient funds
```

**Transaction template construction:**

**Phase 1 (Single-recipient):**
See §6B.2 for detailed single-recipient transaction construction with fee payment modes.

```rust
tx = Transaction {
    version: 0,
    inputs: selected_utxos.map(|u| TxInput { 
        previous_outpoint: u.outpoint,
        signature_script: empty,
        sequence: MAX_SEQUENCE,
        sig_op_count: 1,
    }),
    outputs: [
        TxOutput {  // Payment to recipient
            value: event.amount - fee (if RecipientPays) or event.amount (if SignersPay),
            script_public_key: address_to_script_pubkey(event.destination),
        },
        TxOutput {  // Change back to signers
            value: total_input - event.amount (if RecipientPays) 
                   or total_input - event.amount - fee (if SignersPay),
            script_public_key: wallet.group_script_pubkey(),
        }
    ],
    lock_time: 0,
    subnetwork_id: SUBNETWORK_ID_NATIVE,
    gas: 0,
    payload: event.metadata.memo.unwrap_or_default().as_bytes(),
}
```

**Phase 2 (Multi-recipient):**
See §6B.3 for multi-recipient transaction construction.

**Critical:** All signers must use identical:
- UTXO selection algorithm
- Fee calculation method (including fee payment mode)
- Change address derivation
- Output ordering (recipients first, then change)
- Field ordering

### 6.4 Event-to-TX binding

Binds abstract event to constructed transaction:

```
event_hash = BLAKE3(
    event.event_id ||
    event.event_source (canonical) ||
    event.destination ||
    event.amount ||
    event.metadata (canonical) ||
    event.timestamp
)
```

Primary replay protection identifier.

---

## 6B. Transaction Output Modes

### 6B.1 Overview

The protocol supports multiple transaction output configurations. **Implementation is phased:**

**Phase 1 (Initial):** Single-recipient mode
- One event → One Kaspa transaction → One recipient address
- Simple, predictable, minimal validation complexity

**Phase 2 (Advanced):** Multi-recipient mode
- One event → One Kaspa transaction → Multiple recipient addresses
- Batch payments, complex routing, conditional outputs

### 6B.2 Single-Recipient Mode (Phase 1 - Initial Implementation)

**Event structure:**
```rust
struct SigningEvent {
    event_id: Hash,
    event_source: EventSource,
    destination: String,        // Single Kaspa address (bech32m)
    amount: u64,                // Amount to recipient (sompi)
    metadata: EventMetadata,
    timestamp: u64,
    signature: Vec<u8>,
}

struct EventMetadata {
    source_tx_hash: Option<Hash>,
    memo: Option<String>,
    priority: u8,
    fee_payment_mode: FeePaymentMode,  // NEW: Who pays fees
    extra: Map<String, Value>,
}

enum FeePaymentMode {
    RecipientPays,   // Fee deducted from recipient amount (default Phase 1)
    SignersPay,      // Fee paid by signers (change output reduced)
    Split { recipient_portion: f64 },  // Split fee (e.g., 50/50)
}
```

**Transaction construction (deterministic):**

```rust
fn construct_single_recipient_tx(
    event: &SigningEvent,
    selected_utxos: &[Utxo],
    wallet_config: &WalletConfig,
) -> Result<Transaction> {
    let total_input = selected_utxos.iter().sum::<u64>();
    let fee = estimate_fee(selected_utxos.len(), 2)?; // 2 outputs expected
    
    // Compute output amounts based on fee payment mode
    let (recipient_amount, change_amount) = match event.metadata.fee_payment_mode {
        FeePaymentMode::RecipientPays => {
            // Recipient receives: event.amount - fee
            // Signers receive: total_input - event.amount (full refund)
            let recipient_net = event.amount.checked_sub(fee)
                .ok_or(Error::InsufficientAmount)?;
            let change = total_input.checked_sub(event.amount)
                .ok_or(Error::InsufficientFunds)?;
            (recipient_net, change)
        },
        FeePaymentMode::SignersPay => {
            // Recipient receives: event.amount (full amount)
            // Signers receive: total_input - event.amount - fee
            let change = total_input.checked_sub(event.amount + fee)
                .ok_or(Error::InsufficientFunds)?;
            (event.amount, change)
        },
        FeePaymentMode::Split { recipient_portion } => {
            // Split fee proportionally
            let recipient_fee = (fee as f64 * recipient_portion) as u64;
            let signer_fee = fee - recipient_fee;
            let recipient_net = event.amount.checked_sub(recipient_fee)
                .ok_or(Error::InsufficientAmount)?;
            let change = total_input.checked_sub(event.amount + signer_fee)
                .ok_or(Error::InsufficientFunds)?;
            (recipient_net, change)
        },
    };
    
    // Construct outputs
    let mut outputs = vec![
        TxOutput {  // Output 0: Recipient
            value: recipient_amount,
            script_public_key: address_to_script_pubkey(&event.destination)?,
        }
    ];
    
    // Output 1: Change back to signers (if non-dust)
    if change_amount >= DUST_THRESHOLD {
        outputs.push(TxOutput {
            value: change_amount,
            script_public_key: wallet_config.group_script_pubkey.clone(),
        });
    }
    
    Ok(Transaction {
        version: 0,
        inputs: selected_utxos_to_inputs(selected_utxos),
        outputs,
        lock_time: 0,
        subnetwork_id: SUBNETWORK_ID_NATIVE,
        gas: 0,
        payload: event.metadata.memo.unwrap_or_default().as_bytes().to_vec(),
    })
}
```

**Example: RecipientPays (default Phase 1)**
```
UTXO total:           100.0 KAS
Event amount:          50.0 KAS
Estimated fee:          0.001 KAS
---
Output[0] (recipient): 49.999 KAS  (50.0 - 0.001 fee)
Output[1] (change):    50.0 KAS    (back to signers)
---
Total out:             99.999 KAS
Fee to miners:          0.001 KAS
```

**Example: SignersPay**
```
UTXO total:           100.0 KAS
Event amount:          50.0 KAS
Estimated fee:          0.001 KAS
---
Output[0] (recipient): 50.0 KAS    (full amount)
Output[1] (change):    49.999 KAS  (100 - 50 - 0.001 fee)
---
Total out:             99.999 KAS
Fee to miners:          0.001 KAS
```

**Validation rules (all signers must agree):**
- Output[0] destination matches `event.destination`
- Output[0] amount calculation matches `fee_payment_mode`
- Output[1] (if present) destination matches group script pubkey
- Output[1] amount is correct change calculation
- Total outputs + fee == total inputs
- Fee is reasonable (within configured bounds)

### 6B.3 Multi-Recipient Mode (Phase 2 - Advanced Implementation)

**Event structure (extended):**
```rust
struct SigningEventMulti {
    event_id: Hash,
    event_source: EventSource,
    recipients: Vec<Recipient>,  // Multiple recipients
    metadata: EventMetadata,
    timestamp: u64,
    signature: Vec<u8>,
}

struct Recipient {
    address: String,             // Kaspa address (bech32m)
    amount: u64,                 // Amount to this recipient (sompi)
    memo: Option<String>,        // Per-recipient memo
}

struct EventMetadata {
    source_tx_hash: Option<Hash>,
    global_memo: Option<String>,
    priority: u8,
    fee_payment_mode: FeePaymentMode,
    max_recipients: u16,         // Policy: max recipients per TX (e.g., 10)
    extra: Map<String, Value>,
}
```

**Transaction construction (multi-recipient):**
```rust
fn construct_multi_recipient_tx(
    event: &SigningEventMulti,
    selected_utxos: &[Utxo],
    wallet_config: &WalletConfig,
) -> Result<Transaction> {
    // Validate recipient count
    if event.recipients.len() > event.metadata.max_recipients {
        return Err(Error::TooManyRecipients);
    }
    
    let total_input = selected_utxos.iter().sum::<u64>();
    let total_recipient_amount = event.recipients.iter()
        .map(|r| r.amount)
        .sum::<u64>();
    
    // Estimate fee for n+1 outputs (n recipients + 1 change)
    let fee = estimate_fee(selected_utxos.len(), event.recipients.len() + 1)?;
    
    // Compute amounts based on fee payment mode
    let (recipient_amounts, change_amount) = match event.metadata.fee_payment_mode {
        FeePaymentMode::RecipientPays => {
            // Fee split proportionally among recipients
            let mut adjusted_amounts = Vec::new();
            let mut total_adjusted = 0u64;
            
            for recipient in &event.recipients {
                let proportion = recipient.amount as f64 / total_recipient_amount as f64;
                let recipient_fee = (fee as f64 * proportion) as u64;
                let net_amount = recipient.amount.checked_sub(recipient_fee)
                    .ok_or(Error::InsufficientAmount)?;
                adjusted_amounts.push(net_amount);
                total_adjusted += net_amount;
            }
            
            let change = total_input.checked_sub(total_recipient_amount)
                .ok_or(Error::InsufficientFunds)?;
            (adjusted_amounts, change)
        },
        FeePaymentMode::SignersPay => {
            // Recipients receive full amounts, signers pay fee
            let amounts: Vec<u64> = event.recipients.iter()
                .map(|r| r.amount)
                .collect();
            let change = total_input.checked_sub(total_recipient_amount + fee)
                .ok_or(Error::InsufficientFunds)?;
            (amounts, change)
        },
        FeePaymentMode::Split { recipient_portion } => {
            // Complex split - left as exercise
            todo!("Implement split fee mode for multi-recipient")
        },
    };
    
    // Construct outputs: recipients first, then change
    let mut outputs: Vec<TxOutput> = event.recipients.iter()
        .zip(recipient_amounts.iter())
        .map(|(recipient, &amount)| {
            Ok(TxOutput {
                value: amount,
                script_public_key: address_to_script_pubkey(&recipient.address)?,
            })
        })
        .collect::<Result<_>>()?;
    
    // Add change output (if non-dust)
    if change_amount >= DUST_THRESHOLD {
        outputs.push(TxOutput {
            value: change_amount,
            script_public_key: wallet_config.group_script_pubkey.clone(),
        });
    }
    
    Ok(Transaction {
        version: 0,
        inputs: selected_utxos_to_inputs(selected_utxos),
        outputs,
        lock_time: 0,
        subnetwork_id: SUBNETWORK_ID_NATIVE,
        gas: 0,
        payload: event.metadata.global_memo.unwrap_or_default().as_bytes().to_vec(),
    })
}
```

**Example: Multi-recipient with RecipientPays**
```
UTXO total:           200.0 KAS
Recipients:
  - Alice:             50.0 KAS (25% of total)
  - Bob:               75.0 KAS (37.5% of total)
  - Charlie:           75.0 KAS (37.5% of total)
Estimated fee:          0.003 KAS
---
Output[0] (Alice):     49.9993 KAS  (50.0 - 0.00075 fee)
Output[1] (Bob):       74.9989 KAS  (75.0 - 0.001125 fee)
Output[2] (Charlie):   74.9989 KAS  (75.0 - 0.001125 fee)
Output[3] (change):    0.0 KAS      (200 - 200 = 0, no change)
---
Total out:            199.997 KAS
Fee to miners:          0.003 KAS
```

**Validation rules (extended):**
- Output count matches `recipients.len() + 1` (or `recipients.len()` if no change)
- Each output[i] destination matches `recipients[i].address`
- Each output[i] amount matches fee-adjusted calculation
- Last output (if non-dust) is change back to group
- Total outputs + fee == total inputs
- Recipient count <= policy max_recipients

### 6B.4 Fee Payment Configuration

Fee payment is determined by `fee_payment_mode` in event metadata. **Signers must agree** on fee payment policy before accepting event.

**Policy configuration (per group):**
```rust
struct FeePolicy {
    default_mode: FeePaymentMode,
    allow_recipient_pays: bool,      // Allow recipients to pay fees
    allow_signers_pay: bool,         // Allow signers to pay fees
    allow_split: bool,               // Allow split fee payments
    max_fee_rate: u64,               // sompi per gram (sanity check)
    require_consensus_on_mode: bool, // All signers must approve fee mode
}
```

**Signer validation:**
```rust
fn validate_fee_payment_mode(
    event: &SigningEvent,
    policy: &FeePolicy,
) -> Result<()> {
    match event.metadata.fee_payment_mode {
        FeePaymentMode::RecipientPays if !policy.allow_recipient_pays => {
            Err(Error::FeePaymentModeNotAllowed)
        },
        FeePaymentMode::SignersPay if !policy.allow_signers_pay => {
            Err(Error::FeePaymentModeNotAllowed)
        },
        FeePaymentMode::Split { .. } if !policy.allow_split => {
            Err(Error::FeePaymentModeNotAllowed)
        },
        _ => Ok(())
    }
}
```

**Use cases:**
- **RecipientPays:** Bridge withdrawals (user pays fee to receive funds)
- **SignersPay:** Airdrop, treasury distributions (signers cover costs)
- **Split:** Hybrid scenarios (e.g., large amounts, split fee 50/50)

### 6B.5 Implementation Phases

**Phase 1 (Immediate):**
- Single-recipient mode only
- `FeePaymentMode::RecipientPays` as default
- Simple validation: 2 outputs (recipient + change)
- Event structure: `SigningEvent` with single `destination` + `amount`

**Phase 2 (After Phase 1 stable):**
- Multi-recipient mode
- All fee payment modes (RecipientPays, SignersPay, Split)
- Extended validation: n+1 outputs
- Event structure: `SigningEventMulti` with `recipients[]`
- Policy: max recipients limit (e.g., 10 per TX)

**Migration path:**
- `SigningEvent` (Phase 1) can be viewed as `SigningEventMulti` with `recipients.len() == 1`
- Coordination layer supports both event types
- Signers must upgrade to support multi-recipient before accepting such events

### 6B.6 KPSBT extensions for multi-recipient

**KPSBT global fields (extended in Phase 2):**
```rust
kpsbt.signing_event_type: enum { Single, Multi }
kpsbt.recipients: Vec<Recipient>  // For Multi type
kpsbt.fee_payment_mode: FeePaymentMode
```

**KPSBT per-output fields (new in Phase 2):**
```rust
struct KpsbtOutput {
    output_index: u32,
    output_type: enum { Recipient, Change },
    recipient_index: Option<u32>,  // If Recipient type
    expected_amount: u64,          // For validation
    expected_script_pubkey: ScriptPublicKey,
}
```

---

## 7. PSBT Adaptation: KPSBT (Kaspa-PSBT)

### 7.1 Overview

KPSBT adopts **Bitcoin's PSBT (Partially Signed Bitcoin Transaction) format** from BIP 174, with Kaspa-specific extensions using proprietary keys.

**Why PSBT instead of CBOR:**
- **Wallet compatibility:** Existing wallets (rusty-kaspa, hardware wallets) already support PSBT parsing
- **Hardware wallet support:** Ledger, Trezor, and other HW wallets have PSBT implementations
- **Proven format:** 5+ years in Bitcoin production, battle-tested, security audited
- **Existing tooling:** PSBT explorers, debuggers, validators, libraries (rust-bitcoin)
- **Developer familiarity:** Bitcoin developers already know PSBT internals
- **Less implementation work:** Reuse existing code vs building CBOR from scratch

**PSBT structure (BIP 174):**
- Unsigned transaction template (from SigningEvent)
- Per-input metadata required to sign
- Per-output metadata
- Key-value map format with extensibility
- Incremental partial signatures (multisig) or MPC session reference (FROST/MuSig2)

**KPSBT format:**
```
Magic bytes: 0x6B 0x70 0x73 0x62 0x74 0xFF  ("kpsbt" + separator)
Global map (key-value pairs)
0x00 separator
Input map 0 (key-value pairs)
0x00 separator
Input map 1 (key-value pairs)
...
0x00 separator
Output map 0 (key-value pairs)
0x00 separator
Output map 1 (key-value pairs)
...
```

**Key-value encoding (BIP 174):**
```
<key_length: varint> <key_type: 1 byte> <key_data: bytes> <value_length: varint> <value: bytes>
```

### 7.2 Required global fields

**Standard PSBT fields (from BIP 174):**
- `PSBT_GLOBAL_UNSIGNED_TX = 0x00` → Kaspa unsigned transaction (deterministically constructed)
- `PSBT_GLOBAL_VERSION = 0xFB` → KPSBT version (0x01000000 for v1)

**Kaspa proprietary fields (0xFC prefix):**

Proprietary key format: `0xFC <id_len> <identifier> <subtype> <key_data>`
- Identifier: `"kaspa"` (0x6B61737061) for all Kaspa extensions

```
KPSBT_GLOBAL_NETWORK_ID = 0xFC 05 6B61737061 00
  → network_id (u8: 0=mainnet, 1=testnet, 2=devnet, 3=simnet)

KPSBT_GLOBAL_SIGNING_EVENT = 0xFC 05 6B61737061 01
  → SigningEvent (serialized: event_id || event_source || destination || amount || metadata || timestamp)

KPSBT_GLOBAL_EVENT_HASH = 0xFC 05 6B61737061 02
  → event_hash (BLAKE3, 32 bytes)

KPSBT_GLOBAL_TX_TEMPLATE_HASH = 0xFC 05 6B61737061 03
  → tx_template_hash (BLAKE3 of canonical TX encoding, 32 bytes)

KPSBT_GLOBAL_REQUEST_ID = 0xFC 05 6B61737061 04
  → request_id (UUID, 16 bytes)

KPSBT_GLOBAL_POLICY = 0xFC 05 6B61737061 05
  → policy (threshold m || threshold n || sorted_pubkeys || aggregate_pubkey_if_musig2)

KPSBT_GLOBAL_SIGNING_MODE = 0xFC 05 6B61737061 06
  → mode (u8: 0x00=multisig, 0x01=frost, 0x02=musig2)

KPSBT_GLOBAL_MPC_SESSION_ID = 0xFC 05 6B61737061 07
  → mpc_session_id (optional, UTF-8 string, for FROST)

KPSBT_GLOBAL_MUSIG2_SESSION_ID = 0xFC 05 6B61737061 08
  → musig2_session_id (optional, UTF-8 string, for MuSig2)

KPSBT_GLOBAL_CREATED_AT = 0xFC 05 6B61737061 09
  → created_at (Unix timestamp, u64, 8 bytes)

KPSBT_GLOBAL_EXPIRES_AT = 0xFC 05 6B61737061 0A
  → expires_at (Unix timestamp, u64, 8 bytes)
```

### 7.3 Required per-input fields

**Standard PSBT input fields (adapted from BIP 174):**
```
PSBT_IN_PREVIOUS_TXID = 0x0E
  → Kaspa transaction_id (32 bytes)

PSBT_IN_OUTPUT_INDEX = 0x0F
  → Kaspa output index (u32, 4 bytes)

PSBT_IN_PARTIAL_SIG = 0x02
  → Partial signature (reuse BIP 174)
  → Key: 0x02 <pubkey: 33 bytes>
  → Value: <signature: 64 bytes> (secp256k1 schnorr)
```

**Kaspa proprietary input fields:**
```
KPSBT_IN_UTXO_ENTRY = 0xFC 05 6B61737061 10
  → UTXO entry (value: u64 || script_public_key || block_daa_score: u64 || is_coinbase: u8)

KPSBT_IN_SIGHASH_TYPE = 0xFC 05 6B61737061 11
  → Kaspa sighash type (u8: 0x01=ALL, 0x02=NONE, 0x03=SINGLE, 0x80=ANYONECANPAY)

KPSBT_IN_SIGNING_HASH = 0xFC 05 6B61737061 12
  → signing_hash (BLAKE2b-256, 32 bytes)

KPSBT_IN_MPC_SIGNATURE = 0xFC 05 6B61737061 13
  → FROST MPC aggregated signature (64 bytes)

KPSBT_IN_MUSIG2_SIGNATURE = 0xFC 05 6B61737061 14
  → MuSig2 aggregated signature (64 bytes)
```

**Note:** FROST and MuSig2 internal fields (nonce commitments, shares) NOT in KPSBT - handled by 3rd party libraries.

### 7.4 Canonical signing hash

**Two-level hash:**

**1. Event-level (replay protection):**
```
event_hash = BLAKE3(
    signing_event.event_id ||
    signing_event.event_source (canonical) ||
    signing_event.destination ||
    signing_event.amount ||
    signing_event.metadata (canonical) ||
    signing_event.timestamp
)
```

**2. Per-input (signature target):**
Per `rusty-kaspa v1.x/consensus/core/src/tx/sighash.rs`:
```
signing_hash[i] = BLAKE2b_256(
  tx.version || 
  hash_prev_outputs ||
  hash_sequences ||
  hash_sig_op_counts ||
  inputs[i].previous_outpoint ||
  utxo_entry[i].script_public_key_version ||
  utxo_entry[i].script_public_key ||
  utxo_entry[i].amount ||
  inputs[i].sequence ||
  sighash_type ||
  hash_outputs
)
```

**Validation hash (equivocation detection):**
```
validation_hash = BLAKE3(
  event_hash ||
  tx_template_hash ||
  signing_hash[0] || ... || signing_hash[n] ||
  policy_hash
)
```

Exchanged in `SignerAck` to ensure all signers agree on identical artifacts.

### 7.5 KPSBT serialization example

**Example KPSBT for single-recipient transaction:**

```
Magic: 6B 70 73 62 74 FF                    # "kpsbt" + 0xFF

# Global map
01 00                                        # Key: PSBT_GLOBAL_UNSIGNED_TX (length=1, type=0x00)
  <varint: tx_length>
  <kaspa_tx_bytes>                           # Unsigned Kaspa transaction

09 FC 05 6B61737061 00                       # Key: KPSBT_GLOBAL_NETWORK_ID
  01 00                                      # Value: 0x00 (mainnet)

22 FC 05 6B61737061 02                       # Key: KPSBT_GLOBAL_EVENT_HASH
  20                                         # Value length: 32 bytes
  <32 bytes: event_hash>

09 FC 05 6B61737061 06                       # Key: KPSBT_GLOBAL_SIGNING_MODE
  01 01                                      # Value: 0x01 (FROST)

00                                           # Separator

# Input 0 map
21 0E                                        # Key: PSBT_IN_PREVIOUS_TXID (length=33, type=0x0E)
  <32 bytes: tx_id>

05 0F                                        # Key: PSBT_IN_OUTPUT_INDEX
  04 <u32: index>                            # 4 bytes

22 FC 05 6B61737061 12                       # Key: KPSBT_IN_SIGNING_HASH
  20 <32 bytes: signing_hash>

00                                           # Separator

# Output 0 map
(standard PSBT output fields)

00                                           # Separator

# Output 1 map
(change output fields)

00                                           # Final separator
```

### 7.6 KPSBT libraries and tooling

**Rust implementation (recommended):**
```rust
use bitcoin::psbt::PartiallySignedTransaction;  // Base structure
use kaspa_consensus::tx::Transaction;

// Extend PSBT for Kaspa
struct Kpsbt {
    psbt_base: PartiallySignedTransaction,
    kaspa_globals: KaspaGlobalExtensions,
    kaspa_inputs: Vec<KaspaInputExtensions>,
}

impl Kpsbt {
    fn serialize(&self) -> Vec<u8> {
        // Serialize using BIP 174 format with Kaspa proprietary keys
    }
    
    fn deserialize(bytes: &[u8]) -> Result<Self> {
        // Parse PSBT format, extract Kaspa extensions
    }
}
```

**Existing libraries to leverage:**
- `rust-bitcoin` crate for PSBT parsing/serialization
- `bitcoin-dev` tools for PSBT debugging
- Hardware wallet libraries (already support PSBT)

### 7.7 KPSBT validation

**Each signer MUST validate:**
1. Magic bytes match `0x6B707362FF`
2. All required global fields present
3. All required input fields present for each input
4. `event_hash` recomputed matches KPSBT value
5. `tx_template_hash` recomputed matches KPSBT value
6. `signing_hash[i]` recomputed for each input matches KPSBT value
7. `validation_hash` matches coordinator's proposal
8. Proprietary keys use correct identifier (`"kaspa"` = 0x6B61737061)
9. All values correctly encoded (lengths match, types correct)

**Validation failure → abort session**

---

## 8. Replay Protection

Enforced **by every signer**, independently, with persistent storage.

### 8.1 Identifiers to persist
- `event_id` (source-specific unique ID)
- `event_hash` (BLAKE3 of SigningEvent - **primary replay key**)
- `request_id` (session-level unique ID)
- `validation_hash` (equivocation detection)
- `tx_template_hash` (constructed TX hash)
- `session_id` (ephemeral session ID)
- `per_input_signing_hashes[]` (array per input)
- `decision` ∈ `{pending, approved, rejected, expired, finalized, aborted}`
- `final_tx_id` (if broadcast/observed)
- `final_tx_accepted_blue_score` (DAG blue score at acceptance)
- `timestamps` (first_seen, last_updated, decision_made, finalized)

### 8.2 Replay rules
Signer MUST reject if:
- Same `event_id` seen again (strict once-only per source)
- Same `event_hash` seen after approval (prevent replay from different sources)
- `validation_hash` mismatch (coordinator equivocation)
- `expires_at` in past
- Input UTXO spent in confirmed TX
- Event violates policy (allowlist, limits)

### 8.3 Cross-session event deduplication
**Critical for bridge safety:** Different coordinators may propose same event.

```rust
if db.exists(event_hash):
    existing = db.get(event_hash)
    if existing.status in [approved, finalized]:
        reject_duplicate("Event already processed")
    if existing.status == pending and session_id != existing.session_id:
        reject_duplicate("Event in progress in different session")
```

### 8.4 Storage
SQLite/sled/RocksDB - crash-safe, append-auditable.

**Indices:**
- Primary: `event_hash` (critical for replay)
- Secondary: `event_id`, `request_id`, `final_tx_id`

---

## 9. Protocol Messages (Iroh PubSub)

All messages signed by sender's **Protocol Identity Key (PIK)** (Ed25519).
- NOT Kaspa secp256k1 signing key
- Includes: `sender_peer_id`, `group_id`, `session_id`, `seq_no`, `timestamp_nanos`, `payload`, `payload_hash`, `signature`

### 9.1 Message types

**On Group Topic:**
- `SignEventAnnounce { event_hash, request_id, session_topic_id, event_summary, expires_at, coordinator_peer_id }`

**On Session Topic:**

**Common:**
- `SigningEventPropose { request_id, signing_event, kpsbt_blob }` (coordinator → all)
- `SignerAck { request_id, event_hash, validation_hash, accept|reject, reason?, signer_peer_id }` (signer → coordinator)
- `Abort { request_id, reason, aborted_by }` (any → all)

**Multisig mode:**
- `PartialSigSubmit { request_id, input_index, pubkey, signature }` (signer → coordinator)

**FROST mode (MPC interface):**
- `MpcSessionInit { request_id, mpc_session_id, mpc_library_id, participant_ids[], signing_hashes[] }` (coordinator → all)
- `MpcSessionReady { request_id, mpc_session_id, ready_participants[] }` (participants → coordinator)
- `MpcSignatureReady { request_id, mpc_session_id, aggregated_signatures[], mpc_proof? }` (MPC lib/coordinator → all)

**Note:** FROST/MPC internals (nonce commitments, shares, rounds) handled by 3rd party library's own channels (e.g., Sodot network). Only session coordination + final signature use Iroh.

**MuSig2 mode (MuSig2 interface):**
- `MuSig2SessionInit { request_id, musig2_session_id, musig2_library_id, participant_ids[], signing_hashes[], aggregate_pubkey }` (coordinator → all)
- `MuSig2SessionReady { request_id, musig2_session_id, ready_participants[] }` (participants → coordinator)
- `MuSig2SignatureReady { request_id, musig2_session_id, aggregated_signatures[] }` (MuSig2 lib/coordinator → all)

**Note:** MuSig2 internals (nonce generation, nonce commitments, partial signatures, aggregation) handled by 3rd party library's own protocol (e.g., secp256k1-zkp). Only session coordination + final signature use Iroh.

**Finalization:**
- `FinalizePropose { request_id, final_tx_blob, final_tx_id }` (coordinator → all)
- `FinalizeAck { request_id, final_tx_id, accept|reject, reason?, signer_peer_id }` (signer → coordinator)
- `BroadcastNotice { request_id, final_tx_id, mempool_seen?, accepted_blue_score? }` (any → all)

### 9.2 Sequencing
- `seq_no` per-session per-sender monotonic (u64)
- Ignore out-of-window seq (configurable slack, e.g., ±10)
- Drop duplicates: `seq_no <= last_seen[sender]`

---

## 10. Signing Flow: Multisig Mode

### 10.1 Event reception and TX construction
1. Coordinator receives `SigningEvent` from external source (bridge, oracle, API).
2. Coordinator validates event authenticity and policy.
3. Coordinator uses embedded rusty-kaspa-wallet to construct unsigned TX:
   - Deterministic UTXO selection
   - Compute fee
   - Add change output
4. Coordinator computes per-input `signing_hash[]` and `event_hash`.
5. Coordinator constructs KPSBT with SigningEvent + TX template.

### 10.2 Session announcement
6. Coordinator posts `SignEventAnnounce` to **GroupTopicId** with `session_topic_id`.
7. Interested signers join **SessionTopicId**.

### 10.3 Event and TX validation
8. Coordinator sends `SigningEventPropose` with full KPSBT.
9. Each signer:
   - **Validates SigningEvent:**
     - Event authenticity (source signature if present)
     - Policy compliance (destination allowlist, amount limits)
     - Replay check (`event_hash` not seen before)
   - **Reconstructs TX using own embedded wallet:**
     - Same UTXO selection algorithm
     - Same fee calculation
     - Compare with coordinator's `tx_template`
   - **Validates via local kaspa node:**
     - UTXOs exist, unspent, mature (blue score)
     - Fee sanity (sompi/mass ratio)
     - Output destinations policy-compliant
     - TX mass valid
   - Recomputes per-input `signing_hash[]`
   - Recomputes `event_hash`
   - Computes `validation_hash`
   - Checks: `validation_hash` matches coordinator's
   - Applies replay checks against local DB
   - Replies `SignerAck(accept|reject)` with `validation_hash`

### 10.4 Partial signatures
10. If accepted, signer produces partial sig using embedded wallet:
    - For each input: `sig = schnorr_sign(private_key, signing_hash[i])`
    - Format: 64 bytes (R || s) secp256k1 schnorr
11. Signer sends `PartialSigSubmit` per input.

### 10.5 Finalisation and broadcast
12. Coordinator collects m-of-n partial sigs for all inputs.
13. Coordinator constructs final TX (insert sigs into script positions).
14. Coordinator validates final TX locally (sig verification, mass check).
15. Coordinator sends `FinalizePropose` with `final_tx_blob`.
16. Signers verify final TX independently:
    - Signature verification
    - Mass validation
    - No unexpected changes
17. Signers reply `FinalizeAck`.
18. Coordinator broadcasts via local node RPC (`submitTransaction`).
19. Coordinator sends `BroadcastNotice` with mempool status.
20. Each signer monitors with own node, records finality (blue score acceptance).

---

## 11. Signing Flow: FROST Mode (3rd Party MPC Library)

### 11.1 Overview
Coordination layer remains similar; signature production uses external MPC library (e.g., Sodot, Lit Protocol, Fireblocks MPC SDK).

**Key difference:** All MPC protocol details (nonce generation, commitments, shares, round progression) handled by 3rd party library's own communication channels and protocol. Coordination layer only manages session lifecycle and final signature delivery.

### 11.2 MPC library interface requirements

**Minimum interface from 3rd party MPC library:**

```rust
trait MpcLibrary {
    // Initialize signing session
    fn init_session(
        session_id: String,
        participant_ids: Vec<String>,
        signing_hashes: Vec<[u8; 32]>,  // Per-input signing hashes
        threshold: u16,
    ) -> Result<MpcSessionHandle>;
    
    // Check if participant ready (library-side setup complete)
    fn is_ready(handle: &MpcSessionHandle) -> bool;
    
    // Block until signatures produced (library handles all rounds internally)
    fn await_signatures(handle: &MpcSessionHandle) -> Result<Vec<Signature>>;
    
    // Optional: proof of correct execution
    fn get_proof(handle: &MpcSessionHandle) -> Option<Vec<u8>>;
}

struct Signature {
    input_index: u32,
    signature: [u8; 64],  // secp256k1 schnorr (R || s)
}
```

### 11.3 Flow

**Event reception and TX construction (same as multisig):**
1-9. Same as §10.1-10.3 (event validation, TX construction, validation hash exchange).

**MPC session initialization:**
10. Coordinator calls MPC library: `mpc_lib.init_session(mpc_session_id, participant_ids, signing_hashes, threshold)`.
11. Coordinator sends `MpcSessionInit` with `mpc_session_id` to Iroh session topic.
12. Each signer:
    - Calls own MPC library instance: `mpc_lib.init_session(same params)`
    - Waits for library readiness: `mpc_lib.is_ready()`
    - Sends `MpcSessionReady` to coordinator

**MPC library execution (black box):**
13. Once threshold participants ready, MPC library **internally** executes:
    - Round 1: Nonce generation and commitment exchange (via library's own channels)
    - Round 2: Signature share computation and exchange (via library's own channels)
    - Aggregation: Final signature(s) computation
    - All communication between MPC library instances happens **outside Iroh** (e.g., Sodot's proprietary network, direct P2P, etc.)

**Signature delivery:**
14. Coordinator's MPC library returns: `signatures = mpc_lib.await_signatures()`.
15. Coordinator sends `MpcSignatureReady` with aggregated signatures to Iroh session topic.
16. Signers verify signatures locally:
    - Extract signatures from message
    - Verify each signature against corresponding `signing_hash[i]` and group public key
    - Confirm signatures are valid secp256k1 schnorr

**Finalization (same as multisig):**
17-20. Same as §10.5 (construct final TX, validate, broadcast, monitor).

### 11.4 Example: Sodot MPC integration

```rust
// Coordinator side
let sodot = SodotClient::new(config);
let session = sodot.init_signing_session(
    mpc_session_id,
    participant_ids,
    signing_hashes,  // From KPSBT
    threshold_m,
)?;

// Announce via Iroh
send_message(MpcSessionInit { 
    mpc_session_id, 
    mpc_library_id: "sodot-v1",
    participant_ids,
    signing_hashes 
});

// Signer side (each participant)
let sodot = SodotClient::new(config);
let session = sodot.join_signing_session(mpc_session_id)?;

if sodot.is_ready(&session) {
    send_message(MpcSessionReady { mpc_session_id });
}

// Black box: Sodot handles all rounds internally
let signatures = sodot.await_signatures(&session)?;  // Blocks

// Coordinator receives signatures, broadcasts
send_message(MpcSignatureReady { signatures });
```

### 11.5 MPC library agnosticism

Protocol supports multiple MPC libraries by:
- `mpc_library_id` field identifies library (e.g., "sodot-v1", "lit-v2", "fireblocks-v1")
- Standardized interface (§11.2) - libraries implement same trait
- Library-specific config in signer's local settings
- Coordination layer agnostic to MPC internals

---

## 11B. Signing Flow: MuSig2 Mode (n-of-n, 3rd Party Library)

**Note:** MuSig2 implementation comes **after** Multisig and FROST. It requires all n participants (no threshold).

### 11B.1 Overview

MuSig2 is a 2-round n-of-n multisignature scheme that produces a single schnorr signature indistinguishable from a single-signer signature. Unlike FROST (m-of-n threshold), MuSig2 requires **all n signers** to participate.

**Advantages over Multisig:**
- Single 64-byte signature (not n signatures)
- Lower transaction size and fees
- Better privacy (looks like single-key spend)
- Faster verification

**Advantages over FROST:**
- Simpler protocol (2 rounds vs 3+ rounds)
- No dealer required
- More audited implementations available
- Better performance for n-of-n case

**Trade-off:**
- **No fault tolerance:** Single signer offline = ceremony fails
- All n signers must participate

### 11B.2 MuSig2 library interface requirements

**Minimum interface from 3rd party MuSig2 library:**

```rust
trait MuSig2Library {
    // Initialize signing session (all n participants required)
    fn init_session(
        session_id: String,
        participant_ids: Vec<String>,        // All n participants
        participant_pubkeys: Vec<PublicKey>, // All n public keys
        signing_hashes: Vec<[u8; 32]>,       // Per-input signing hashes
    ) -> Result<MuSig2SessionHandle>;
    
    // Compute aggregate public key (deterministic, same for all participants)
    fn compute_aggregate_pubkey(
        pubkeys: &[PublicKey],
    ) -> Result<PublicKey>;
    
    // Check if participant ready (library-side setup complete)
    fn is_ready(handle: &MuSig2SessionHandle) -> bool;
    
    // Block until signatures produced (library handles both rounds internally)
    // Round 1: Nonce generation and commitment exchange
    // Round 2: Partial signature generation and aggregation
    fn await_signatures(handle: &MuSig2SessionHandle) -> Result<Vec<Signature>>;
}

struct Signature {
    input_index: u32,
    signature: [u8; 64],  // secp256k1 schnorr (R || s)
}
```

### 11B.3 MuSig2 protocol overview (library internals)

**For reference only - handled entirely by 3rd party library:**

**Setup (one-time):**
1. Each signer has private key `x_i`
2. Corresponding public keys `X_i = x_i * G`
3. Aggregate public key: `X_agg = H(X_1, ..., X_n, X_1) * X_1 + ... + H(X_1, ..., X_n, X_n) * X_n`
4. On-chain spend condition uses `X_agg` (single public key)

**Round 1 (nonce commitment):**
1. Each signer generates two nonces: `(r_i1, r_i2)` (fresh random, must never reuse)
2. Compute commitments: `(R_i1, R_i2) = (r_i1 * G, r_i2 * G)`
3. Broadcast commitments to all participants (via library's protocol)

**Round 2 (partial signatures):**
4. All signers received all commitments
5. Compute aggregate nonce: `R = R_11 + ... + R_n1 + b * (R_12 + ... + R_n2)` where `b = H(X_agg, R_11 + ... + R_n1, m)`
6. Each signer computes challenge: `c = H(X_agg, R, m)` where `m` is signing_hash
7. Each signer computes partial signature: `s_i = r_i1 + b * r_i2 + c * a_i * x_i`
   where `a_i = H(X_1, ..., X_n, X_i)` is signer's key aggregation coefficient
8. Broadcast partial signatures

**Aggregation:**
9. Compute final signature: `s = s_1 + ... + s_n`
10. Final signature: `(R, s)` - standard 64-byte schnorr signature
11. Verify: `s * G == R + c * X_agg`

### 11B.4 Flow

**Event reception and TX construction (same as multisig/FROST):**
1-9. Same as §10.1-10.3 (event validation, TX construction, validation hash exchange).

**MuSig2 session initialization:**
10. Coordinator computes aggregate public key:
    ```rust
    let aggregate_pubkey = musig2_lib.compute_aggregate_pubkey(&participant_pubkeys)?;
    ```
11. Coordinator calls MuSig2 library:
    ```rust
    musig2_lib.init_session(
        musig2_session_id,
        participant_ids,      // All n participants
        participant_pubkeys,  // All n public keys
        signing_hashes,       // Per-input from KPSBT
    )
    ```
12. Coordinator sends `MuSig2SessionInit` with `musig2_session_id` and `aggregate_pubkey` to Iroh session topic.
13. Each signer:
    - Verifies `aggregate_pubkey` matches own computation
    - Calls own MuSig2 library instance:
      ```rust
      musig2_lib.init_session(same params)
      ```
    - Waits for library readiness: `musig2_lib.is_ready()`
    - Sends `MuSig2SessionReady` to coordinator

**MuSig2 library execution (black box):**
14. Once **all n participants** ready, MuSig2 library **internally** executes:
    - **Round 1:** Nonce generation and commitment exchange (via library's own channels)
    - **Round 2:** Partial signature computation and exchange (via library's own channels)
    - **Aggregation:** Final signature(s) computation
    - All communication between MuSig2 library instances happens **outside Iroh** (library's P2P, direct connections, etc.)

**Critical:** If any single signer fails or goes offline, the entire ceremony fails. This is the n-of-n trade-off.

**Signature delivery:**
15. Coordinator's MuSig2 library returns: `signatures = musig2_lib.await_signatures()`.
16. Coordinator sends `MuSig2SignatureReady` with aggregated signatures to Iroh session topic.
17. Signers verify signatures locally:
    - Extract signatures from message
    - Verify each signature against corresponding `signing_hash[i]` and `aggregate_pubkey`
    - Confirm signatures are valid secp256k1 schnorr
    - **Critical:** Signature must verify against `aggregate_pubkey`, not individual public keys

**Finalization (same as multisig/FROST):**
18-21. Same as §10.5 (construct final TX, validate, broadcast, monitor).

### 11B.5 Example: secp256k1-zkp MuSig2 integration

```rust
// Using secp256k1-zkp with MuSig2 module (Rust bindings)
use secp256k1_zkp::{Secp256k1, musig::{MusigSession, MusigKeyAggCache}};

// Coordinator side
let secp = Secp256k1::new();

// Compute aggregate public key (all signers must agree on this)
let mut key_agg_cache = MusigKeyAggCache::new(&secp, &participant_pubkeys)?;
let aggregate_pubkey = key_agg_cache.agg_pk();

// Announce via Iroh
send_message(MuSig2SessionInit { 
    musig2_session_id,
    musig2_library_id: "secp256k1-zkp-musig2-v1",
    participant_ids,
    signing_hashes,
    aggregate_pubkey,
});

// Each signer side
let secp = Secp256k1::new();

// Verify aggregate public key matches
let mut my_key_agg_cache = MusigKeyAggCache::new(&secp, &participant_pubkeys)?;
assert_eq!(my_key_agg_cache.agg_pk(), received_aggregate_pubkey);

// Initialize session for each input
let mut sessions: Vec<MusigSession> = signing_hashes.iter().map(|hash| {
    MusigSession::new(
        &secp,
        &my_key_agg_cache,
        hash,
        &my_secret_key,
    )
}).collect::<Result<_>>()?;

send_message(MuSig2SessionReady { musig2_session_id });

// Black box: secp256k1-zkp handles all rounds internally
// (In practice, library may expose round-by-round API for more control)
let signatures = await_musig2_signatures(&secp, &mut sessions)?;

// Coordinator receives signatures, verifies, broadcasts
send_message(MuSig2SignatureReady { signatures });
```

### 11B.6 On-chain representation

**Key difference from Multisig:**

**Multisig on-chain:**
```
script_pubkey: MULTISIG(m, [pubkey_1, pubkey_2, ..., pubkey_n])
witness: [sig_1, sig_2, ..., sig_m]  // m signatures, each 64 bytes
Total size: m * 64 bytes
```

**MuSig2 on-chain:**
```
script_pubkey: PUBKEY(aggregate_pubkey)  // Single public key
witness: [signature]  // Single signature, 64 bytes
Total size: 64 bytes (constant, regardless of n)
```

**Benefits:**
- **67% smaller** for 3-of-3 (64 bytes vs 192 bytes)
- **87% smaller** for 5-of-5 (64 bytes vs 320 bytes)
- Privacy: indistinguishable from single-key spend
- Faster on-chain verification

### 11B.7 When to use MuSig2 vs FROST

**Use MuSig2 when:**
- All n signers are highly available (e.g., co-located, same organization)
- Privacy is critical (single-signature on-chain)
- Transaction size optimization is important
- n is small (2-of-2, 3-of-3)

**Use FROST when:**
- Fault tolerance required (some signers may be offline)
- Threshold < n needed (e.g., 3-of-5)
- Signers geographically distributed or less reliable
- Larger groups (n > 5)

**Use Multisig when:**
- On-chain transparency required (see which keys signed)
- Simplest implementation (no MPC/aggregation complexity)
- Auditability is critical
- Existing infrastructure

### 11B.8 MuSig2 nonce reuse prevention

**Critical security requirement:**

Nonces in MuSig2 MUST be generated fresh and random for **every signing session**. Nonce reuse across sessions leaks private keys.

**Enforced by:**
- 3rd party library (e.g., secp256k1-zkp) handles nonce generation securely
- New session ID for every signing request ensures library generates new nonces
- Each signing_hash is unique (binds to specific transaction)
- Libraries use high-quality CSRNG (e.g., `getrandom` crate)

**Additional safeguards:**
- Session ID includes timestamp + random component
- Signers abort if duplicate session ID detected
- Audit log tracks all session IDs
- Library-level nonce commitment verification

---

## 12. Rusty-Kaspa Wallet Integration

**Official SDK:** This specification uses **rusty-kaspa v1.x** as the official Kaspa SDK for both node and wallet integration.

**SDK components:**
- **rusty-kaspa node v1.0+:** Full node implementation (consensus, RPC, network)
- **rusty-kaspa-wallet v1.0+:** Official wallet SDK (key management, transaction construction, signing)
- **kaspa-consensus v1.0+:** Core consensus library (transaction validation, signing hash computation)

### 12.1 Embedded wallet requirements

Each signer runs **embedded rusty-kaspa-wallet v1.0+** instance:

**Capabilities:**
- **Deterministic UTXO selection:** Identical algorithm across all signers
- **Transaction construction:** From abstract `SigningEvent` to unsigned Kaspa TX
- **Fee estimation:** Configurable (static or dynamic)
- **Change address derivation:** Deterministic per group policy
- **Signing hash computation:** Per `rusty-kaspa v1.x/consensus/core/src/tx/sighash.rs`
- **Schnorr signature production:** secp256k1 (multisig mode)
- **Key management:** Import/manage multisig keys or FROST shares

**Configuration (per signer):**
```rust
struct WalletConfig {
    network_id: u8,
    group_descriptor: GroupDescriptor,  // Multisig script or FROST pubkey
    utxo_selection_strategy: UtxoSelectionStrategy,
    fee_rate: FeeRate,  // sompi per gram
    change_address_derivation: ChangeAddressDerivation,
}

enum UtxoSelectionStrategy {
    LargestFirst,  // Default: deterministic (amount DESC, age DESC)
    // Other strategies can be added if needed
}
```

**Critical:** All signers must have **identical** `WalletConfig` (except private keys).

### 12.2 Transaction construction API

**Using rusty-kaspa-wallet v1.x SDK:**

```rust
use kaspa_wallet_core::api::WalletApi;  // rusty-kaspa-wallet v1.x
use kaspa_consensus::tx::Transaction;
use kaspa_consensus::sighash::calc_schnorr_signature_hash;

impl EmbeddedWallet {
    // Main entry point: event → unsigned TX
    // Leverages rusty-kaspa-wallet v1.x core APIs
    fn construct_transaction(
        &self,
        event: &SigningEvent,
    ) -> Result<(Transaction, Vec<UtxoEntry>)> {
        // 1. Validate event
        self.validate_event(event)?;
        
        // 2. Query UTXO set (using rusty-kaspa-wallet v1.x)
        let utxos = self.wallet_api.get_utxos()?;
        
        // 3. Select UTXOs (deterministic)
        let selected = self.select_utxos(&utxos, event.amount, fee_estimate)?;
        
        // 4. Construct TX (using rusty-kaspa-wallet v1.x builders)
        let tx = self.build_transaction(event, &selected)?;
        
        Ok((tx, selected))
    }
    
    // Compute signing hashes using rusty-kaspa v1.x consensus library
    fn compute_signing_hashes(
        &self,
        tx: &Transaction,
        utxo_entries: &[UtxoEntry],
    ) -> Result<Vec<[u8; 32]>> {
        // Use rusty-kaspa v1.x calc_schnorr_signature_hash
        tx.inputs.iter().enumerate().map(|(i, input)| {
            calc_schnorr_signature_hash(
                tx,
                i,
                &utxo_entries[i],
                SighashType::All,
            )
        }).collect()
    }
    
    // Sign (multisig mode) using rusty-kaspa-wallet v1.x signing
    fn sign_input(
        &self,
        signing_hash: &[u8; 32],
        key_index: usize,
    ) -> Result<Signature> {
        // secp256k1 schnorr signing via rusty-kaspa-wallet v1.x
        self.wallet_api.sign_schnorr(signing_hash, key_index)
    }
}
```

**rusty-kaspa-wallet v1.x dependencies:**
```toml
[dependencies]
kaspa-wallet-core = "1.0"      # Core wallet API
kaspa-consensus = "1.0"        # Transaction, signing hash, validation
kaspa-txscript = "1.0"         # Script handling
kaspa-addresses = "1.0"        # Address parsing (bech32m)
kaspa-rpc-core = "1.0"         # Node RPC client
```

### 12.3 Node RPC usage

Each signer's wallet queries local **rusty-kaspa v1.0+ node**:

**Required RPC calls (rusty-kaspa v1.x RPC API):**
```rust
use kaspa_rpc_core::api::rpc::RpcApi;  // rusty-kaspa v1.x

// UTXO queries
node_rpc.get_utxos_by_addresses(addresses).await?;

// Current blue score
node_rpc.get_virtual_selected_parent_blue_score().await?;

// Block queries (maturity checks)
node_rpc.get_block(block_hash).await?;

// Transaction submission
node_rpc.submit_transaction(transaction, allow_orphan).await?;

// Transaction monitoring
node_rpc.get_transaction(tx_id, include_block_verbose).await?;

// Mempool queries (detect conflicts)
node_rpc.get_mempool_entry(tx_id).await?;
```

**Node requirements:**
- **Minimum version:** rusty-kaspa v1.0.0+
- **RPC enabled:** gRPC or JSON-RPC interface
- **Sync status:** Fully synced with network
- **UTXO index:** Enabled for address-based queries

**Example node connection (rusty-kaspa v1.x):**
```rust
use kaspa_rpc_core::RpcClient;

let node_client = RpcClient::connect(
    "grpc://localhost:16110",  // Default mainnet gRPC
    None,                       // No auth for local node
).await?;

// Verify node is synced
let info = node_client.get_server_info().await?;
assert!(info.is_synced);
```

---

## 13. Security Considerations

### 13.1 Coordinator equivocation
**Attack:** Coordinator sends different KPSBT versions to different signers.

**Mitigation:**
- Every signer reconstructs TX from `SigningEvent` using own wallet
- Computes own `validation_hash`
- Includes `validation_hash` in `SignerAck`
- Any mismatch aborts session
- Persistent audit log

### 13.2 Event replay
**Attack:** Reuse of old events or signing requests.

**Mitigation:**
- Primary key: `event_hash` (binds to specific event)
- Strict `event_id` uniqueness per source
- `event_hash` persistence with status tracking
- Cross-session deduplication (§8.3)
- `expires_at` enforcement
- UTXO spent check before signing

### 13.3 Deterministic TX construction divergence
**Attack:** Signers construct different TXs from same event (Byzantine behavior).

**Mitigation:**
- Standardized UTXO selection algorithm
- Identical wallet config enforced
- `validation_hash` exchange catches divergence
- Abort if any signer's `validation_hash` differs

### 13.4 Double-signing / conflicting TXs
**Attack:** Sign multiple conflicting TXs spending same UTXOs.

**Mitigation:**
- Track all approved `event_hash` values
- Check UTXO reuse in pending/approved requests
- Reject if UTXO appears in multiple events
- Monitor node for conflicting mempool TXs
- Require policy override for UTXO reuse

### 13.5 Transport integrity
**Attack:** Message tampering, spoofing, MITM.

**Mitigation:**
- All messages signed by sender PIK (Ed25519)
- Verify signature on every message
- Reject unauthorized PIKs (group membership)
- Iroh encrypted channels (if available)
- TLS for node RPC

### 13.6 Denial of service
**Attack:** Spam, resource exhaustion, session flooding.

**Mitigation:**
- Rate-limit per PIK/peer_id (e.g., 10 sessions/hour)
- Group membership proof required
- Session timeouts (auto-abort)
- Message size limits (KPSBT max 1MB)
- Drop sessions with excessive invalid messages

### 13.7 MPC/MuSig2 library trust
**Risk:** 3rd party library bugs, backdoors, or vulnerabilities.

**Mitigation:**
- Use audited, well-known libraries (Sodot, Lit, Fireblocks, secp256k1-zkp)
- Verify final signatures independently (all signers verify against signing_hash + pubkey)
- Monitor libraries for security updates
- Multi-library support (switch if needed)
- **Critical:** Even with MPC/MuSig2, final signature must be verified by all signers before accepting TX

### 13.8 MuSig2-specific: nonce reuse
**Attack:** Reusing nonces across MuSig2 sessions leaks private keys.

**Mitigation:**
- 3rd party library handles nonce generation (e.g., secp256k1-zkp with secure RNG)
- Fresh session ID per signing request
- Each signing_hash is unique
- Session ID includes timestamp + random component
- Signers abort if duplicate session ID detected
- Audit log tracks all session IDs
- Library-level nonce commitment verification

### 13.9 MuSig2-specific: n-of-n availability
**Risk:** Single signer offline = entire ceremony fails (no fault tolerance).

**Mitigation:**
- Use MuSig2 only when all n signers are highly available
- Implement timeout + fallback to FROST if MuSig2 fails
- Health checks before initiating MuSig2 session
- Coordinator pings all signers before `MuSig2SessionInit`
- Auto-downgrade to FROST if availability concerns
- Document when MuSig2 vs FROST is appropriate (§11B.7)

### 13.10 Bridge/oracle event authenticity
**Attack:** Malicious event source injecting fake events.

**Mitigation:**
- Verify event source signatures (if available)
- Allowlist authorized event sources
- Multi-oracle consensus (if applicable)
- Policy limits (max amount, destination allowlist)
- Human approval for large amounts (integration layer)

---

## 14. Data Model (Signer Local DB)

### Tables/collections

**events** (primary: event tracking)
```sql
CREATE TABLE events (
    event_hash BLOB PRIMARY KEY,           -- BLAKE3, 32 bytes
    event_id TEXT NOT NULL,                -- Source-specific ID
    event_source TEXT NOT NULL,            -- JSON: EventSource
    destination TEXT NOT NULL,             -- Kaspa address
    amount INTEGER NOT NULL,               -- sompi
    metadata TEXT,                         -- JSON: EventMetadata
    timestamp INTEGER NOT NULL,            -- Unix nanos
    status TEXT NOT NULL,                  -- pending|approved|rejected|expired|finalized|aborted
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX idx_events_event_id ON events(event_id);
CREATE INDEX idx_events_status ON events(status);
```

**requests** (session tracking)
```sql
CREATE TABLE requests (
    request_id TEXT PRIMARY KEY,           -- UUID
    event_hash BLOB NOT NULL,              -- FK to events
    session_id BLOB NOT NULL,              -- BLAKE3, 32 bytes
    coordinator_peer_id TEXT NOT NULL,
    validation_hash BLOB NOT NULL,         -- BLAKE3, 32 bytes
    tx_template_hash BLOB NOT NULL,        -- BLAKE3, 32 bytes
    mode TEXT NOT NULL,                    -- multisig|frost|musig2
    threshold_m INTEGER NOT NULL,          -- Ignored for musig2 (always n)
    threshold_n INTEGER NOT NULL,
    decision TEXT NOT NULL,                -- pending|approved|rejected|expired|finalized|aborted
    decision_made_at INTEGER,
    expires_at INTEGER NOT NULL,
    final_tx_id BLOB,                      -- Hash, 32 bytes
    final_tx_accepted_blue_score INTEGER,
    mpc_session_id TEXT,                   -- External MPC library session ID (FROST)
    musig2_session_id TEXT,                -- External MuSig2 library session ID (MuSig2)
    aggregate_pubkey BLOB,                 -- For MuSig2 mode (33 bytes compressed)
    notes TEXT,
    FOREIGN KEY(event_hash) REFERENCES events(event_hash)
);
CREATE INDEX idx_requests_event_hash ON requests(event_hash);
CREATE INDEX idx_requests_session_id ON requests(session_id);
CREATE INDEX idx_requests_final_tx_id ON requests(final_tx_id);
CREATE INDEX idx_requests_mode ON requests(mode);
```

**request_inputs** (per-input tracking)
```sql
CREATE TABLE request_inputs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL,
    input_index INTEGER NOT NULL,
    utxo_tx_id BLOB NOT NULL,              -- Hash, 32 bytes
    utxo_output_index INTEGER NOT NULL,
    utxo_value INTEGER NOT NULL,           -- sompi
    signing_hash BLOB NOT NULL,            -- BLAKE2b, 32 bytes
    my_signature BLOB,                     -- 64 bytes (if signed)
    FOREIGN KEY(request_id) REFERENCES requests(request_id),
    UNIQUE(request_id, input_index)
);
```

**policies** (group configuration)
```sql
CREATE TABLE policies (
    group_id BLOB PRIMARY KEY,             -- BLAKE3, 32 bytes (deterministic from config)
    network_id INTEGER NOT NULL,
    threshold_m INTEGER NOT NULL,          -- Ignored if mode=musig2
    threshold_n INTEGER NOT NULL,
    member_pubkeys TEXT NOT NULL,          -- JSON array (sorted)
    protocol_type TEXT NOT NULL,           -- multisig|frost|musig2
    
    -- V1 Immutable parameters (part of group_id)
    fee_payment_mode TEXT NOT NULL,        -- recipient_pays|signers_pay|split
    fee_rate_sompi_per_gram INTEGER NOT NULL, -- Static fee rate (V1)
    finality_blue_score_threshold INTEGER NOT NULL, -- Blue score confirmations required
    dust_threshold_sompi INTEGER NOT NULL, -- Minimum output value (e.g., 1000)
    min_recipient_amount_sompi INTEGER NOT NULL, -- Minimum payment (e.g., 10000)
    session_timeout_seconds INTEGER NOT NULL, -- Session timeout (e.g., 300)
    
    -- V1 Mutable parameters (not part of group_id, can be updated via external governance)
    allowed_destinations TEXT,             -- JSON array of addresses (allowlist)
    max_amount_per_tx INTEGER,             -- sompi (per-tx limit)
    max_velocity_per_hour INTEGER,         -- sompi (velocity limit)
    require_human_approval BOOL DEFAULT 0, -- Future: pause for approval (not V1)
    
    -- Protocol-specific
    signing_mode TEXT NOT NULL,            -- multisig|frost|musig2 (same as protocol_type)
    mpc_library_id TEXT,                   -- e.g., "sodot-v1" (for FROST)
    musig2_library_id TEXT,                -- e.g., "secp256k1-zkp-musig2-v1" (for MuSig2)
    aggregate_pubkey BLOB,                 -- For MuSig2 mode (33 bytes compressed)
    
    -- V1 Phase 2 features (not used in Phase 1)
    support_multi_recipient BOOL DEFAULT 0, -- Phase 2 feature
    max_recipients_per_tx INTEGER DEFAULT 1, -- Phase 1: 1, Phase 2: e.g. 10
    
    -- Metadata
    group_name TEXT,                       -- Human-readable name
    group_metadata TEXT,                   -- JSON: GroupMetadata
    policy_version INTEGER NOT NULL,       -- Schema version (V1 = 1)
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- V1 Note: All parameters in group_id are immutable after creation
-- Changing immutable params requires new group + fund movement
-- Mutable params (allowlist, limits) can be updated via governance (post-V1)
```

**seen_messages** (deduplication, optional)
```sql
CREATE TABLE seen_messages (
    sender_peer_id TEXT NOT NULL,
    session_id BLOB NOT NULL,
    seq_no INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    PRIMARY KEY(sender_peer_id, session_id, seq_no)
);
```

---

## 15. Open Questions / Follow-ups

### 15.1 V1 Scope (Resolved for initial implementation)

**Finality thresholds (Q3):**
- **V1 Decision:** Part of group metadata/config, constant value included in group_id
- Example: `finality_blue_score_confirmations: 10` (10 blue score confirmations required)
- No runtime negotiation in V1

**Member rotation (Q2):**
- **V1 Decision:** Not supported in V1
- Member changes require new group (new group_id, fund movement)
- DKG/resharing handled by MPC libraries in future versions

**MPC/MuSig2 library interface (Q4, Q5):**
- **V1 Decision:** Standard interface preferred (trait-based)
- Single library per mode in V1 (e.g., Sodot for FROST, secp256k1-zkp for MuSig2)
- Multi-library support in future versions

**Fee estimation (Q7):**
- **V1 Decision:** Static/constant fee rate (sompi per gram)
- Part of group config: `fee_rate_sompi_per_gram: 10`
- Dynamic fee estimation in future versions
- Simple flow: coordinator proposes TX with static fee, signers validate fee is within bounds

**Fee payment consensus (Q8):**
- **V1 Decision:** `fee_payment_mode` part of group_id hash (immutable)
- All signers must agree on mode at group creation
- No runtime negotiation in V1
- Future: policy-based negotiation, per-event mode selection

**UTXO/output minimums (Q9, Q10, Q11):**
- **V1 Decision:** Constants in group config
- `dust_threshold_sompi: 1000` (minimum output value)
- `min_recipient_amount_sompi: 10000` (minimum payment amount)
- Simple validation: reject if below threshold

**Multi-recipient (Q11, Q20):**
- **Not in V1:** Single-recipient only
- Architecture designed for future extension
- Event schema supports multi-recipient (Phase 2 ready)

**Subnetwork support (Q14):**
- **Not in V1:** Native subnetwork only (`SUBNETWORK_ID_NATIVE`)
- Architecture aware: subnetwork_id in TX template
- Future: policy-based subnetwork routing

**Human approval / HW wallets (Q15):**
- **Not in V1:** Automated signing only
- Architecture supports pause/resume (timeout-based abort)
- Future: External approval hooks, hardware wallet integration

**Disaster recovery (Q16):**
- **V1 Decision:** Simple timeout-based abort
- Session timeout in policy: `session_timeout_seconds: 300`
- Coordinator failure → session expires → manual retry
- Future: Session resurrection, automatic failover

**Protocol migration (Q18):**
- **Not in V1:** No in-place migration
- Migration requires new group + fund movement
- Future: Re-keying protocols, backward compatibility

**MuSig2 nonce generation (Q19):**
- **Not in V1:** Delegated to library (secp256k1-zkp handles securely)
- No custom nonce derivation
- Future: Deterministic nonce backup schemes

**Multi-recipient ordering (Q20):**
- **V1 Decision:** Not applicable (single-recipient only)
- Future: Canonical ordering (sorted by address) for determinism

**Fee payment mode negotiation (Q21):**
- **V1 Decision:** Part of group policy (immutable in group_id)
- No per-event negotiation
- Future: Event-level mode proposal with signer approval

### 15.2 Still Open (Future versions)

1. **KPSBT field definitions:** Formal BIP 174-style specification document - needs detailed definition during Phase 1 implementation
2. **Group membership PKI:** Static PIK allowlist vs certificate chain - design during Phase 2
3. **Cross-chain event verification:** Multi-oracle consensus, light client proofs - Phase 8 (bridge integration)
4. **Policy update mechanism:** On-chain governance, threshold voting - post-V1 feature
5. **Advanced disaster recovery:** Session resurrection, coordinator failover - post-V1 hardening
6. **Metrics and monitoring:** Specific telemetry points, alert thresholds - Phase 6 (production hardening)

### 15.3 Architecture Future-Proofing

**V1 is designed to support future extensions without breaking changes:**

**Session lifecycle hooks:**
```rust
trait SessionHooks {
    // Called before signing starts (future: human approval)
    fn pre_sign_hook(&self, event: &SigningEvent) -> Result<Approval>;
    
    // Called after signatures collected (future: additional validation)
    fn post_sign_hook(&self, tx: &Transaction) -> Result<()>;
    
    // Called on session timeout (future: retry logic)
    fn on_timeout(&self, session: &Session) -> TimeoutAction;
}

enum TimeoutAction {
    Abort,              // V1: simple abort
    Retry,              // Future: automatic retry
    WaitForApproval,    // Future: wait for human approval
}
```

**Policy versioning:**
```rust
struct PolicyV1 {
    version: 1,
    // V1 fields
}

struct PolicyV2 {
    version: 2,
    // V1 fields + new fields
    dynamic_fee_enabled: bool,
    fee_market_integration: Option<FeeMarketConfig>,
}

// Forward-compatible deserialization
fn deserialize_policy(bytes: &[u8]) -> Result<Box<dyn Policy>> {
    let version = peek_version(bytes)?;
    match version {
        1 => Ok(Box::new(deserialize::<PolicyV1>(bytes)?)),
        2 => Ok(Box::new(deserialize::<PolicyV2>(bytes)?)),
        _ => Err(Error::UnsupportedPolicyVersion),
    }
}
```

**Event schema evolution:**
```rust
enum SigningEventV1 {
    Single(SingleRecipientEvent),
}

enum SigningEventV2 {
    Single(SingleRecipientEvent),
    Multi(MultiRecipientEvent),  // Phase 2
}

enum SigningEventV3 {
    Single(SingleRecipientEvent),
    Multi(MultiRecipientEvent),
    Conditional(ConditionalEvent),  // Future: conditional payments
}
```

**Protocol upgrade path:**
```rust
// V1: Simple version check
if kpsbt.version != 1 {
    return Err(Error::UnsupportedKpsbtVersion);
}

// Future: Backward compatibility
match kpsbt.version {
    1 => process_v1(kpsbt),
    2 => process_v2_with_v1_compat(kpsbt),
    3 => process_v3_with_v2_compat(kpsbt),
    _ => Err(Error::UnsupportedKpsbtVersion),
}
```

---

## 16. Next Steps (Implementation Roadmap)

**Phase 1: Foundation + Single-Recipient (1-2 months)**
1. Define KPSBT specification (BIP 174-style with Kaspa proprietary keys)
2. Implement embedded wallet wrapper using **rusty-kaspa-wallet v1.x SDK**
3. Build deterministic TX construction (single-recipient mode) using rusty-kaspa APIs
4. Implement `FeePaymentMode::RecipientPays` (default)
5. Implement event model + replay protection DB
6. Group ID derivation (deterministic from config)
7. KPSBT serialization/deserialization (reuse rust-bitcoin + rusty-kaspa extensions)
8. Basic Iroh pubsub integration
9. Integration testing with local **rusty-kaspa v1.x node**

**Phase 2: Multisig (2-3 months)**
8. Implement multisig coordination messages
9. Build coordinator agent (using rusty-kaspa-wallet v1.x SDK)
10. Build signer agent with local rusty-kaspa v1.x node integration
11. Policy engine (allowlist, limits, velocity, fee payment)
12. Validation: 2-output TXs (recipient + change)
13. Integration testing: 3-of-5 multisig with rusty-kaspa v1.x testnet nodes
14. Testnet deployment + testing

**Phase 3: FROST Integration (2-3 months)**
14. Define MPC library interface standard
15. Integrate Sodot MPC SDK (or Lit Protocol)
16. Implement FROST session coordination
17. MPC library abstraction layer
18. Testnet FROST testing (3-of-5 threshold)

**Phase 4: MuSig2 Integration (1-2 months)**
19. Define MuSig2 library interface standard
20. Integrate secp256k1-zkp MuSig2 module
21. Implement MuSig2 session coordination
22. Aggregate public key computation + verification
23. Testnet MuSig2 testing (3-of-3, 5-of-5)
24. Availability fallback logic (MuSig2 → FROST)

**Phase 5: Fee Payment Modes (1 month)**
25. Implement `FeePaymentMode::SignersPay`
26. Implement `FeePaymentMode::Split`
27. Fee payment mode validation in policy engine
28. Consensus mechanism for fee mode (if required)
29. Testnet testing: all fee modes

**Phase 6: Production Hardening (2-3 months)**
30. Security audit (internal + external)
31. Performance optimization (message batching, caching)
32. Monitoring + alerting (Prometheus, Grafana)
33. Disaster recovery testing
34. Mode comparison benchmarks (Multisig vs FROST vs MuSig2)
35. Fee payment mode stress testing
36. Mainnet deployment (staged rollout)

**Phase 7: Multi-Recipient Mode (2-3 months)**
37. Extend `SigningEvent` to `SigningEventMulti`
38. Implement multi-recipient TX construction
39. Extended validation: n+1 output TXs
40. Policy: max_recipients_per_tx enforcement
41. KPSBT extensions for multi-recipient
42. Testnet testing: batch payments (2-10 recipients)
43. Proportional fee splitting for multi-recipient
44. Mainnet rollout: multi-recipient support

**Phase 8: Cross-Chain Integration (3-4 months)**
45. Hyperlane event listener + validator
46. LayerZero endpoint integration
47. Multi-oracle event verification
48. Bridge UI/API (single + multi-recipient)
49. Production bridge launch

---

## 17. Potential Integration into rusty-kaspa Core

**Status:** Optional proposal for consideration by Kaspa core team and community

### 17.1 Proposal Overview

Once this threshold signing framework is production-proven and stable, the Kaspa community and core team may consider integrating it as an **official module** within the rusty-kaspa v1.x SDK ecosystem.

**Potential integration path:**
```
rusty-kaspa/
├── consensus/          (existing)
├── wallet/            (existing: rusty-kaspa-wallet)
├── rpc/               (existing)
├── mining/            (existing)
└── threshold-signing/ (new: this framework)
    ├── coordination/  (Iroh pubsub, protocol messages)
    ├── kpsbt/         (KPSBT serialization, validation)
    ├── multisig/      (Multisig implementation)
    ├── mpc/           (FROST MPC integration)
    ├── musig2/        (MuSig2 integration)
    └── event-model/   (Cross-chain event processing)
```

### 17.2 Benefits of Core Integration

**For Kaspa ecosystem:**
- **Official support:** Maintained by core team alongside rusty-kaspa
- **Standardization:** Single reference implementation for threshold signing
- **Quality assurance:** Same testing/audit standards as core components
- **Ecosystem adoption:** Easier integration for wallets, exchanges, bridges
- **Version alignment:** Synchronized releases with rusty-kaspa versions

**For developers:**
- **Single dependency:** `kaspa-threshold = "1.0"` instead of external crate
- **API consistency:** Same patterns as rusty-kaspa-wallet
- **Documentation:** Integrated docs.rs documentation
- **Support channels:** Official Kaspa support channels

**For bridges/DeFi:**
- **Trusted implementation:** Core team reviewed and maintained
- **Security updates:** Coordinated with rusty-kaspa security patches
- **Feature parity:** Stays current with Kaspa protocol upgrades

### 17.3 Integration Criteria

**Prerequisites for core integration consideration:**

1. **Production maturity:**
   - Mainnet deployment operational for 6+ months
   - Real-world usage with significant value secured
   - No critical bugs or security issues

2. **Security validation:**
   - External security audit completed
   - Bug bounty program completed
   - Penetration testing performed
   - No unresolved critical/high severity issues

3. **Code quality:**
   - Comprehensive test coverage (>80%)
   - Fuzzing for KPSBT parsing and validation
   - Property-based testing for deterministic TX construction
   - CI/CD pipeline with automated testing

4. **Documentation:**
   - Complete API documentation (rustdoc)
   - Integration guides for wallet developers
   - Security best practices guide
   - Example implementations

5. **Community consensus:**
   - Discussion on Kaspa forums/Discord
   - Review by Kaspa core developers
   - Community feedback incorporated
   - No major objections from stakeholders

### 17.4 Integration Proposal (If Approved)

**Phase 1: External crate (current plan)**
```toml
[dependencies]
kaspa-threshold-signing = "1.0"  # External crate
kaspa-wallet-core = "1.0"
kaspa-consensus = "1.0"
```

**Phase 2: Workspace integration (if accepted)**
```
rusty-kaspa workspace:
├── kaspa-threshold-signing/    # Move into workspace
├── kaspa-wallet-core/
├── kaspa-consensus/
└── ...
```

**Phase 3: Core module (if desired)**
```rust
// Single import for threshold signing
use kaspa::threshold::{
    Coordinator, Signer, Kpsbt,
    multisig::MultisigSigner,
    mpc::FrostSigner,
    musig2::MuSig2Signer,
};
```

### 17.5 Governance and Maintenance

**If integrated into core:**

**Ownership:**
- Code ownership: Kaspa core team
- Original authors: Acknowledged contributors
- License: Same as rusty-kaspa (ISC/MIT + BSL 2.0 if applicable)

**Maintenance model:**
- Core team reviews PRs
- Security issues handled via Kaspa security process
- Feature requests via Kaspa RFC process
- Breaking changes coordinated with rusty-kaspa releases

**Versioning:**
- Follows rusty-kaspa versioning (v1.x.y)
- Breaking changes only in major versions
- Backward compatibility within v1.x series

### 17.6 Alternative: Official Extension Crate

**If core integration is not desired:**

The framework can remain as an **official Kaspa extension crate**, similar to how Bitcoin has core + external modules:

```toml
[dependencies]
kaspa-threshold-signing = "1.0"  # Official but external
# Maintained by: Kaspa ecosystem developers
# Supported by: Kaspa community
# Security: Independent audits + community review
```

**Benefits of extension approach:**
- **Faster iteration:** Not bound to core release schedule
- **Experimentation:** Can evolve independently
- **Modular:** Optional for users who don't need threshold signing
- **Specialized maintenance:** Focused team on threshold cryptography

**Drawbacks:**
- Less visibility (not in main repo)
- Potential version drift with rusty-kaspa
- Separate security audit cycle

### 17.7 Decision Process

**Proposed process for community consideration:**

1. **Phase 1-6 completion:** Framework proven in production
2. **Community RFC:** Formal proposal to Kaspa community
3. **Core team review:** Technical assessment by Kaspa core developers
4. **Community feedback:** Public comment period (30 days)
5. **Decision:** Core team + community consensus
6. **Integration (if approved):** Gradual merge into rusty-kaspa workspace

**Key stakeholders:**
- Kaspa core team
- Kaspa community (forums, Discord)
- Bridge operators (would use this framework)
- Wallet developers
- Security researchers

### 17.8 No-Pressure Approach

**Important:** This is a **suggestion only**, not a requirement. The framework is designed to work excellently as:
- External crate (current plan)
- Community-maintained module
- Independent project

**Core integration is beneficial but not necessary for success.** The decision should be made by the Kaspa core team and community based on their priorities and resource availability.

### 17.9 Next Steps (If Interest Exists)

**If Kaspa core team and community are interested:**

1. **Post-Phase 6:** Create formal RFC with production metrics
2. **Technical review:** Present to core developers for feedback
3. **Community discussion:** Open thread on Kaspa Discord/forums
4. **Pilot integration:** Test workspace integration in separate branch
5. **Final decision:** Based on consensus and technical feasibility

**Timeline:** Earliest consideration after 12+ months of production usage (Phase 6 complete + stabilization period).

---


**Document version:** 0.3  
**Last updated:** 17/12/2025  
**Author:** dimdumon  
**License:** Business Source License 2.0 (BSL 2.0)

---

## Document Revision History

**v0.3 (17/12/2025):**
- Initial comprehensive specification
- Three signing modes: Multisig, FROST MPC, MuSig2
- Abstract event model for cross-chain integration
- Bitcoin PSBT format adopted (KPSBT)
- Transaction output modes (single/multi-recipient)
- Fee payment modes (RecipientPays, SignersPay, Split)
- rusty-kaspa v1.x as official SDK
- V1 scope decisions and architecture future-proofing
- Optional proposal for rusty-kaspa core integration
