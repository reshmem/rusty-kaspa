# Kaspa Threshold Signing - API Documentation

**Version:** 0.3  
**Date:** 17/12/2025  
**Author:** dimdumon

---

## Table of Contents

1. [External APIs Used](#external-apis-used)
2. [APIs Exposed by Framework](#apis-exposed-by-framework)
3. [Integration Examples](#integration-examples)

---

## External APIs Used

### 1. rusty-kaspa v1.x SDK APIs

The framework relies heavily on the official Kaspa SDK for all node and wallet operations.

#### 1.1 kaspa-wallet-core v1.x

**Purpose:** Core wallet functionality - key management, transaction construction, signing

```rust
use kaspa_wallet_core::api::WalletApi;
use kaspa_wallet_core::storage::UtxoEntry;

trait WalletApi {
    // UTXO management
    fn get_utxos(&self) -> Result<Vec<UtxoEntry>>;
    fn get_utxos_by_addresses(&self, addresses: &[Address]) -> Result<Vec<UtxoEntry>>;
    
    // Transaction construction
    fn construct_transaction(
        &self,
        outputs: Vec<TxOutput>,
        fee_rate: u64,
    ) -> Result<Transaction>;
    
    // Signing
    fn sign_schnorr(
        &self,
        signing_hash: &[u8; 32],
        key_index: usize,
    ) -> Result<Signature>;
    
    // Address derivation
    fn derive_address(&self, index: u32) -> Result<Address>;
    fn get_change_address(&self) -> Result<Address>;
}
```

**Used by:** Coordinator, all Signers  
**Purpose:** Deterministic transaction construction, UTXO selection, signing

---

#### 1.2 kaspa-consensus v1.x

**Purpose:** Consensus rules, transaction validation, signing hash computation

```rust
use kaspa_consensus::tx::{Transaction, TxInput, TxOutput};
use kaspa_consensus::sighash::{calc_schnorr_signature_hash, SighashType};

// Compute signing hash for input (critical for signature generation)
pub fn calc_schnorr_signature_hash(
    tx: &Transaction,
    input_index: usize,
    utxo_entry: &UtxoEntry,
    sighash_type: SighashType,
) -> [u8; 32];

// Transaction validation
pub fn validate_transaction(
    tx: &Transaction,
    utxo_context: &UtxoContext,
) -> Result<()>;

// Mass calculation (for fee estimation)
pub fn calc_transaction_mass(tx: &Transaction) -> u64;
```

**Used by:** All Signers, Coordinator  
**Purpose:** Signing hash computation (must be identical across all signers), TX validation

---

#### 1.3 kaspa-rpc-core v1.x

**Purpose:** Node RPC communication

```rust
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::{RpcClient, GetUtxosByAddressesRequest};

#[async_trait]
trait RpcApi {
    // UTXO queries
    async fn get_utxos_by_addresses(
        &self,
        addresses: Vec<Address>,
    ) -> RpcResult<GetUtxosByAddressesResponse>;
    
    // Current blue score
    async fn get_virtual_selected_parent_blue_score(&self) -> RpcResult<u64>;
    
    // Block queries
    async fn get_block(
        &self,
        block_hash: Hash,
        include_transactions: bool,
    ) -> RpcResult<Block>;
    
    // Transaction submission
    async fn submit_transaction(
        &self,
        transaction: Transaction,
        allow_orphan: bool,
    ) -> RpcResult<SubmitTransactionResponse>;
    
    // Transaction status
    async fn get_transaction(
        &self,
        tx_id: Hash,
        include_block_verbose: bool,
    ) -> RpcResult<GetTransactionResponse>;
    
    // Mempool queries
    async fn get_mempool_entry(&self, tx_id: Hash) -> RpcResult<MempoolEntry>;
    
    // Node info
    async fn get_server_info(&self) -> RpcResult<ServerInfo>;
}
```

**Connection example:**
```rust
let client = RpcClient::connect(
    "grpc://localhost:16110",  // Mainnet gRPC
    None,                       // No auth for local node
).await?;

// Verify node is synced
let info = client.get_server_info().await?;
assert!(info.is_synced, "Node must be fully synced");
```

**Used by:** All Signers  
**Purpose:** UTXO validation, transaction submission, mempool monitoring

---

#### 1.4 kaspa-addresses v1.x

**Purpose:** Address encoding/decoding (bech32m)

```rust
use kaspa_addresses::{Address, Prefix, Version};

impl Address {
    // Parse bech32m address
    pub fn from_str(s: &str) -> Result<Self>;
    
    // Encode to bech32m
    pub fn to_string(&self) -> String;
    
    // Extract script public key
    pub fn to_script_public_key(&self) -> ScriptPublicKey;
}
```

**Used by:** All Signers, Coordinator  
**Purpose:** Parse destination addresses from SigningEvent, validate format

---

#### 1.5 kaspa-txscript v1.x

**Purpose:** Script handling (multisig scripts)

```rust
use kaspa_txscript::{ScriptBuilder, opcodes};

// Build multisig script (for Multisig mode)
pub fn build_multisig_script(
    m: usize,
    pubkeys: &[PublicKey],
) -> Result<Vec<u8>>;

// Verify script signature
pub fn verify_script(
    script_sig: &[u8],
    script_pubkey: &[u8],
    tx: &Transaction,
    input_index: usize,
) -> Result<bool>;
```

**Used by:** Multisig mode signers  
**Purpose:** Construct and verify multisig spend conditions

---

### 2. MPC Library APIs (3rd Party)

These are external cryptographic libraries for FROST and MuSig2. The framework treats them as black boxes.

#### 2.1 FROST MPC (e.g., Sodot SDK, Lit Protocol)

**Purpose:** m-of-n threshold signatures via MPC

```rust
// Example interface (actual API depends on library)
trait MpcLibrary {
    // Initialize signing session
    fn init_session(
        session_id: String,
        participant_ids: Vec<String>,
        signing_hashes: Vec<[u8; 32]>,  // Per-input hashes
        threshold: u16,
    ) -> Result<MpcSessionHandle>;
    
    // Check readiness
    fn is_ready(handle: &MpcSessionHandle) -> bool;
    
    // Block until signatures produced (library handles all rounds)
    fn await_signatures(handle: &MpcSessionHandle) -> Result<Vec<Signature>>;
    
    // Optional: proof of correct execution
    fn get_proof(handle: &MpcSessionHandle) -> Option<Vec<u8>>;
}

struct Signature {
    input_index: u32,
    signature: [u8; 64],  // secp256k1 schnorr
}
```

**Example: Sodot integration**
```rust
use sodot_sdk::{SodotClient, SigningSession};

let sodot = SodotClient::new(config)?;
let session = sodot.init_signing_session(
    session_id,
    participant_ids,
    signing_hashes,
    threshold_m,
)?;

// Sodot handles all MPC rounds internally via its own network
let signatures = sodot.await_signatures(&session)?;
```

**Used by:** FROST mode signers  
**Purpose:** Produce aggregated threshold signatures without exposing individual shares  
**Communication:** Uses library's own P2P network (NOT Iroh)

---

#### 2.2 MuSig2 (e.g., secp256k1-zkp, libsecp256k1-rs)

**Purpose:** n-of-n signature aggregation

```rust
use secp256k1_zkp::{Secp256k1, musig::{MusigSession, MusigKeyAggCache}};

trait MuSig2Library {
    // Compute aggregate public key
    fn compute_aggregate_pubkey(
        pubkeys: &[PublicKey],
    ) -> Result<PublicKey>;
    
    // Initialize signing session
    fn init_session(
        session_id: String,
        participant_ids: Vec<String>,
        participant_pubkeys: Vec<PublicKey>,
        signing_hashes: Vec<[u8; 32]>,
    ) -> Result<MuSig2SessionHandle>;
    
    // Check readiness
    fn is_ready(handle: &MuSig2SessionHandle) -> bool;
    
    // Block until signatures produced (2 rounds internally)
    fn await_signatures(handle: &MuSig2SessionHandle) -> Result<Vec<Signature>>;
}
```

**Example: secp256k1-zkp integration**
```rust
use secp256k1_zkp::{Secp256k1, musig::*};

let secp = Secp256k1::new();

// Compute aggregate public key
let mut key_agg_cache = MusigKeyAggCache::new(&secp, &participant_pubkeys)?;
let aggregate_pubkey = key_agg_cache.agg_pk();

// Create session per input
let mut sessions: Vec<MusigSession> = signing_hashes.iter().map(|hash| {
    MusigSession::new(&secp, &my_key_agg_cache, hash, &my_secret_key)
}).collect::<Result<_>>()?;

// Library handles nonce exchange and signature aggregation
let signatures = await_musig2_signatures(&secp, &mut sessions)?;
```

**Used by:** MuSig2 mode signers  
**Purpose:** Produce single aggregate signature from n participants  
**Communication:** Uses library's protocol (NOT Iroh)

---

### 3. Other External APIs

#### 3.1 rust-bitcoin (PSBT support)

**Purpose:** Bitcoin PSBT base structures for KPSBT

```rust
use bitcoin::psbt::PartiallySignedTransaction;

// Use Bitcoin's PSBT as base, extend with Kaspa proprietary keys
struct Kpsbt {
    psbt_base: PartiallySignedTransaction,
    kaspa_extensions: KaspaExtensions,
}

// Serialization follows BIP 174
impl Kpsbt {
    fn serialize(&self) -> Vec<u8>;
    fn deserialize(bytes: &[u8]) -> Result<Self>;
}
```

**Used by:** KPSBT serialization/deserialization  
**Purpose:** Leverage proven PSBT format, extend with Kaspa fields

---

#### 3.2 Iroh (P2P networking)

**Purpose:** Gossip/pubsub for coordinator-signer communication

```rust
use iroh::gossip::{GossipClient, Message};

// Subscribe to topic
let subscription = gossip.subscribe(topic_id).await?;

// Publish message
gossip.publish(topic_id, message_bytes).await?;

// Receive messages
while let Some(msg) = subscription.next().await {
    handle_message(msg)?;
}
```

**Used by:** Coordinator, all Signers  
**Purpose:** Broadcast KPSBT, collect signatures, coordinate signing sessions

---

#### 3.3 Cryptographic Libraries

**blake3:**
```rust
use blake3::Hasher;

// Compute event_hash, group_id, validation_hash
let hash = blake3::hash(data);
```

**blake2:**
```rust
use blake2::{Blake2b, Digest};

// Compute signing_hash (Kaspa uses BLAKE2b-256)
let mut hasher = Blake2b::<U32>::new();
hasher.update(data);
let signing_hash = hasher.finalize();
```

**secp256k1:**
```rust
use secp256k1::{Secp256k1, schnorr, Message};

// Sign (multisig mode)
let secp = Secp256k1::new();
let keypair = Keypair::from_secret_key(&secp, &secret_key);
let msg = Message::from_slice(&signing_hash)?;
let signature = secp.sign_schnorr(&msg, &keypair);
```

**Used by:** All components  
**Purpose:** Hashing, signature generation/verification

---

## APIs Exposed by Framework

### 1. Public APIs (for integrators)

These APIs are exposed for bridges, exchanges, and other systems integrating threshold signing.

#### 1.1 Coordinator API

```rust
pub struct Coordinator {
    wallet: EmbeddedWallet,
    node: RpcClient,
    network: IrohClient,
    policy: GroupPolicy,
}

impl Coordinator {
    /// Create new signing session from external event
    pub async fn create_signing_session(
        &self,
        event: SigningEvent,
    ) -> Result<SessionId> {
        // 1. Validate event
        self.validate_event(&event).await?;
        
        // 2. Construct TX using embedded wallet
        let (tx, utxos) = self.wallet.construct_transaction(&event)?;
        
        // 3. Build KPSBT
        let kpsbt = self.build_kpsbt(&event, &tx, &utxos)?;
        
        // 4. Create session on Iroh
        let session_id = self.network.create_session(&kpsbt).await?;
        
        Ok(session_id)
    }
    
    /// Propose KPSBT to signers
    pub async fn propose_kpsbt(
        &self,
        session_id: SessionId,
        kpsbt: Kpsbt,
    ) -> Result<()> {
        // Serialize and broadcast via Iroh
        let kpsbt_bytes = kpsbt.serialize()?;
        self.network.publish_kpsbt(session_id, kpsbt_bytes).await
    }
    
    /// Collect signatures from signers
    pub async fn collect_signatures(
        &self,
        session_id: SessionId,
        timeout: Duration,
    ) -> Result<Vec<PartialSig>> {
        // Wait for threshold signatures
        self.network.await_signatures(session_id, timeout).await
    }
    
    /// Finalize transaction with collected signatures
    pub fn finalize_transaction(
        &self,
        kpsbt: Kpsbt,
        signatures: Vec<PartialSig>,
    ) -> Result<Transaction> {
        // Insert signatures into TX
        let mut tx = kpsbt.unsigned_tx.clone();
        self.insert_signatures(&mut tx, &signatures)?;
        
        // Validate final TX
        self.validate_final_tx(&tx)?;
        
        Ok(tx)
    }
    
    /// Broadcast signed transaction to Kaspa network
    pub async fn broadcast_transaction(
        &self,
        tx: Transaction,
    ) -> Result<TxId> {
        self.node.submit_transaction(tx, false).await
    }
    
    /// Monitor transaction status
    pub async fn monitor_transaction(
        &self,
        tx_id: TxId,
    ) -> Result<TransactionStatus> {
        self.node.get_transaction(tx_id, true).await
    }
}
```

**Usage example:**
```rust
// Bridge operator creates signing session
let event = SigningEvent {
    event_id: hyperlane_message_id,
    event_source: EventSource::Hyperlane { ... },
    destination: "kaspa:qr...".to_string(),
    amount: 50_000_000_000,  // 500 KAS in sompi
    metadata: EventMetadata::default(),
    timestamp: now(),
    signature: bridge_signature,
};

let session_id = coordinator.create_signing_session(event).await?;
let sigs = coordinator.collect_signatures(session_id, Duration::from_secs(60)).await?;
let final_tx = coordinator.finalize_transaction(kpsbt, sigs)?;
let tx_id = coordinator.broadcast_transaction(final_tx).await?;
```

---

#### 1.2 Signer API

```rust
pub struct Signer {
    wallet: EmbeddedWallet,
    node: RpcClient,
    network: IrohClient,
    policy: GroupPolicy,
    persistence: SignerDb,
    signing_backend: SigningBackend,  // Multisig | FROST | MuSig2
}

impl Signer {
    /// Validate incoming signing event
    pub async fn validate_event(
        &self,
        event: &SigningEvent,
    ) -> Result<()> {
        // 1. Check replay protection
        if self.persistence.event_seen(&event.event_hash())? {
            return Err(Error::EventReplayed);
        }
        
        // 2. Validate event source signature
        event.verify_signature()?;
        
        // 3. Check policy compliance
        self.policy.validate_event(event)?;
        
        Ok(())
    }
    
    /// Sign KPSBT (produces partial signature or MPC signature)
    pub async fn sign_kpsbt(
        &self,
        kpsbt: &Kpsbt,
    ) -> Result<SignatureResult> {
        // 1. Validate KPSBT
        self.validate_kpsbt(kpsbt).await?;
        
        // 2. Reconstruct TX from event (deterministic)
        let (my_tx, my_utxos) = self.wallet.construct_transaction(
            &kpsbt.signing_event
        )?;
        
        // 3. Verify TX matches coordinator's proposal
        if my_tx != kpsbt.unsigned_tx {
            return Err(Error::TransactionMismatch);
        }
        
        // 4. Compute validation_hash
        let my_validation_hash = self.compute_validation_hash(kpsbt)?;
        
        // 5. Sign using appropriate backend
        let result = match self.signing_backend {
            SigningBackend::Multisig => {
                self.sign_multisig(kpsbt).await?
            },
            SigningBackend::Frost(ref mpc) => {
                self.sign_frost(kpsbt, mpc).await?
            },
            SigningBackend::MuSig2(ref musig2) => {
                self.sign_musig2(kpsbt, musig2).await?
            },
        };
        
        // 6. Store in persistence (anti-replay)
        self.persistence.record_signing(
            &kpsbt.event_hash,
            &my_validation_hash,
            &result,
        )?;
        
        Ok(result)
    }
    
    /// Join existing signing session
    pub async fn join_session(
        &self,
        session_id: SessionId,
    ) -> Result<()> {
        self.network.subscribe_session(session_id).await
    }
    
    /// Query signing history (audit)
    pub fn get_signing_history(
        &self,
        filter: HistoryFilter,
    ) -> Result<Vec<SigningRecord>> {
        self.persistence.query_history(filter)
    }
}

pub enum SignatureResult {
    Partial(PartialSig),       // Multisig mode
    MpcAggregated(Signature),  // FROST mode
    MuSig2Aggregated(Signature), // MuSig2 mode
}
```

**Usage example:**
```rust
// Signer receives KPSBT via Iroh
signer.join_session(session_id).await?;

// When KPSBT arrives
let kpsbt = Kpsbt::deserialize(&kpsbt_bytes)?;
let sig_result = signer.sign_kpsbt(&kpsbt).await?;

// Broadcast signature back via Iroh
network.publish_signature(session_id, sig_result).await?;
```

---

### 2. Internal APIs (framework internals)

These are not exposed publicly but are documented for completeness.

#### 2.1 Event Processing

```rust
// Internal module: kaspa_threshold::event

pub fn validate_event_source(event: &SigningEvent) -> Result<()>;
pub fn compute_event_hash(event: &SigningEvent) -> Hash;
pub fn check_replay(db: &SignerDb, event_hash: &Hash) -> Result<bool>;
```

#### 2.2 KPSBT Operations

```rust
// Internal module: kaspa_threshold::kpsbt

pub fn serialize_kpsbt(kpsbt: &Kpsbt) -> Result<Vec<u8>>;
pub fn deserialize_kpsbt(bytes: &[u8]) -> Result<Kpsbt>;
pub fn validate_kpsbt(kpsbt: &Kpsbt, wallet: &EmbeddedWallet, node: &RpcClient) -> Result<()>;
pub fn compute_validation_hash(kpsbt: &Kpsbt) -> Hash;
```

#### 2.3 Transaction Construction

```rust
// Internal module: kaspa_threshold::tx_builder

pub fn construct_transaction_deterministic(
    event: &SigningEvent,
    utxos: &[UtxoEntry],
    policy: &GroupPolicy,
) -> Result<Transaction>;

pub fn select_utxos_deterministic(
    utxos: &[UtxoEntry],
    amount: u64,
    fee: u64,
) -> Result<Vec<UtxoEntry>>;

pub fn calculate_fee(
    num_inputs: usize,
    num_outputs: usize,
    fee_rate: u64,
) -> u64;
```

#### 2.4 Signature Handling

```rust
// Internal module: kaspa_threshold::signatures

pub fn insert_multisig_signatures(
    tx: &mut Transaction,
    signatures: &[PartialSig],
) -> Result<()>;

pub fn verify_signature(
    signature: &Signature,
    signing_hash: &[u8; 32],
    pubkey: &PublicKey,
) -> Result<bool>;
```

---

## Integration Examples

### Example 1: Bridge Integration (Hyperlane → Kaspa)

```rust
use kaspa_threshold::{Coordinator, SigningEvent, EventSource};

// Bridge listener receives Hyperlane message
async fn handle_hyperlane_message(msg: HyperlaneMessage) -> Result<()> {
    // 1. Convert to SigningEvent
    let event = SigningEvent {
        event_id: msg.message_id,
        event_source: EventSource::Hyperlane {
            chain_id: msg.origin_chain,
            contract: msg.contract_address,
            message_id: msg.message_id,
        },
        destination: msg.recipient,  // Kaspa address
        amount: msg.amount,
        metadata: EventMetadata {
            source_tx_hash: Some(msg.tx_hash),
            memo: msg.memo,
            priority: 1,
            ..Default::default()
        },
        timestamp: now(),
        signature: msg.signature,
    };
    
    // 2. Create signing session
    let coordinator = Coordinator::new(config)?;
    let session_id = coordinator.create_signing_session(event).await?;
    
    // 3. Wait for signatures
    let sigs = coordinator.collect_signatures(
        session_id,
        Duration::from_secs(120),
    ).await?;
    
    // 4. Finalize and broadcast
    let final_tx = coordinator.finalize_transaction(kpsbt, sigs)?;
    let tx_id = coordinator.broadcast_transaction(final_tx).await?;
    
    // 5. Monitor confirmation
    let status = coordinator.monitor_transaction(tx_id).await?;
    
    Ok(())
}
```

### Example 2: Treasury Management (Multi-sig)

```rust
// Treasury operator creates payment
let event = SigningEvent {
    event_id: uuid::Uuid::new_v4().into(),
    event_source: EventSource::Manual {
        operator: operator_pubkey,
    },
    destination: "kaspa:qr...".to_string(),
    amount: 1_000_000_000,  // 10 KAS
    metadata: EventMetadata {
        memo: Some("Q4 team payment".to_string()),
        priority: 0,
        ..Default::default()
    },
    timestamp: now(),
    signature: operator_sig,
};

// Submit to threshold signing group
let session_id = coordinator.create_signing_session(event).await?;

// 3-of-5 signers review and approve
// Once threshold reached, TX is finalized
```

---

**Document version:** 0.3  
**Last updated:** 17/12/2025  
**Author:** dimdumon  
**License:** Business Source License 2.0 (BSL 2.0)