# Hyperlane Integration

Integration plan for connecting igra-service to the real Hyperlane relayer.

---

## Overview

The Hyperlane relayer is a **pull-based** system. It reads messages from origin chains and calls destination chain APIs to deliver them. For Kaspa integration, we need:

1. **`hyperlane-kaspa` crate** in the Hyperlane monorepo - implements Hyperlane traits as HTTP clients
2. **Extended igra-service RPC API** - exposes endpoints the `hyperlane-kaspa` crate calls

### Simple Flow Diagram

```
┌─────────────────┐      ┌──────────────────────┐      ┌─────────────────┐
│   Origin Chain  │      │   Hyperlane Relayer  │      │   igra-service  │
│   (e.g., IGRA)  │      │   (Rust agent)       │      │   (Kaspa)       │
└────────┬────────┘      └──────────┬───────────┘      └────────┬────────┘
         │                         │                           │
    dispatch()                     │                           │
         │ ─────────────────────── │                           │
         │  1. reads messages      │                           │
         │◄─────────────────────── │                           │
         │                         │                           │
         │                         │  2. HTTP: POST /process   │
         │                         │ ────────────────────────► │
         │                         │                           │ threshold signing
         │                         │  3. TxOutcome             │ CRDT coordination
         │                         │◄──────────────────────────│ broadcast to Kaspa
         │                         │                           │
```

### Full Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           ORIGIN SIDE (IGRA/EVM)                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   User dApp                                                                     │
│       │                                                                         │
│       ▼                                                                         │
│   Mailbox.dispatch(destDomain, recipient, body)                                 │
│       │                                                                         │
│       ├──────────────────────────────────────────────┐                          │
│       ▼                                              ▼                          │
│   MerkleTreeHook                              InterchainGasPaymaster            │
│   (creates checkpoint)                        (handles gas payments)            │
│       │                                                                         │
│       │  Events emitted                                                         │
│       ▼                                                                         │
│   ┌─────────────────────────────────────────────────────────────┐               │
│   │                    VALIDATORS (3-of-5)                      │               │
│   │                                                             │               │
│   │   Validator 1        Validator 2        Validator 3         │               │
│   │       │                  │                  │               │               │
│   │       ▼                  ▼                  ▼               │               │
│   │   Sign checkpoint    Sign checkpoint    Sign checkpoint     │               │
│   │       │                  │                  │               │               │
│   │       ▼                  ▼                  ▼               │               │
│   │   S3://bucket-1      S3://bucket-2      S3://bucket-3       │               │
│   │                                                             │               │
│   └─────────────────────────────────────────────────────────────┘               │
│                              │                                                  │
│                              ▼                                                  │
│                    ValidatorAnnounce contract                                   │
│                    (stores S3 URLs for each validator)                          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         │ Relayer polls ValidatorAnnounce
                                         │ Fetches signatures from S3
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              RELAYER                                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   1. Index Mailbox.Dispatch events from IGRA                                    │
│   2. Query ValidatorAnnounce for storage locations                              │
│   3. Fetch checkpoint signatures from S3 buckets                                │
│   4. Wait for quorum (3-of-5 signatures)                                        │
│   5. Build ISM metadata (checkpoint + sigs + merkle proof)                      │
│   6. Call Kaspa Mailbox.process() via hyperlane-kaspa crate                     │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────┐               │
│   │  hyperlane-kaspa crate (HTTP client)                        │               │
│   │      │                                                      │               │
│   │      ├── KaspaMailbox.process(message, metadata)            │               │
│   │      ├── KaspaMailbox.delivered(messageId)                  │               │
│   │      └── KaspaMultisigIsm.validators_and_threshold()        │               │
│   └─────────────────────────────────────────────────────────────┘               │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         │ HTTP: POST /rpc (hyperlane.mailbox_process)
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         DESTINATION SIDE (KASPA)                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   igra-service (3 nodes, 2-of-3 threshold)                                      │
│       │                                                                         │
│       ├── 1. Receive Hyperlane message + ISM metadata                           │
│       ├── 2. Verify Hyperlane validator signatures (3-of-5)                     │
│       ├── 3. Extract destination address + amount from message body             │
│       ├── 4. Build Kaspa PSKT transaction                                       │
│       ├── 5. CRDT gossip for signature collection                               │
│       ├── 6. Collect 2-of-3 igra-service signatures                             │
│       ├── 7. Broadcast to Kaspa network                                         │
│       │                                                                         │
│       ▼                                                                         │
│   Kaspa Node (via gRPC)                                                         │
│       │                                                                         │
│       ▼                                                                         │
│   Transaction confirmed on Kaspa DAG                                            │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Two Separate Signature Sets

**Important:** There are TWO independent threshold signature schemes:

| Component | Signers | Threshold | Purpose |
|-----------|---------|-----------|---------|
| Hyperlane Validators | 5 operators on IGRA/EVM | 3-of-5 | Sign checkpoints (merkle root + nonce) to attest messages were dispatched |
| igra-service Signers | 3 operators on Kaspa | 2-of-3 | Sign Kaspa transactions to release funds |

These two groups can be (and typically are) operated by different entities.

### Message Ordering (FYI)

**Hyperlane does NOT enforce message ordering at the protocol level.**

#### What Hyperlane Tracks

- **Sequential nonce on dispatch** - Each message gets an incrementing index when dispatched
- **Merkle tree** - Messages are added to a merkle tree in order (for checkpoint proofs)
- **Message ID uniqueness** - Each message has a unique ID, and `delivered(id)` prevents replay

#### What Hyperlane Does NOT Enforce

The relayer can deliver messages **in any order**:

```
Origin (IGRA)                    Destination (Kaspa)
─────────────────                ────────────────────
dispatch() → msg #1
dispatch() → msg #2
dispatch() → msg #3
                                 process(msg #3) ✓  ← delivered first
                                 process(msg #1) ✓  ← delivered second
                                 process(msg #2) ✓  ← delivered third
```

The destination `Mailbox.process()` only checks:
- Is message ID already delivered? (no replay)
- Is ISM verification valid? (signatures)

It does **not** check: "Was the previous message delivered first?"

#### If Your Application Needs Ordering

Applications must implement ordering themselves. Options:

1. **Recipient-side enforcement** - Include sequence number in message body, recipient contract rejects out-of-order
2. **Queue and reorder** - igra-service could queue out-of-order messages and process when expected sequence arrives
3. **Application-level nonce** - Track per-sender nonces in the destination

Example (Solidity recipient):

```solidity
contract OrderedRecipient {
    uint256 public lastProcessedNonce;

    function handle(uint32 origin, bytes32 sender, bytes calldata body) external {
        uint256 nonce = abi.decode(body, (uint256, ...));
        require(nonce == lastProcessedNonce + 1, "Out of order");
        lastProcessedNonce = nonce;
        // ... process
    }
}
```

#### Why No Protocol-Level Ordering?

- **Performance** - Parallel processing is faster
- **Fault tolerance** - One stuck message doesn't block others
- **Gas optimization** - Relayer can batch/prioritize by gas costs

Most cross-chain use cases (token transfers, governance votes) don't require strict ordering.

---

## Part 0: Pre-Deployment Setup

Before any deployment, operators must agree on keys, thresholds, and infrastructure.

### 0.1 Participants & Roles

| Role | Count | Responsibility |
|------|-------|----------------|
| Hyperlane Validator Operators | 3-5 | Run validator software, sign origin chain checkpoints |
| igra-service Signer Operators | 3 | Run igra-service nodes, sign Kaspa transactions (2-of-3) |
| Relayer Operator | 1+ | Run relayer infrastructure |
| Contract Deployer | 1 | Deploy IGRA contracts on EVM chain |

### 0.2 Key Generation Ceremony

All key generation should be done on secure, air-gapped machines when possible.

**Step 1: Generate Hyperlane Validator Keys (each validator operator)**

```bash
# Generate secp256k1 key for Ethereum signing
cast wallet new
# Output example:
#   Successfully created new keypair.
#   Address:     0x1234567890abcdef1234567890abcdef12345678
#   Private key: 0xabc123...

# Share PUBLIC address only with other operators
# Keep private key secure (hardware wallet, KMS, or encrypted storage)
```

**Step 2: Generate igra-service Signer Keys (each signer operator)**

```bash
# Use existing igra key generation
# This generates Kaspa-compatible keys for threshold signing
./devnet-keygen generate --network kaspa

# Output includes xpub (extended public key)
# Share PUBLIC xpub only with other operators
# Keep private key secure
```

**Step 3: Collective Agreement Document**

All operators must sign off on a shared document containing:

```yaml
# IGRA-Kaspa Bridge Configuration Agreement
# Date: YYYY-MM-DD

# Domain IDs
igra_domain_id: 12345678        # IGRA EVM chain
kaspa_domain_id: 87654321       # Kaspa (destination)

# Hyperlane Validators (origin chain attestation)
hyperlane_validators:
  addresses:
    - "0x1111111111111111111111111111111111111111"  # Validator 1
    - "0x2222222222222222222222222222222222222222"  # Validator 2
    - "0x3333333333333333333333333333333333333333"  # Validator 3
    - "0x4444444444444444444444444444444444444444"  # Validator 4
    - "0x5555555555555555555555555555555555555555"  # Validator 5
  threshold: 3  # 3-of-5 required

# igra-service Signers (destination chain signing)
igra_service_signers:
  xpubs:
    - "xpub661MyMwAqRbcF..."  # Signer 1
    - "xpub661MyMwAqRbcG..."  # Signer 2
    - "xpub661MyMwAqRbcH..."  # Signer 3
  threshold: 2  # 2-of-3 required
  group_id: "<computed_from_xpubs>"

# S3 Checkpoint Storage
checkpoint_storage:
  - "s3://hyperlane-igra-validator-1"
  - "s3://hyperlane-igra-validator-2"
  - "s3://hyperlane-igra-validator-3"
  - "s3://hyperlane-igra-validator-4"
  - "s3://hyperlane-igra-validator-5"

# Signatures (operators sign this document)
signatures:
  validator_1: "0x..."
  validator_2: "0x..."
  # ... etc
```

### 0.3 S3 Bucket Setup (for validator checkpoints)

Each validator needs access to checkpoint storage. The relayer reads from all buckets.

**Option A: Per-validator S3 buckets (recommended for production)**

```bash
# Each validator operator creates their own bucket
aws s3 mb s3://hyperlane-igra-validator-1 --region us-east-1

# Create IAM policy for validator write access
cat > validator-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject"],
      "Resource": "arn:aws:s3:::hyperlane-igra-validator-1/*"
    }
  ]
}
EOF

aws iam create-policy \
  --policy-name HyperlaneValidator1Policy \
  --policy-document file://validator-policy.json
```

**Option B: Shared S3 bucket (simpler for devnet/testnet)**

```bash
# Single bucket with prefix-based access
aws s3 mb s3://hyperlane-igra-validators

# Validators write to: s3://hyperlane-igra-validators/validator-1/
# Validators write to: s3://hyperlane-igra-validators/validator-2/
# etc.
```

**Relayer read access (applied to ALL validator buckets)**

```bash
# Relayer needs read access to all validator buckets
cat > relayer-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::hyperlane-igra-validator-*",
        "arn:aws:s3:::hyperlane-igra-validator-*/*"
      ]
    }
  ]
}
EOF
```

### 0.4 Infrastructure Prerequisites

| Component | Requirement | Notes |
|-----------|-------------|-------|
| IGRA RPC | Private RPC endpoint | Not public; used by validators and relayer |
| Kaspa node | Full node with UTXO index | `--utxoindex` flag required |
| S3 buckets | One per validator (or shared) | See 0.3 above |
| KMS keys | Optional: AWS KMS for validator keys | Production recommended |
| Domain names | For validator announcement URLs | Can use S3 URLs directly |
| igra-service nodes | 3 machines for threshold signing | Can be VMs or containers |

### 0.5 Network Connectivity Requirements

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Network Diagram                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  IGRA RPC (EVM)                                                     │
│       │                                                             │
│       ├──► Validators (read Mailbox events)                         │
│       └──► Relayer (read Mailbox events, query ValidatorAnnounce)   │
│                                                                     │
│  S3 Buckets                                                         │
│       │                                                             │
│       ├──► Validators (write checkpoints)                           │
│       └──► Relayer (read checkpoints)                               │
│                                                                     │
│  igra-service (port 8088)                                           │
│       │                                                             │
│       └──► Relayer (HTTP: process messages)                         │
│                                                                     │
│  igra-service gossip (port 7777)                                    │
│       │                                                             │
│       └──► Other igra-service nodes (CRDT sync)                     │
│                                                                     │
│  Kaspa node (gRPC port 16110)                                       │
│       │                                                             │
│       └──► igra-service (submit transactions, query UTXOs)          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Part 1: hyperlane-kaspa Crate (Hyperlane Monorepo)

Location: `/rust/main/chains/hyperlane-kaspa/`

### 1.1 Crate Structure

```
hyperlane-kaspa/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── error.rs
│   ├── provider.rs         # KaspaProvider (HyperlaneProvider impl)
│   ├── mailbox.rs          # KaspaMailbox (Mailbox impl)
│   ├── ism.rs              # KaspaMultisigIsm (MultisigIsm + ISM impl)
│   ├── indexer.rs          # KaspaIndexer (Indexer impl)
│   ├── client.rs           # HTTP client for igra-service RPC
│   └── types.rs            # Request/response types
```

### 1.2 Connection Configuration

Add to `hyperlane-core/src/chain.rs`:

```rust
// In HyperlaneDomainProtocol enum
pub enum HyperlaneDomainProtocol {
    // ... existing ...
    /// Kaspa DAG-based chain using igra-service
    Kaspa,
}
```

Add to `hyperlane-base/src/settings/chains.rs`:

```rust
// In ChainConnectionConf enum
pub enum ChainConnectionConf {
    // ... existing ...
    /// Kaspa configuration
    Kaspa(h_kaspa::ConnectionConf),
}
```

### 1.3 ConnectionConf

```rust
// hyperlane-kaspa/src/lib.rs

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct ConnectionConf {
    /// Base URL of igra-service RPC (e.g., "http://127.0.0.1:8088")
    pub rpc_url: String,

    /// Optional authentication token
    #[serde(default)]
    pub rpc_token: Option<String>,

    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,

    /// Kaspa network prefix (e.g., "kaspa", "kaspatest", "kaspadev")
    pub network_prefix: String,
}

fn default_timeout() -> u64 { 30 }
```

### 1.4 KaspaProvider Implementation

```rust
// hyperlane-kaspa/src/provider.rs

use async_trait::async_trait;
use hyperlane_core::{
    BlockInfo, ChainInfo, ChainResult, HyperlaneChain, HyperlaneDomain,
    HyperlaneProvider, TxnInfo, H256, H512, U256,
};

#[derive(Clone, Debug)]
pub struct KaspaProvider {
    domain: HyperlaneDomain,
    client: KaspaRpcClient,
}

#[async_trait]
impl HyperlaneChain for KaspaProvider {
    fn domain(&self) -> &HyperlaneDomain {
        &self.domain
    }

    fn provider(&self) -> Box<dyn HyperlaneProvider> {
        Box::new(self.clone())
    }
}

#[async_trait]
impl HyperlaneProvider for KaspaProvider {
    /// Get block info by DAA score (Kaspa uses DAA score instead of block height)
    async fn get_block_by_height(&self, height: u64) -> ChainResult<BlockInfo> {
        // Call: GET /chain/block/{daa_score}
        self.client.get_block_by_daa_score(height).await
    }

    /// Get transaction info by hash
    async fn get_txn_by_hash(&self, hash: &H512) -> ChainResult<TxnInfo> {
        // Call: GET /chain/transaction/{tx_id}
        self.client.get_transaction(hash).await
    }

    /// Always returns true - Kaspa has no contracts, igra-service is the "contract"
    async fn is_contract(&self, _address: &H256) -> ChainResult<bool> {
        Ok(true)
    }

    /// Get balance for a Kaspa address
    async fn get_balance(&self, address: String) -> ChainResult<U256> {
        // Call: GET /chain/balance/{address}
        self.client.get_balance(&address).await
    }

    /// Get chain metrics (current blue score, DAA score, etc.)
    async fn get_chain_metrics(&self) -> ChainResult<Option<ChainInfo>> {
        // Call: GET /chain/info
        self.client.get_chain_info().await
    }
}
```

### 1.5 KaspaMailbox Implementation

```rust
// hyperlane-kaspa/src/mailbox.rs

use async_trait::async_trait;
use hyperlane_core::{
    ChainResult, ContractLocator, HyperlaneChain, HyperlaneContract, HyperlaneDomain,
    HyperlaneMessage, HyperlaneProvider, Mailbox, Metadata, ReorgPeriod,
    TxCostEstimate, TxOutcome, H256, U256,
};

#[derive(Clone, Debug)]
pub struct KaspaMailbox {
    domain: HyperlaneDomain,
    /// The "address" is the group_id of the signing group
    address: H256,
    provider: KaspaProvider,
    client: KaspaRpcClient,
}

impl HyperlaneContract for KaspaMailbox {
    fn address(&self) -> H256 {
        self.address
    }
}

impl HyperlaneChain for KaspaMailbox {
    fn domain(&self) -> &HyperlaneDomain {
        &self.domain
    }

    fn provider(&self) -> Box<dyn HyperlaneProvider> {
        Box::new(self.provider.clone())
    }
}

#[async_trait]
impl Mailbox for KaspaMailbox {
    /// Get the merkle tree count (nonce) - maps to processed event count
    async fn count(&self, _reorg_period: &ReorgPeriod) -> ChainResult<u32> {
        // Call: GET /mailbox/count
        self.client.get_mailbox_count().await
    }

    /// Check if a message has been delivered (event processed)
    async fn delivered(&self, message_id: H256) -> ChainResult<bool> {
        // Call: GET /mailbox/delivered/{message_id}
        self.client.is_message_delivered(message_id).await
    }

    /// Get the default ISM address (returns group_id)
    async fn default_ism(&self) -> ChainResult<H256> {
        // Call: GET /mailbox/default_ism
        self.client.get_default_ism().await
    }

    /// Get the ISM for a recipient (always returns default for Kaspa)
    async fn recipient_ism(&self, _recipient: H256) -> ChainResult<H256> {
        self.default_ism().await
    }

    /// Process a message - THIS IS THE MAIN ENTRY POINT
    /// Triggers threshold signing flow in igra-service
    async fn process(
        &self,
        message: &HyperlaneMessage,
        metadata: &Metadata,
        _tx_gas_limit: Option<U256>,
    ) -> ChainResult<TxOutcome> {
        // Call: POST /mailbox/process
        // This maps to existing hyperlane.mailbox_process RPC
        self.client.process_message(message, metadata).await
    }

    /// Estimate costs - Kaspa fees are minimal, return fixed estimate
    async fn process_estimate_costs(
        &self,
        message: &HyperlaneMessage,
        metadata: &Metadata,
    ) -> ChainResult<TxCostEstimate> {
        // Call: POST /mailbox/estimate_costs
        self.client.estimate_process_costs(message, metadata).await
    }

    /// Get calldata - not applicable for Kaspa
    async fn process_calldata(
        &self,
        _message: &HyperlaneMessage,
        _metadata: &Metadata,
    ) -> ChainResult<Vec<u8>> {
        Ok(vec![])
    }

    fn delivered_calldata(&self, _message_id: H256) -> ChainResult<Option<Vec<u8>>> {
        Ok(None)
    }
}
```

### 1.6 KaspaMultisigIsm Implementation

```rust
// hyperlane-kaspa/src/ism.rs

use async_trait::async_trait;
use hyperlane_core::{
    ChainResult, HyperlaneChain, HyperlaneContract, HyperlaneDomain,
    HyperlaneMessage, HyperlaneProvider, InterchainSecurityModule,
    Metadata, ModuleType, MultisigIsm, H256, U256,
};

#[derive(Clone, Debug)]
pub struct KaspaMultisigIsm {
    domain: HyperlaneDomain,
    address: H256,
    provider: KaspaProvider,
    client: KaspaRpcClient,
}

impl HyperlaneContract for KaspaMultisigIsm {
    fn address(&self) -> H256 {
        self.address
    }
}

impl HyperlaneChain for KaspaMultisigIsm {
    fn domain(&self) -> &HyperlaneDomain {
        &self.domain
    }

    fn provider(&self) -> Box<dyn HyperlaneProvider> {
        Box::new(self.provider.clone())
    }
}

#[async_trait]
impl InterchainSecurityModule for KaspaMultisigIsm {
    /// Returns the ISM module type
    async fn module_type(&self) -> ChainResult<ModuleType> {
        // Call: GET /ism/module_type
        // Returns MessageIdMultisig or MerkleRootMultisig based on config
        self.client.get_ism_module_type().await
    }

    /// Dry-run verification of signatures
    async fn dry_run_verify(
        &self,
        message: &HyperlaneMessage,
        metadata: &Metadata,
    ) -> ChainResult<Option<U256>> {
        // Call: POST /ism/dry_run_verify
        // Returns estimated gas (for Kaspa: fixed fee estimate)
        self.client.dry_run_verify(message, metadata).await
    }
}

#[async_trait]
impl MultisigIsm for KaspaMultisigIsm {
    /// Get validators and threshold for a message
    async fn validators_and_threshold(
        &self,
        message: &HyperlaneMessage,
    ) -> ChainResult<(Vec<H256>, u8)> {
        // Call: POST /ism/validators_and_threshold
        // Maps to existing hyperlane.validators_and_threshold RPC
        self.client.get_validators_and_threshold(message).await
    }
}
```

### 1.7 KaspaIndexer Implementation

```rust
// hyperlane-kaspa/src/indexer.rs

use async_trait::async_trait;
use hyperlane_core::{
    ChainResult, HyperlaneMessage, Indexed, Indexer, LogMeta,
    SequenceAwareIndexer, H256, H512,
};
use std::ops::RangeInclusive;

#[derive(Clone, Debug)]
pub struct KaspaMessageIndexer {
    client: KaspaRpcClient,
}

#[async_trait]
impl Indexer<HyperlaneMessage> for KaspaMessageIndexer {
    /// Fetch dispatched messages in a DAA score range
    /// NOTE: Kaspa is destination-only, this returns empty for outbound
    async fn fetch_logs_in_range(
        &self,
        range: RangeInclusive<u32>,
    ) -> ChainResult<Vec<(Indexed<HyperlaneMessage>, LogMeta)>> {
        // Call: GET /indexer/messages?from={start}&to={end}
        // For destination chain, this returns processed (delivered) messages
        self.client.get_messages_in_range(range).await
    }

    /// Get the latest finalized block (DAA score with sufficient blue score depth)
    async fn get_finalized_block_number(&self) -> ChainResult<u32> {
        // Call: GET /indexer/finalized_block
        self.client.get_finalized_daa_score().await
    }
}

#[async_trait]
impl SequenceAwareIndexer<HyperlaneMessage> for KaspaMessageIndexer {
    async fn latest_sequence_count_and_tip(&self) -> ChainResult<(Option<u32>, u32)> {
        // Call: GET /indexer/sequence_tip
        self.client.get_sequence_tip().await
    }
}

/// Indexer for delivery confirmations
#[derive(Clone, Debug)]
pub struct KaspaDeliveryIndexer {
    client: KaspaRpcClient,
}

#[async_trait]
impl Indexer<H256> for KaspaDeliveryIndexer {
    /// Fetch delivered message IDs in a DAA score range
    async fn fetch_logs_in_range(
        &self,
        range: RangeInclusive<u32>,
    ) -> ChainResult<Vec<(Indexed<H256>, LogMeta)>> {
        // Call: GET /indexer/deliveries?from={start}&to={end}
        self.client.get_deliveries_in_range(range).await
    }

    async fn get_finalized_block_number(&self) -> ChainResult<u32> {
        self.client.get_finalized_daa_score().await
    }
}

#[async_trait]
impl SequenceAwareIndexer<H256> for KaspaDeliveryIndexer {
    async fn latest_sequence_count_and_tip(&self) -> ChainResult<(Option<u32>, u32)> {
        self.client.get_delivery_sequence_tip().await
    }
}
```

### 1.8 HTTP Client

```rust
// hyperlane-kaspa/src/client.rs

use reqwest::Client;
use serde::{Deserialize, Serialize};
use hyperlane_core::{
    BlockInfo, ChainInfo, ChainResult, HyperlaneMessage, Indexed,
    LogMeta, Metadata, ModuleType, TxCostEstimate, TxOutcome, H256, H512, U256,
};

#[derive(Clone, Debug)]
pub struct KaspaRpcClient {
    http: Client,
    base_url: String,
    token: Option<String>,
}

impl KaspaRpcClient {
    pub fn new(base_url: String, token: Option<String>, timeout_seconds: u64) -> Self {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_seconds))
            .build()
            .expect("failed to build HTTP client");
        Self { http, base_url, token }
    }

    async fn post<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> ChainResult<R> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.post(&url).json(body);
        if let Some(token) = &self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        let resp = req.send().await.map_err(|e| /* convert to ChainError */)?;
        resp.json().await.map_err(|e| /* convert to ChainError */)
    }

    async fn get<R: for<'de> Deserialize<'de>>(&self, path: &str) -> ChainResult<R> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.get(&url);
        if let Some(token) = &self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        let resp = req.send().await.map_err(|e| /* convert */)?;
        resp.json().await.map_err(|e| /* convert */)
    }

    // Mailbox methods
    pub async fn get_mailbox_count(&self) -> ChainResult<u32> {
        self.get("/rpc/mailbox/count").await
    }

    pub async fn is_message_delivered(&self, id: H256) -> ChainResult<bool> {
        self.get(&format!("/rpc/mailbox/delivered/{:?}", id)).await
    }

    pub async fn process_message(
        &self,
        message: &HyperlaneMessage,
        metadata: &Metadata,
    ) -> ChainResult<TxOutcome> {
        // Reuse existing JSON-RPC format for compatibility
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "hyperlane.mailbox_process",
            "params": {
                "message": serialize_message(message),
                "metadata": serialize_metadata(metadata),
            }
        });
        self.post("/rpc", &payload).await
    }

    // ISM methods
    pub async fn get_validators_and_threshold(
        &self,
        message: &HyperlaneMessage,
    ) -> ChainResult<(Vec<H256>, u8)> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "hyperlane.validators_and_threshold",
            "params": {
                "message_id": format!("0x{}", hex::encode(message.id())),
                "destination_domain": message.destination,
                "origin_domain": message.origin,
            }
        });
        self.post("/rpc", &payload).await
    }

    // ... other methods
}
```

---

## Part 2: igra-service RPC Extensions

New endpoints to add in `igra-service/src/api/handlers/`.

### 2.1 New Endpoints Summary

| Endpoint | Method | Purpose | Maps To |
|----------|--------|---------|---------|
| `/rpc/mailbox/count` | GET | Get processed message count | New |
| `/rpc/mailbox/delivered/{id}` | GET | Check if message delivered | New |
| `/rpc/mailbox/default_ism` | GET | Get default ISM (group_id) | New |
| `/rpc/mailbox/estimate_costs` | POST | Estimate processing costs | New |
| `/rpc/ism/module_type` | GET | Get ISM type | New |
| `/rpc/ism/dry_run_verify` | POST | Verify signatures without processing | New |
| `/rpc/indexer/finalized_block` | GET | Get finalized DAA score | New |
| `/rpc/indexer/deliveries` | GET | Get delivered messages in range | New |
| `/rpc/indexer/sequence_tip` | GET | Get latest sequence and tip | New |
| `/rpc/chain/info` | GET | Get chain metrics | New |
| `/rpc/chain/block/{daa}` | GET | Get block by DAA score | New |
| `/rpc/chain/balance/{addr}` | GET | Get address balance | New |
| `hyperlane.mailbox_process` | JSON-RPC | Process message (existing) | Existing |
| `hyperlane.validators_and_threshold` | JSON-RPC | Get validators (existing) | Existing |

### 2.2 Storage Requirements

Add to `igra-core/src/infrastructure/storage/traits.rs`:

```rust
pub trait HyperlaneStorage: Send + Sync {
    /// Get count of successfully processed (delivered) messages
    fn get_delivered_count(&self) -> Result<u32>;

    /// Check if a message_id has been delivered
    fn is_message_delivered(&self, message_id: &Hash32) -> Result<bool>;

    /// Mark a message as delivered (after successful Kaspa tx broadcast)
    fn mark_message_delivered(&self, message_id: Hash32, tx_id: Hash32, daa_score: u64) -> Result<()>;

    /// Get delivered messages in DAA score range
    fn get_deliveries_in_range(&self, from_daa: u64, to_daa: u64) -> Result<Vec<DeliveryRecord>>;

    /// Get the highest DAA score with a delivery
    fn get_latest_delivery_daa_score(&self) -> Result<Option<u64>>;
}

#[derive(Clone, Debug)]
pub struct DeliveryRecord {
    pub message_id: Hash32,
    pub tx_id: Hash32,
    pub daa_score: u64,
    pub delivered_at_nanos: u64,
}
```

### 2.3 Handler Implementations

```rust
// igra-service/src/api/handlers/mailbox.rs

use axum::{extract::Path, Json};

/// GET /rpc/mailbox/count
pub async fn get_mailbox_count(
    State(state): State<RpcState>,
) -> Result<Json<MailboxCountResponse>, ApiError> {
    let count = state.storage.get_delivered_count()?;
    Ok(Json(MailboxCountResponse { count }))
}

#[derive(Serialize)]
pub struct MailboxCountResponse {
    pub count: u32,
}

/// GET /rpc/mailbox/delivered/{message_id}
pub async fn get_message_delivered(
    State(state): State<RpcState>,
    Path(message_id): Path<String>,
) -> Result<Json<DeliveredResponse>, ApiError> {
    let id = parse_h256(&message_id)?;
    let delivered = state.storage.is_message_delivered(&id)?;
    Ok(Json(DeliveredResponse { delivered }))
}

#[derive(Serialize)]
pub struct DeliveredResponse {
    pub delivered: bool,
}

/// GET /rpc/mailbox/default_ism
pub async fn get_default_ism(
    State(state): State<RpcState>,
) -> Result<Json<DefaultIsmResponse>, ApiError> {
    // Return the group_id as the ISM "address"
    let group_id = state.group_id_hex.as_ref()
        .ok_or(ApiError::NotConfigured("group_id not set"))?;
    Ok(Json(DefaultIsmResponse {
        ism: group_id.clone(),
    }))
}

#[derive(Serialize)]
pub struct DefaultIsmResponse {
    pub ism: String,
}

/// POST /rpc/mailbox/estimate_costs
pub async fn estimate_costs(
    State(state): State<RpcState>,
    Json(req): Json<EstimateCostsRequest>,
) -> Result<Json<EstimateCostsResponse>, ApiError> {
    // Kaspa has minimal fees - return fixed estimate
    // Could be more sophisticated based on UTXO count
    Ok(Json(EstimateCostsResponse {
        gas_limit: 100_000u64.into(), // Nominal value
        gas_price: 1u64.into(),       // 1 sompi/mass
        l2_gas_limit: None,
    }))
}
```

```rust
// igra-service/src/api/handlers/ism.rs

/// GET /rpc/ism/module_type
pub async fn get_module_type(
    State(state): State<RpcState>,
) -> Result<Json<ModuleTypeResponse>, ApiError> {
    let ism = state.hyperlane_ism.as_ref()
        .ok_or(ApiError::NotConfigured("hyperlane ISM not configured"))?;

    // Get mode from config
    let mode = ism.default_mode();
    let module_type = match mode {
        IsmMode::MessageIdMultisig => "message_id_multisig",
        IsmMode::MerkleRootMultisig => "merkle_root_multisig",
    };

    Ok(Json(ModuleTypeResponse { module_type: module_type.to_string() }))
}

/// POST /rpc/ism/dry_run_verify
pub async fn dry_run_verify(
    State(state): State<RpcState>,
    Json(req): Json<DryRunVerifyRequest>,
) -> Result<Json<DryRunVerifyResponse>, ApiError> {
    let ism = state.hyperlane_ism.as_ref()
        .ok_or(ApiError::NotConfigured("hyperlane ISM not configured"))?;

    let message = req.message.into_core()?;
    let metadata = req.metadata.into_core(message.id(), req.mode)?;

    match ism.verify_proof(&message, &metadata, req.mode) {
        Ok(_) => Ok(Json(DryRunVerifyResponse {
            success: true,
            gas_estimate: Some(100_000u64.into()),
            error: None,
        })),
        Err(e) => Ok(Json(DryRunVerifyResponse {
            success: false,
            gas_estimate: None,
            error: Some(e),
        })),
    }
}
```

```rust
// igra-service/src/api/handlers/indexer.rs

/// GET /rpc/indexer/finalized_block
pub async fn get_finalized_block(
    State(state): State<RpcState>,
) -> Result<Json<FinalizedBlockResponse>, ApiError> {
    // Get current DAA score minus confirmation depth
    let info = state.rpc.get_server_info().await?;
    let current_daa = info.virtual_daa_score;
    let confirmation_depth = state.config.utxo_confirmation_depth.unwrap_or(10);
    let finalized = current_daa.saturating_sub(confirmation_depth as u64);

    Ok(Json(FinalizedBlockResponse {
        finalized_block: finalized as u32,
    }))
}

/// GET /rpc/indexer/deliveries?from={from}&to={to}
pub async fn get_deliveries(
    State(state): State<RpcState>,
    Query(params): Query<RangeParams>,
) -> Result<Json<DeliveriesResponse>, ApiError> {
    let deliveries = state.storage.get_deliveries_in_range(
        params.from as u64,
        params.to as u64,
    )?;

    Ok(Json(DeliveriesResponse {
        deliveries: deliveries.into_iter().map(|d| DeliveryLog {
            message_id: format!("0x{}", hex::encode(d.message_id)),
            tx_id: format!("0x{}", hex::encode(d.tx_id)),
            daa_score: d.daa_score,
            timestamp_nanos: d.delivered_at_nanos,
        }).collect(),
    }))
}

/// GET /rpc/indexer/sequence_tip
pub async fn get_sequence_tip(
    State(state): State<RpcState>,
) -> Result<Json<SequenceTipResponse>, ApiError> {
    let count = state.storage.get_delivered_count()?;
    let latest_daa = state.storage.get_latest_delivery_daa_score()?;
    let tip = state.rpc.get_server_info().await?.virtual_daa_score as u32;

    Ok(Json(SequenceTipResponse {
        sequence: if count > 0 { Some(count) } else { None },
        tip,
    }))
}
```

```rust
// igra-service/src/api/handlers/chain.rs

/// GET /rpc/chain/info
pub async fn get_chain_info(
    State(state): State<RpcState>,
) -> Result<Json<ChainInfoResponse>, ApiError> {
    let info = state.rpc.get_server_info().await?;

    Ok(Json(ChainInfoResponse {
        virtual_daa_score: info.virtual_daa_score,
        past_median_time: info.past_median_time,
        pruning_point_hash: info.pruning_point_hash,
        network_name: info.network_id.to_string(),
        is_synced: info.is_synced,
    }))
}

/// GET /rpc/chain/block/{daa_score}
pub async fn get_block_by_daa(
    State(state): State<RpcState>,
    Path(daa_score): Path<u64>,
) -> Result<Json<BlockInfoResponse>, ApiError> {
    // Kaspa doesn't have single blocks at DAA scores
    // Return virtual chain block at that DAA score
    let block = state.rpc.get_block_at_daa_score(daa_score).await?;

    Ok(Json(BlockInfoResponse {
        hash: format!("0x{}", hex::encode(block.hash)),
        daa_score: block.header.daa_score,
        timestamp: block.header.timestamp,
        blue_score: block.header.blue_score,
    }))
}

/// GET /rpc/chain/balance/{address}
pub async fn get_balance(
    State(state): State<RpcState>,
    Path(address): Path<String>,
) -> Result<Json<BalanceResponse>, ApiError> {
    let balance = state.rpc.get_balance_by_address(&address).await?;

    Ok(Json(BalanceResponse {
        balance: balance.to_string(),
    }))
}
```

### 2.4 Router Updates

```rust
// igra-service/src/api/router.rs

pub fn create_router(state: RpcState) -> Router {
    Router::new()
        // Existing routes
        .route("/rpc", post(json_rpc_handler))
        .route("/health", get(health_handler))

        // New Hyperlane-compatible REST routes
        .route("/rpc/mailbox/count", get(mailbox::get_mailbox_count))
        .route("/rpc/mailbox/delivered/:id", get(mailbox::get_message_delivered))
        .route("/rpc/mailbox/default_ism", get(mailbox::get_default_ism))
        .route("/rpc/mailbox/estimate_costs", post(mailbox::estimate_costs))

        .route("/rpc/ism/module_type", get(ism::get_module_type))
        .route("/rpc/ism/dry_run_verify", post(ism::dry_run_verify))

        .route("/rpc/indexer/finalized_block", get(indexer::get_finalized_block))
        .route("/rpc/indexer/deliveries", get(indexer::get_deliveries))
        .route("/rpc/indexer/sequence_tip", get(indexer::get_sequence_tip))

        .route("/rpc/chain/info", get(chain::get_chain_info))
        .route("/rpc/chain/block/:daa", get(chain::get_block_by_daa))
        .route("/rpc/chain/balance/:address", get(chain::get_balance))

        .with_state(state)
}
```

### 2.5 Delivery Tracking

Update the signing flow to mark messages as delivered:

```rust
// igra-service/src/service/coordination/mod.rs

/// Called after successful Kaspa transaction broadcast
pub async fn on_transaction_broadcast(
    ctx: &EventContext,
    event_id: Hash32,
    message_id: Hash32,  // Hyperlane message ID from metadata
    tx_id: Hash32,
    daa_score: u64,
) -> Result<(), ThresholdError> {
    // Mark the Hyperlane message as delivered
    ctx.storage.mark_message_delivered(message_id, tx_id, daa_score)?;

    info!(
        "hyperlane message delivered message_id={} tx_id={} daa_score={}",
        hex::encode(message_id),
        hex::encode(tx_id),
        daa_score
    );

    Ok(())
}
```

---

## Part 3: Configuration

### 3.1 Hyperlane Relayer Config

Example `agent-config.json` for Kaspa destination:

```json
{
  "chains": {
    "kaspa": {
      "name": "kaspa",
      "domainId": 12345678,
      "protocol": "kaspa",
      "rpcUrl": "http://igra-service:8088",
      "rpcToken": "optional-auth-token",
      "timeoutSeconds": 30,
      "networkPrefix": "kaspa",
      "addresses": {
        "mailbox": "0x<group_id_hex>",
        "interchainSecurityModule": "0x<group_id_hex>"
      },
      "index": {
        "from": 0,
        "chunk": 1000
      },
      "reorgPeriod": 10
    }
  },
  "defaultSigner": {
    "type": "hexKey",
    "key": "0x..."
  }
}
```

### 3.2 igra-service Config Updates

```toml
# igra.toml

[hyperlane]
enabled = true
domain_id = 12345678
mode = "message_id_multisig"  # or "merkle_root_multisig"

[hyperlane.validators]
# Validator public keys for signature verification
keys = [
  "0x...",
  "0x...",
  "0x..."
]
threshold = 2
```

---

## Part 4: Implementation Phases

### Phase 1: Core API (Week 1)
- [ ] Add `HyperlaneStorage` trait and RocksDB implementation
- [ ] Implement `/rpc/mailbox/*` endpoints
- [ ] Implement `/rpc/ism/*` endpoints
- [ ] Add delivery tracking to signing flow

### Phase 2: Indexer API (Week 2)
- [ ] Implement `/rpc/indexer/*` endpoints
- [ ] Implement `/rpc/chain/*` endpoints
- [ ] Add DAA score tracking for deliveries

### Phase 3: hyperlane-kaspa Crate (Week 3)
- [ ] Create crate structure in hyperlane-monorepo
- [ ] Implement `KaspaProvider`
- [ ] Implement `KaspaMailbox`
- [ ] Implement `KaspaMultisigIsm`
- [ ] Implement `KaspaIndexer`

### Phase 4: Integration (Week 4)
- [ ] Add `Kaspa` to `HyperlaneDomainProtocol` enum
- [ ] Add `ChainConnectionConf::Kaspa` variant
- [ ] Wire up chain builder in `hyperlane-base`
- [ ] End-to-end testing with real relayer

---

## Part 5: Testing Strategy

### 5.1 Unit Tests (igra-service)
```rust
#[tokio::test]
async fn test_mailbox_count_increments_on_delivery() { ... }

#[tokio::test]
async fn test_delivered_returns_true_after_broadcast() { ... }

#[tokio::test]
async fn test_dry_run_verify_validates_signatures() { ... }
```

### 5.2 Integration Tests (hyperlane-kaspa)
```rust
#[tokio::test]
async fn test_mailbox_process_triggers_signing() { ... }

#[tokio::test]
async fn test_indexer_returns_deliveries() { ... }
```

### 5.3 E2E Test Setup
```bash
# 1. Start local Kaspa devnet
./kaspad --devnet --utxoindex

# 2. Start igra-service (3 nodes)
./igra-service --config igra-1.toml &
./igra-service --config igra-2.toml &
./igra-service --config igra-3.toml &

# 3. Start Hyperlane relayer with Kaspa config
./relayer --config agent-config.json

# 4. Dispatch message from origin chain (e.g., Sepolia)
# 5. Verify relayer calls igra-service and transaction appears on Kaspa
```

---

## Part 6: Hyperlane Validator Setup (IGRA Origin Chain)

Validators monitor the IGRA Mailbox contract and sign checkpoints. They are the first line of security - they attest that a message was actually dispatched on the origin chain.

### 6.1 What Validators Do

1. Watch for `Dispatch` events on Mailbox contract
2. Wait for finality (N blocks, configurable as `reorgPeriod`)
3. Sign checkpoint (merkle root + message index)
4. Publish signature to S3/storage
5. Announce storage location via ValidatorAnnounce contract

### 6.2 Validator Configuration

```yaml
# validator-config.yaml
originChainName: igra
validator:
  type: hexKey
  key: "${VALIDATOR_PRIVATE_KEY}"  # or use AWS KMS
checkpointSyncer:
  type: s3
  bucket: hyperlane-igra-validator-1
  region: us-east-1
interval: 30          # seconds between checks
reorgPeriod: 10       # blocks to wait for finality
```

Full configuration options:

```yaml
# Full validator configuration
chains:
  igra:
    name: igra
    domainId: 12345678
    protocol: ethereum
    rpcUrls:
      - "https://rpc.igra.network"
    blocks:
      reorgPeriod: 10       # blocks before message is considered final
      confirmations: 1

originChainName: igra

validator:
  # Option 1: Hex key (development only)
  type: hexKey
  key: "0xabc123..."

  # Option 2: AWS KMS (production recommended)
  # type: aws
  # id: "alias/hyperlane-validator-1"
  # region: "us-east-1"

checkpointSyncer:
  # Option 1: S3
  type: s3
  bucket: hyperlane-igra-validator-1
  region: us-east-1
  folder: ""  # optional subfolder

  # Option 2: Local filesystem (development)
  # type: localStorage
  # path: /data/checkpoints

interval: 30  # seconds between checking for new messages
```

### 6.3 Running a Validator

**Build from hyperlane-monorepo:**

```bash
cd /path/to/hyperlane-monorepo/rust/main
cargo build --release --bin validator
```

**Run with command-line arguments:**

```bash
./target/release/validator \
  --originChainName igra \
  --validator.type hexKey \
  --validator.key "0x${VALIDATOR_KEY}" \
  --checkpointSyncer.type s3 \
  --checkpointSyncer.bucket hyperlane-igra-validator-1 \
  --checkpointSyncer.region us-east-1 \
  --reorgPeriod 10 \
  --db /data/validator
```

**Run with config file:**

```bash
./target/release/validator --config /config/validator-config.yaml
```

**Run with environment variables:**

```bash
export HYP_BASE_ORIGINCHAINNAME=igra
export HYP_BASE_VALIDATOR_TYPE=hexKey
export HYP_BASE_VALIDATOR_KEY=0x...
export HYP_BASE_CHECKPOINTSYNCER_TYPE=s3
export HYP_BASE_CHECKPOINTSYNCER_BUCKET=hyperlane-igra-validator-1
export HYP_BASE_CHECKPOINTSYNCER_REGION=us-east-1
export HYP_BASE_DB=/data/validator

./target/release/validator
```

### 6.4 Validator Announcement

After validator is running and publishing checkpoints, announce its storage location on-chain:

```bash
# Get the storage location string
STORAGE_LOCATION="s3://hyperlane-igra-validator-1/us-east-1"

# Sign the announcement (validator signs their own address + storage location)
# This proves the validator controls the key
ANNOUNCEMENT_SIGNATURE=$(cast wallet sign \
  --private-key $VALIDATOR_KEY \
  $(cast keccak "$(echo -n "${VALIDATOR_ADDRESS}${STORAGE_LOCATION}" | xxd -p -c 1000)")
)

# Call ValidatorAnnounce contract on IGRA
cast send $VALIDATOR_ANNOUNCE_ADDRESS \
  "announce(address,string,bytes)" \
  $VALIDATOR_ADDRESS \
  "$STORAGE_LOCATION" \
  $ANNOUNCEMENT_SIGNATURE \
  --private-key $DEPLOYER_KEY \
  --rpc-url $IGRA_RPC
```

**Verify announcement:**

```bash
# Query announced validators
cast call $VALIDATOR_ANNOUNCE_ADDRESS \
  "getAnnouncedValidators()(address[])" \
  --rpc-url $IGRA_RPC

# Query storage location for a validator
cast call $VALIDATOR_ANNOUNCE_ADDRESS \
  "getAnnouncedStorageLocations(address[])(string[][])" \
  "[$VALIDATOR_ADDRESS]" \
  --rpc-url $IGRA_RPC
```

### 6.5 AWS KMS Setup (Production)

For production deployments, use AWS KMS to manage validator keys:

```bash
# Create KMS key for validator
aws kms create-key \
  --description "Hyperlane Validator 1 - IGRA Origin" \
  --key-usage SIGN_VERIFY \
  --key-spec ECC_SECG_P256K1  # secp256k1 for Ethereum

# Get key ID
KEY_ID=$(aws kms list-keys --query 'Keys[0].KeyId' --output text)

# Create alias for easier reference
aws kms create-alias \
  --alias-name alias/hyperlane-validator-1 \
  --target-key-id $KEY_ID

# Get public key (for collective agreement document)
aws kms get-public-key --key-id $KEY_ID

# Configure validator to use KMS
./validator \
  --validator.type aws \
  --validator.id alias/hyperlane-validator-1 \
  --validator.region us-east-1
```

**IAM policy for KMS access:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Sign",
        "kms:GetPublicKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:ACCOUNT:key/KEY_ID"
    }
  ]
}
```

### 6.6 Monitoring Validators

**Health check endpoints:**

```bash
# Validator exposes metrics on port 9090
curl http://localhost:9090/metrics

# Key metrics to monitor:
# - hyperlane_latest_checkpoint_index: latest signed checkpoint
# - hyperlane_checkpoint_latency_seconds: time between event and signature
```

**Log monitoring:**

```bash
# Watch for successful checkpoint signatures
tail -f /var/log/validator.log | grep "signed checkpoint"

# Watch for errors
tail -f /var/log/validator.log | grep -i error
```

---

## Part 7: Relayer Deployment

The relayer is the bridge that moves messages from origin to destination. It collects validator signatures and submits them to the destination chain.

### 7.1 What the Relayer Does

1. Polls origin chain (IGRA) for dispatched messages via Mailbox events
2. Fetches validator signatures from S3/announced storage locations
3. Waits for quorum (e.g., 3-of-5 signatures)
4. Constructs ISM metadata (checkpoint + signatures + merkle proof)
5. Calls destination chain's `Mailbox.process()` (via hyperlane-kaspa crate)
6. Retries failed deliveries with exponential backoff

### 7.2 Building Relayer with Kaspa Support

```bash
cd /path/to/hyperlane-monorepo/rust/main

# Standard build (after hyperlane-kaspa crate is added)
cargo build --release --bin relayer

# With explicit Kaspa feature (if feature-gated)
cargo build --release --bin relayer --features kaspa
```

### 7.3 Relayer Configuration

**Minimal configuration:**

```json
{
  "chains": {
    "igra": {
      "name": "igra",
      "domainId": 12345678,
      "protocol": "ethereum",
      "rpcUrls": ["https://rpc.igra.network"],
      "addresses": {
        "mailbox": "0x...",
        "merkleTreeHook": "0x...",
        "interchainGasPaymaster": "0x...",
        "validatorAnnounce": "0x..."
      },
      "index": { "from": 0, "chunk": 1000 }
    },
    "kaspa": {
      "name": "kaspa",
      "domainId": 87654321,
      "protocol": "kaspa",
      "rpcUrl": "http://igra-service:8088",
      "addresses": {
        "mailbox": "0x<group_id_hex>",
        "interchainSecurityModule": "0x<group_id_hex>"
      }
    }
  },
  "defaultSigner": {
    "type": "hexKey",
    "key": "0x..."
  }
}
```

**Full configuration:**

```json
{
  "chains": {
    "igra": {
      "name": "igra",
      "domainId": 12345678,
      "protocol": "ethereum",
      "rpcUrls": [
        "https://rpc.igra.network",
        "https://rpc-backup.igra.network"
      ],
      "addresses": {
        "mailbox": "0x...",
        "merkleTreeHook": "0x...",
        "interchainGasPaymaster": "0x...",
        "validatorAnnounce": "0x..."
      },
      "index": {
        "from": 0,
        "chunk": 1000
      },
      "blocks": {
        "reorgPeriod": 10,
        "confirmations": 1
      }
    },
    "kaspa": {
      "name": "kaspa",
      "domainId": 87654321,
      "protocol": "kaspa",
      "rpcUrl": "http://igra-service:8088",
      "rpcToken": "optional-bearer-token",
      "timeoutSeconds": 60,
      "networkPrefix": "kaspa",
      "addresses": {
        "mailbox": "0x<group_id_hex>",
        "interchainSecurityModule": "0x<group_id_hex>"
      },
      "index": {
        "from": 0,
        "chunk": 1000
      }
    }
  },
  "defaultSigner": {
    "type": "hexKey",
    "key": "0x..."
  },
  "relayChains": ["igra", "kaspa"],
  "db": "/data/relayer",
  "allowLocalCheckpointSyncers": false,
  "gasPaymentEnforcement": {
    "type": "none"
  }
}
```

### 7.4 Running the Relayer

**Command line:**

```bash
./target/release/relayer \
  --relayChains igra,kaspa \
  --db /data/relayer \
  --config /config/relayer-config.json \
  --allowLocalCheckpointSyncers false
```

**Environment variables:**

```bash
export HYP_BASE_RELAYCHAINS=igra,kaspa
export HYP_BASE_DB=/data/relayer
export CONFIG_FILES=/config/relayer-config.json
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1

./target/release/relayer
```

### 7.5 Docker Deployment

**Dockerfile:**

```dockerfile
FROM rust:1.75-slim as builder

WORKDIR /app
COPY .. .
RUN cargo build --release --bin relayer

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/relayer /usr/local/bin/

ENTRYPOINT ["relayer"]
```

**docker-compose.yaml:**

```yaml
version: '3.8'

services:
  relayer:
    image: hyperlane-relayer:latest
    build:
      context: /path/to/hyperlane-monorepo/rust/main
      dockerfile: Dockerfile.relayer
    volumes:
      - relayer-db:/data/relayer
      - ./config:/config:ro
    environment:
      - CONFIG_FILES=/config/relayer-config.json
      - HYP_BASE_RELAYCHAINS=igra,kaspa
      - HYP_BASE_DB=/data/relayer
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
      - AWS_REGION=us-east-1
    ports:
      - "9090:9090"  # metrics
    restart: unless-stopped
    networks:
      - hyperlane
    depends_on:
      - igra-service-1
      - igra-service-2
      - igra-service-3

  igra-service-1:
    image: igra-service:latest
    volumes:
      - igra-1-db:/data
      - ./config/igra-1.toml:/config/igra.toml:ro
    environment:
      - RUST_LOG=info,igra=debug
    ports:
      - "8088:8088"
      - "7777:7777"
    networks:
      - hyperlane

  # igra-service-2 and igra-service-3 similar...

volumes:
  relayer-db:
  igra-1-db:
  igra-2-db:
  igra-3-db:

networks:
  hyperlane:
    driver: bridge
```

### 7.6 Kubernetes Deployment

**Using Hyperlane's Helm chart:**

```bash
# Clone hyperlane-monorepo
git clone https://github.com/hyperlane-xyz/hyperlane-monorepo.git
cd hyperlane-monorepo/rust/main/helm

# Install relayer
helm install relayer ./hyperlane-agent \
  --set role=relayer \
  --set-file config=/path/to/relayer-config.json \
  --set storage.size=32Gi \
  --set resources.requests.memory=2Gi \
  --set resources.requests.cpu=1

# Or with values file
helm install relayer ./hyperlane-agent -f relayer-values.yaml
```

**relayer-values.yaml:**

```yaml
role: relayer

config:
  chains:
    igra:
      domainId: 12345678
      # ... rest of config
    kaspa:
      domainId: 87654321
      protocol: kaspa
      rpcUrl: http://igra-service:8088

storage:
  size: 32Gi
  storageClass: standard

resources:
  requests:
    memory: 2Gi
    cpu: 1
  limits:
    memory: 4Gi
    cpu: 2

env:
  - name: AWS_ACCESS_KEY_ID
    valueFrom:
      secretKeyRef:
        name: aws-credentials
        key: access-key-id
  - name: AWS_SECRET_ACCESS_KEY
    valueFrom:
      secretKeyRef:
        name: aws-credentials
        key: secret-access-key
```

### 7.7 Relayer Monitoring

**Prometheus metrics:**

```bash
# Relayer exposes metrics on port 9090
curl http://localhost:9090/metrics

# Key metrics:
# - hyperlane_messages_processed_total: total messages relayed
# - hyperlane_message_latency_seconds: time from dispatch to delivery
# - hyperlane_wallet_balance: relayer wallet balance (for gas)
```

**Alerting rules:**

```yaml
groups:
  - name: hyperlane-relayer
    rules:
      - alert: RelayerNotProcessing
        expr: increase(hyperlane_messages_processed_total[1h]) == 0
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Relayer has not processed any messages in 1 hour"

      - alert: RelayerHighLatency
        expr: hyperlane_message_latency_seconds > 600
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Relayer message latency exceeds 10 minutes"
```

---

## Part 8: Checkpoint Storage (S3)

Validators write signed checkpoints to S3; the relayer reads them. This decoupled architecture allows validators and relayers to operate independently.

### 8.1 How Checkpoints Flow

```
┌───────────────────────────────────────────────────────────────────────┐
│                      CHECKPOINT FLOW                                  │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   Mailbox (IGRA)                                                      │
│       │                                                               │
│       │ Dispatch event                                                │
│       ▼                                                               │
│   ┌─────────────────────────────────────────────────────────────┐     │
│   │  Validator 1        Validator 2        Validator 3          │     │
│   │      │                  │                  │                │     │
│   │      │ sign             │ sign             │ sign           │     │
│   │      ▼                  ▼                  ▼                │     │
│   │  S3://bucket-1      S3://bucket-2      S3://bucket-3        │     │
│   │  /checkpoint_42.json                                        │     │
│   └─────────────────────────────────────────────────────────────┘     │
│                                 │                                     │
│                                 │ Relayer reads from all buckets      │
│                                 │ Needs 3-of-5 signatures             │
│                                 ▼                                     │
│   ┌─────────────────────────────────────────────────────────────┐     │
│   │                        RELAYER                              │     │
│   │                                                             │     │
│   │   1. Query ValidatorAnnounce for storage locations          │     │
│   │   2. Fetch checkpoint from each validator's S3              │     │
│   │   3. Verify signatures                                      │     │
│   │   4. Wait for quorum (3-of-5)                               │     │
│   │   5. Package metadata and send to destination               │     │
│   └─────────────────────────────────────────────────────────────┘     │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

### 8.2 Checkpoint File Format

**Checkpoint signature file** (`<checkpoint_index>.json`):

```json
{
  "value": {
    "checkpoint": {
      "merkle_tree_hook_address": "0x1234567890abcdef1234567890abcdef12345678",
      "mailbox_domain": 12345678,
      "root": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
      "index": 42
    },
    "message_id": "0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba"
  },
  "signature": {
    "r": "0x...",
    "s": "0x...",
    "v": 27
  }
}
```

**Announcement file** (`announcement.json`):

```json
{
  "value": {
    "validator": "0x1111111111111111111111111111111111111111",
    "mailbox_address": "0x...",
    "mailbox_domain": 12345678,
    "storage_location": "s3://hyperlane-igra-validator-1/us-east-1"
  },
  "signature": {
    "r": "0x...",
    "s": "0x...",
    "v": 28
  }
}
```

### 8.3 S3 Bucket Structure

```
s3://hyperlane-igra-validator-1/
├── announcement.json           # Validator announcement
├── checkpoint_0.json           # First checkpoint
├── checkpoint_1.json
├── checkpoint_2.json
├── ...
├── checkpoint_latest_index.json  # Contains just the latest index number
└── checkpoint_42.json          # Latest checkpoint
```

### 8.4 S3 Bucket Policy

**Validator write policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ValidatorWrite",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::VALIDATOR_ACCOUNT:role/ValidatorRole"
      },
      "Action": [
        "s3:PutObject",
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::hyperlane-igra-validator-1/*"
    }
  ]
}
```

**Relayer read policy (cross-account):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RelayerRead",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::RELAYER_ACCOUNT:role/RelayerRole"
      },
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::hyperlane-igra-validator-1",
        "arn:aws:s3:::hyperlane-igra-validator-1/*"
      ]
    }
  ]
}
```

**Public read (if validators want public checkpoints):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::hyperlane-igra-validator-1/*"
    }
  ]
}
```

### 8.5 Alternative: Local File Storage (Development)

For development/testing without S3:

**Validator configuration:**

```yaml
checkpointSyncer:
  type: localStorage
  path: /data/checkpoints
```

**Relayer configuration:**

```json
{
  "allowLocalCheckpointSyncers": true
}
```

**Shared volume setup (docker-compose):**

```yaml
volumes:
  checkpoints:

services:
  validator:
    volumes:
      - checkpoints:/data/checkpoints

  relayer:
    volumes:
      - checkpoints:/data/checkpoints:ro
```

### 8.6 Alternative: GCS (Google Cloud Storage)

```yaml
# Validator config for GCS
checkpointSyncer:
  type: gcs
  bucket: hyperlane-igra-validator-1
  folder: ""
```

```bash
# GCS bucket policy via IAM
gcloud storage buckets add-iam-policy-binding gs://hyperlane-igra-validator-1 \
  --member=serviceAccount:validator@project.iam.gserviceaccount.com \
  --role=roles/storage.objectCreator
```

---

## Part 9: Step-by-Step Deployment Runbook

This runbook provides a sequential deployment guide. All operators should coordinate timing.

### Phase 1: Pre-Deployment (Days -14 to -7)

| Step | Who | Action | Verification |
|------|-----|--------|--------------|
| 1.1 | All operators | Schedule key generation ceremony | Calendar invite sent |
| 1.2 | Each validator | Generate secp256k1 keypair | `cast wallet new` |
| 1.3 | Each igra-signer | Generate Kaspa keypair | `devnet-keygen generate` |
| 1.4 | Coordinator | Collect all public keys | Document created |
| 1.5 | All operators | Review and sign agreement document | All signatures collected |
| 1.6 | Infra team | Create AWS accounts (if needed) | Accounts active |
| 1.7 | Each validator | Create S3 bucket | `aws s3 ls` shows bucket |
| 1.8 | Each validator | Configure bucket policy | Relayer can read |
| 1.9 | Infra team | Create KMS keys (if using) | Keys listed in KMS |

**Checkpoint: Agreement document signed by all operators**

### Phase 2: Contract Deployment (Days -7 to -3)

| Step | Who | Action | Verification |
|------|-----|--------|--------------|
| 2.1 | Deployer | Deploy ProxyAdmin on IGRA | Contract verified |
| 2.2 | Deployer | Deploy Mailbox on IGRA | Contract verified |
| 2.3 | Deployer | Deploy MerkleTreeHook | Contract verified |
| 2.4 | Deployer | Deploy MultisigISM (with validator addresses) | `validatorsAndThreshold()` returns correct values |
| 2.5 | Deployer | Deploy ValidatorAnnounce | Contract verified |
| 2.6 | Deployer | Deploy InterchainGasPaymaster | Contract verified |
| 2.7 | Deployer | Set default ISM on Mailbox | `defaultIsm()` returns MultisigISM |
| 2.8 | Deployer | Set default hook on Mailbox | `defaultHook()` returns MerkleTreeHook |
| 2.9 | Deployer | Share contract addresses with all operators | Addresses documented |

**Contract addresses document:**

```yaml
# IGRA Contract Addresses
mailbox: "0x..."
merkle_tree_hook: "0x..."
multisig_ism: "0x..."
validator_announce: "0x..."
interchain_gas_paymaster: "0x..."
```

**Checkpoint: All contracts deployed and verified**

### Phase 3: Validator Deployment (Days -3 to -1)

| Step | Who | Action | Verification |
|------|-----|--------|--------------|
| 3.1 | Validator 1 | Configure validator | Config file created |
| 3.2 | Validator 1 | Start validator | Process running, logs show "started" |
| 3.3 | Validator 1 | Wait for first checkpoint | S3 shows `checkpoint_0.json` |
| 3.4 | Validator 1 | Announce storage location | `getAnnouncedValidators()` includes address |
| 3.5 | Validator 2 | Repeat 3.1-3.4 | Same verifications |
| 3.6 | Validator 3 | Repeat 3.1-3.4 | Same verifications |
| 3.7 | Validator 4 | Repeat 3.1-3.4 (if 5 validators) | Same verifications |
| 3.8 | Validator 5 | Repeat 3.1-3.4 (if 5 validators) | Same verifications |
| 3.9 | Coordinator | Verify all announcements | All validators in `getAnnouncedValidators()` |

**Validator startup commands:**

```bash
# Validator 1
./validator --config /config/validator-1.yaml 2>&1 | tee /var/log/validator.log &

# Verify running
curl http://localhost:9090/metrics | grep hyperlane_latest_checkpoint

# Verify S3 checkpoint
aws s3 ls s3://hyperlane-igra-validator-1/

# Announce
cast send $VALIDATOR_ANNOUNCE "announce(address,string,bytes)" ...
```

**Checkpoint: All validators running and announced**

### Phase 4: igra-service Deployment (Day 0)

| Step | Who | Action | Verification |
|------|-----|--------|--------------|
| 4.1 | Signer 1 | Deploy igra-service node 1 | Health endpoint returns 200 |
| 4.2 | Signer 2 | Deploy igra-service node 2 | Health endpoint returns 200 |
| 4.3 | Signer 3 | Deploy igra-service node 3 | Health endpoint returns 200 |
| 4.4 | Coordinator | Verify CRDT gossip connectivity | All nodes see each other |
| 4.5 | Coordinator | Verify Kaspa node sync | Node is synced |
| 4.6 | Coordinator | Test signing flow | Test transaction broadcasts |

**igra-service startup:**

```bash
# Node 1
./igra-service --config /config/igra-1.toml 2>&1 | tee /var/log/igra.log &

# Verify health
curl http://localhost:8088/health

# Verify gossip connectivity
curl http://localhost:8088/debug/peers
```

**Checkpoint: All igra-service nodes running and connected**

### Phase 5: Relayer Deployment (Day 0)

| Step | Who | Action | Verification |
|------|-----|--------|--------------|
| 5.1 | Relayer op | Build relayer with Kaspa support | Binary built |
| 5.2 | Relayer op | Create relayer configuration | Config file created |
| 5.3 | Relayer op | Start relayer | Process running |
| 5.4 | Relayer op | Verify relayer reads validator checkpoints | Logs show checkpoint fetch |
| 5.5 | Relayer op | Verify relayer connects to igra-service | Logs show successful connection |

**Relayer startup:**

```bash
./relayer --config /config/relayer-config.json 2>&1 | tee /var/log/relayer.log &

# Verify running
curl http://localhost:9090/metrics | grep hyperlane

# Check logs for validator fetching
grep "fetched checkpoint" /var/log/relayer.log
```

**Checkpoint: Relayer running and fetching checkpoints**

### Phase 6: End-to-End Testing (Day 1)

| Step | Who | Action | Verification |
|------|-----|--------|--------------|
| 6.1 | Tester | Fund test wallet on IGRA | Balance confirmed |
| 6.2 | Tester | Dispatch test message on IGRA | Transaction confirmed |
| 6.3 | All | Monitor validator signatures | Checkpoints appear in S3 |
| 6.4 | All | Monitor relayer pickup | Logs show message received |
| 6.5 | All | Monitor igra-service processing | Logs show signing flow |
| 6.6 | All | Verify Kaspa transaction | Transaction on Kaspa explorer |
| 6.7 | All | Mark message as delivered | `delivered()` returns true |

**Test dispatch (using Foundry):**

```bash
# Dispatch test message from IGRA to Kaspa
cast send $MAILBOX_ADDRESS \
  "dispatch(uint32,bytes32,bytes)" \
  87654321 \
  "0x<recipient_padded_to_32_bytes>" \
  "0x<message_body>" \
  --private-key $TEST_KEY \
  --rpc-url $IGRA_RPC \
  --value 0.01ether  # If gas payment required

# Get message ID from logs
cast logs $MAILBOX_ADDRESS \
  --from-block latest \
  --rpc-url $IGRA_RPC
```

**Verify delivery:**

```bash
# Check if delivered (on igra-service)
curl http://igra-service:8088/rpc/mailbox/delivered/$MESSAGE_ID
```

**Checkpoint: End-to-end message flow verified**

### Phase 7: Production Go-Live

| Step | Who | Action | Verification |
|------|-----|--------|--------------|
| 7.1 | All operators | Review all metrics | No errors in last 24h |
| 7.2 | All operators | Set up alerting | Alerts configured |
| 7.3 | All operators | Document runbooks | Runbooks reviewed |
| 7.4 | Coordinator | Announce bridge open | Public announcement |

---

## Appendix A: Type Mappings

| Hyperlane Type | Kaspa/igra Type |
|----------------|-----------------|
| `H256` (message_id) | `Hash32` (event_id derived from message) |
| `H256` (address) | `Hash32` (group_id) |
| `u32` (block_number) | `u64` (daa_score) |
| `TxOutcome.transaction_id` | Kaspa `TransactionId` |
| `Metadata` | ISM signatures + checkpoint |

## Appendix B: Error Codes

| Code | Meaning |
|------|---------|
| -32001 | Hyperlane not configured |
| -32002 | Unknown domain |
| -32003 | Invalid params |
| -32004 | Signature verification failed |
| -32005 | Message already delivered |
| -32006 | Event already processed |
| -32007 | Signing in progress |

---

*Generated: 2025-01-14*
