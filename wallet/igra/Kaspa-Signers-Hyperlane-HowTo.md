# Igra Multisig Bootstrap Guide: Kaspa + Hyperlane

This guide provides step-by-step instructions for bootstrapping a new Igra threshold signing group on Kaspa using Hyperlane as the cross-chain event provider.

**Target audience**: Multisig signers, operators, and external auditors.

**Security model**: This process involves public verification (Discord/forums) and private key exchange (Signal/Telegram). External auditors validate all public commitments before funds are deposited.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Phase 1: Agreement on Parameters](#2-phase-1-agreement-on-parameters)
3. [Phase 2: Key Generation (Per Signer, Private)](#3-phase-2-key-generation-per-signer-private)
4. [Phase 3: Public Key Exchange and Verification](#4-phase-3-public-key-exchange-and-verification)
5. [Phase 4: Multisig Address Derivation](#5-phase-4-multisig-address-derivation)
6. [Phase 5: Hyperlane Validator Setup](#6-phase-5-hyperlane-validator-setup)
7. [Phase 6: Iroh Gossip Network Setup](#7-phase-6-iroh-gossip-network-setup)
8. [Phase 7: Configuration File Creation](#8-phase-7-configuration-file-creation)
9. [Phase 8: Pre-Funding Verification](#9-phase-8-pre-funding-verification)
10. [Phase 9: Funding the Multisig](#10-phase-9-funding-the-multisig)
11. [Phase 10: System Initialization and Health Check](#11-phase-10-system-initialization-and-health-check)
12. [Phase 11: First Test Transaction](#12-phase-11-first-test-transaction)
13. [Appendix A: Verification Checklist for Auditors](#appendix-a-verification-checklist-for-auditors)
14. [Appendix B: Configuration Reference](#appendix-b-configuration-reference)
15. [Appendix C: Troubleshooting](#appendix-c-troubleshooting)

---

## 1. Prerequisites

### Required Software

Each signer must have:
- **Rust toolchain**: `rustc 1.70+` and `cargo`
- **Igra binary**: Compiled from `rusty-kaspa/wallet/igra`
  ```bash
  cd rusty-kaspa/wallet/igra
  cargo build --release --bin igra-service
  cargo build --release --bin devnet-keygen  # For key generation
  ```
- **Kaspa node access**: RPC endpoint for UTXO queries (can be shared public node for testing)
- **Secure communication**: Signal or Telegram for private key exchange

### Required Knowledge

- Basic understanding of BIP39 mnemonics and BIP32 derivation
- Understanding of threshold signatures (m-of-n multisig)
- Familiarity with TOML configuration files
- Basic command-line and environment variable usage

### Communication Channels

**Public (Discord/Forum):**
- Agreement on parameters (threshold, network, policies)
- Public key commitments
- Redeem script verification
- Peer ID verification
- Multisig address announcement
- Auditor verification results

**Private (Signal/Telegram):**
- Mnemonic exchange (encrypted)
- Iroh Ed25519 seeds
- Wallet encryption secrets
- Bootstrap endpoint addresses (if not public)

---

## 2. Phase 1: Agreement on Parameters

All signers must publicly agree on the following parameters **before** generating keys. Post these to Discord for auditor review.

### 2.1 Threshold Parameters

**Consensus required:**
- **M (threshold_m)**: Minimum signatures required (e.g., 2, 3, 5)
- **N (threshold_n)**: Total number of signers (e.g., 3, 5, 7)

**Recommendation**: Use $M = \lceil (2N + 1) / 3 \rceil$ for Byzantine tolerance in future upgrades.

**Example:**
```
M = 2, N = 3  (2-of-3, can tolerate 1 failure)
M = 3, N = 5  (3-of-5, can tolerate 2 failures)
M = 5, N = 7  (5-of-7, can tolerate 2 failures)
```

**Discord announcement:**
```markdown
## Multisig Threshold Parameters
- **Threshold (M)**: 2
- **Total Signers (N)**: 3
- **Fault Tolerance**: Can tolerate 1 signer offline
```

### 2.2 Network Selection

**Consensus required:**
- **Kaspa network**: Mainnet (0), Testnet (1), Devnet (2), Simnet (3)
- **Iroh network_id**: Must be unique per deployment (use `0` for mainnet, `2` for devnet)

**Example:**
```toml
network_id = 2  # Devnet
```

**Discord announcement:**
```markdown
## Network Configuration
- **Kaspa Network**: Devnet (testnet10)
- **Iroh Network ID**: 2
- **Expected Address Prefix**: `kaspadev:`
```

### 2.3 Fee and Policy Parameters

**Consensus required:**

```toml
[group]
fee_rate_sompi_per_gram = 1000          # 1000 sompi/gram (Kaspa default)
finality_blue_score_threshold = 100     # Wait 100 blocks before considering UTXOs final
dust_threshold_sompi = 546              # Minimum UTXO size
min_recipient_amount_sompi = 1000       # Minimum withdrawal amount
session_timeout_seconds = 300           # 5 minutes per round

[policy]
allowed_destinations = []               # Empty = allow all
min_amount_sompi = 100000000           # 1 KAS minimum
max_amount_sompi = 1000000000000       # 10,000 KAS maximum
max_daily_volume_sompi = 5000000000000 # 50,000 KAS per day
require_reason = false                  # Don't require memo
```

**Discord announcement:**
```markdown
## Fee and Policy Parameters
- **Fee Rate**: 1000 sompi/gram
- **Finality Threshold**: 100 blocks (~100 seconds on Kaspa)
- **Min Withdrawal**: 1 KAS
- **Max Withdrawal**: 10,000 KAS
- **Daily Limit**: 50,000 KAS
- **Destination Whitelist**: None (allow all)
```

### 2.4 Session Metadata

**Optional but recommended:**

```toml
[group.group_metadata]
creation_timestamp_nanos = 1705939200000000000  # Unix timestamp
group_name = "Kaspa-Hyperlane-Bridge-Mainnet"
policy_version = 1
```

**Discord announcement:**
```markdown
## Group Metadata
- **Group Name**: Kaspa-Hyperlane-Bridge-Mainnet
- **Policy Version**: 1
- **Creation Date**: 2024-01-22 (UTC)
```

---

## 3. Phase 2: Key Generation (Per Signer, Private)

Each signer **independently** generates their own keys. **Do not share mnemonics publicly.**

### 3.1 Generate BIP39 Mnemonic

**Using Igra's key generation tool:**

```bash
cd rusty-kaspa/wallet/igra
cargo run --release --bin devnet-keygen -- --count 1 > signer-1-keys.json
```

**Or manually using standard BIP39 tools:**

```bash
# Using https://iancoleman.io/bip39/ (offline)
# Or using kaspa-wallet CLI
kaspa-cli wallet create --testnet
```

**Output: 24-word mnemonic phrase**
```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

**Security:**
- Generate on air-gapped machine if possible
- Store in password manager (encrypted)
- Write physical backup on paper (stored securely)
- **Never share mnemonic publicly**

### 3.2 Derive Signing Public Key

**Option A: Using Igra devnet-keygen**

The `devnet-keygen` tool automatically derives pubkeys from mnemonics. Extract from `devnet-keys.json`:

```json
{
  "signers": [
    {
      "signer_name": "signer-1",
      "mnemonic": "abandon abandon abandon...",
      "secp256k1_pubkey": "03a4ebef8e3553bd43ea837e07cfe2cfee87f1827799e5e00ef134eb9eb942c43c",
      "schnorr_xonly_pubkey": "a4ebef8e3553bd43ea837e07cfe2cfee87f1827799e5e00ef134eb9eb942c43c"
    }
  ]
}
```

**Option B: Manual derivation**

```bash
# Using kaspa-cli or BIP32 tools
# Derivation path (default): m/45'/111111'/0'/0/0
# Extract x-only (32-byte) Schnorr pubkey

# Example output:
# x-only pubkey: a4ebef8e3553bd43ea837e07cfe2cfee87f1827799e5e00ef134eb9eb942c43c
```

**CRITICAL**: Use **x-only (32-byte) Schnorr public keys**, NOT compressed secp256k1 (33-byte).

### 3.3 Generate Iroh Ed25519 Seed

**Using devnet-keygen** (automatic):

```json
{
  "signers": [
    {
      "iroh_seed_hex": "65a408b407328577681a2d53b7a3e36a1c7f8b9d0e5c4f3a2b1d0e9c8f7a6b5c",
      "iroh_pubkey_hex": "2c44f8b1a7d6e3c9f0b2a1d5e8c7f9a3b6c4d2e0f1a9b8c7d6e5f4a3b2c1d0e9",
      "iroh_peer_id": "peer-65a408b407328577"
    }
  ]
}
```

**Manual generation:**

```bash
# Generate random 32 bytes
openssl rand -hex 32
# Output: 65a408b407328577681a2d53b7a3e36a1c7f8b9d0e5c4f3a2b1d0e9c8f7a6b5c

# Derive peer ID (first 8 bytes of blake3 hash)
echo -n "65a408b407328577681a2d53b7a3e36a1c7f8b9d0e5c4f3a2b1d0e9c8f7a6b5c" | xxd -r -p | b3sum --no-names | head -c 16
# Output: 65a408b407328577

# Peer ID format: "peer-" + first 8 bytes
# Result: peer-65a408b407328577
```

**Security:**
- Keep Iroh seed private (used for gossip authentication)
- Unlike mnemonics, Iroh seeds are not recoverable (no BIP39 backup)
- If lost, signer must reconfigure with new peer ID (requires re-bootstrapping gossip)

---

## 4. Phase 3: Public Key Exchange and Verification

### 4.1 Collect Public Keys

Each signer posts to **Discord** (public channel) using this template:

```markdown
## Signer 1 Public Key Commitment

**Signer Name**: Alice (signer-1)
**Schnorr X-Only Pubkey**:
```
a4ebef8e3553bd43ea837e07cfe2cfee87f1827799e5e00ef134eb9eb942c43c
```

**Iroh Ed25519 Pubkey**:
```
2c44f8b1a7d6e3c9f0b2a1d5e8c7f9a3b6c4d2e0f1a9b8c7d6e5f4a3b2c1d0e9
```

**Iroh Peer ID**: `peer-65a408b407328577`

**Derivation Path**: `m/45'/111111'/0'/0/0` (default)

**Timestamp**: 2024-01-22 15:30:00 UTC

**Signature (GPG/PGP)**:
```
-----BEGIN PGP SIGNATURE-----
...
-----END PGP SIGNATURE-----
```

**Commitment Hash (SHA256 of above data)**:
```
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```
```

**All signers repeat** with their own keys.

### 4.2 Cross-Verification (Auditors and Signers)

**Auditors verify:**

1. **GPG/PGP signatures** (if signers have established identities)
2. **Schnorr pubkeys are valid**:
   - 32 bytes (64 hex characters)
   - On secp256k1 curve (use verification tool)
3. **Iroh peer IDs match Ed25519 pubkeys**:
   ```bash
   # Verify peer ID derivation
   echo -n "<iroh_seed_hex>" | xxd -r -p | b3sum --no-names | head -c 16
   # Must match peer ID suffix (after "peer-")
   ```
4. **No duplicate pubkeys** across signers
5. **Timeline consistency** (no backdated commitments)

**Each signer verifies**:
- Received all $N$ public key commitments
- No duplicates or conflicts
- Commitment hashes match posted data

### 4.3 Canonicalize Pubkey Order

**CRITICAL**: Multisig redeem scripts require **deterministic ordering**.

**Sorting rule**: Lexicographic order of x-only pubkeys (32-byte binary comparison).

**Example:**

```
Original order (by signer name):
signer-1: a4ebef8e3553bd43ea837e07cfe2cfee87f1827799e5e00ef134eb9eb942c43c
signer-2: b93ff1e12a7c4f3d5e6b9a8c7d2e1f0a3b5c4d6e8f9a0b1c2d3e4f5a6b7c8d9e
signer-3: ca1582f4d6e9b7a3c5f2e8d1b4a7c9e6f3d0b5a8c2e4f1d7b9a6c3e0f5d8b1a4

Canonical order (sorted):
signer-1: a4ebef8e3553bd43ea837e07cfe2cfee87f1827799e5e00ef134eb9eb942c43c
signer-2: b93ff1e12a7c4f3d5e6b9a8c7d2e1f0a3b5c4d6e8f9a0b1c2d3e4f5a6b7c8d9e
signer-3: ca1582f4d6e9b7a3c5f2e8d1b4a7c9e6f3d0b5a8c2e4f1d7b9a6c3e0f5d8b1a4
```

**Verification script:**

```python
#!/usr/bin/env python3
pubkeys = [
    "a4ebef8e3553bd43ea837e07cfe2cfee87f1827799e5e00ef134eb9eb942c43c",
    "b93ff1e12a7c4f3d5e6b9a8c7d2e1f0a3b5c4d6e8f9a0b1c2d3e4f5a6b7c8d9e",
    "ca1582f4d6e9b7a3c5f2e8d1b4a7c9e6f3d0b5a8c2e4f1d7b9a6c3e0f5d8b1a4",
]
canonical = sorted(pubkeys)
print("Canonical order:")
for i, pk in enumerate(canonical, 1):
    print(f"  {i}. {pk}")
```

**Discord post** (auditable):

```markdown
## Canonical Pubkey Ordering (Sorted)

1. `a4ebef8e...` (signer-1)
2. `b93ff1e1...` (signer-2)
3. `ca1582f4...` (signer-3)

**All signers MUST use this exact order in their configs.**
```

---

## 5. Phase 4: Multisig Address Derivation

### 5.1 Create Redeem Script

**Using canonical pubkey order**, create the multisig redeem script.

**Script format** (Kaspa Schnorr multisig):
```
OP_M <pubkey1_32bytes> <pubkey2_32bytes> ... <pubkeyN_32bytes> OP_N OP_CHECKMULTISIG
```

**Hex encoding example** (2-of-3):
```
OP_2 = 0x52
OP_PUSH_32 = 0x20
<pubkey1> = 32 bytes
OP_PUSH_32 = 0x20
<pubkey2> = 32 bytes
OP_PUSH_32 = 0x20
<pubkey3> = 32 bytes
OP_3 = 0x53
OP_CHECKMULTISIG = 0xae

Full script:
5220a4ebef8e3553bd43ea837e07cfe2cfee87f1827799e5e00ef134eb9eb942c43c20b93ff1e12a7c4f3d5e6b9a8c7d2e1f0a3b5c4d6e8f9a0b1c2d3e4f5a6b7c8d9e20ca1582f4d6e9b7a3c5f2e8d1b4a7c9e6f3d0b5a8c2e4f1d7b9a6c3e0f5d8b1a453ae
```

**Using Igra devnet-keygen** (automatic):

```bash
# Create a temporary config with all pubkeys
cat > temp-pubkeys.json <<EOF
{
  "threshold_m": 2,
  "threshold_n": 3,
  "pubkeys": [
    "a4ebef8e3553bd43ea837e07cfe2cfee87f1827799e5e00ef134eb9eb942c43c",
    "b93ff1e12a7c4f3d5e6b9a8c7d2e1f0a3b5c4d6e8f9a0b1c2d3e4f5a6b7c8d9e",
    "ca1582f4d6e9b7a3c5f2e8d1b4a7c9e6f3d0b5a8c2e4f1d7b9a6c3e0f5d8b1a4"
  ]
}
EOF

# Run keygen with pubkeys (it will generate redeem script)
cargo run --release --bin devnet-keygen | jq '.redeem_script_hex'
# Output: "5220a4ebef..."
```

**Manual creation** (using Rust):

```rust
use kaspa_txscript::{opcodes, script_builder::ScriptBuilder};

fn multisig_redeem_script(pubkeys: &[[u8; 32]], m: u8) -> Vec<u8> {
    let n = pubkeys.len() as u8;
    let mut script = vec![0x50 + m];  // OP_M
    for pk in pubkeys {
        script.push(0x20);            // OP_PUSH_32
        script.extend_from_slice(pk);
    }
    script.push(0x50 + n);            // OP_N
    script.push(0xae);                // OP_CHECKMULTISIG
    script
}
```

### 5.2 Derive Multisig Address

**Using Kaspa wallet library**:

```rust
use kaspa_addresses::{Address, Prefix};
use kaspa_txscript::pay_to_script_hash_script;

fn multisig_address(redeem_script: &[u8], prefix: Prefix) -> String {
    let script_hash = pay_to_script_hash_script(redeem_script);
    Address::new(prefix, kaspa_addresses::Version::PubKeyECDSA, &script_hash).to_string()
}
```

**Example output:**
```
kaspadev:qzczw26cseqrcrsneqlhlfv4v7a9pvrukvwaw22fst7czc8ef42wyhn89ljng
```

**Discord announcement** (public):

```markdown
## Multisig Derivation Results

**Redeem Script (hex)**:
```
5220a4ebef8e3553bd43ea837e07cfe2cfee87f1827799e5e00ef134eb9eb942c43c20b93ff1e12a7c4f3d5e6b9a8c7d2e1f0a3b5c4d6e8f9a0b1c2d3e4f5a6b7c8d9e20ca1582f4d6e9b7a3c5f2e8d1b4a7c9e6f3d0b5a8c2e4f1d7b9a6c3e0f5d8b1a453ae
```

**Multisig Address (Devnet)**:
```
kaspadev:qzczw26cseqrcrsneqlhlfv4v7a9pvrukvwaw22fst7czc8ef42wyhn89ljng
```

**Verification**: All signers independently derive and confirm the address matches.
```

### 5.3 Independent Verification

**Each signer must verify**:

```bash
# Extract pubkeys from redeem script
cargo run --release --bin verify-redeem-script -- \
  --script "5220a4ebef..." \
  --expected-m 2 \
  --expected-n 3

# Expected output:
# ✓ M = 2, N = 3
# ✓ Pubkey 1: a4ebef8e...
# ✓ Pubkey 2: b93ff1e1...
# ✓ Pubkey 3: ca1582f4...
# ✓ Address: kaspadev:qzczw26c...
```

**Auditors verify**:
- Redeem script hex decodes correctly
- M and N match agreed parameters
- Pubkeys in script match Discord commitments (in canonical order)
- Address derivation is deterministic (all signers get same address)

---

## 6. Phase 5: Hyperlane Validator Setup

### 6.1 Obtain Hyperlane Validator Public Keys

**Option A: Use Existing Hyperlane Validators (Recommended)**

Hyperlane deploys validators on multiple chains. For a production bridge, use the official Hyperlane validator set.

**Where to find validator keys**:
1. **Hyperlane documentation**: https://docs.hyperlane.xyz/
2. **Hyperlane registry**: https://github.com/hyperlane-xyz/hyperlane-registry
3. **On-chain query**: Query the Interchain Security Module (ISM) contract on the source EVM chain

**Example (Ethereum Mainnet → Kaspa):**

```javascript
// Query ISM contract for validator set
const ism = await ethers.getContractAt("IMultisigIsm", ISM_ADDRESS);
const validators = await ism.validators(KASPA_DOMAIN_ID);
const threshold = await ism.threshold(KASPA_DOMAIN_ID);

console.log("Validators:", validators);
console.log("Threshold:", threshold);
```

**Typical validator set**:
```
Validators (secp256k1 ECDSA pubkeys):
- 0x039a8d46f1c3e7b2a5d8f9e0c4a6b3d1e7f2a9c5b8d0e3f6a1c4d7e9b2f5a8c0d3
- 0x02f5c3508d1a7e4b9c2f6d0e8a3b5c7d9e1f4a6c8b0d2e5f7a9c1d4e6b8f0a2c5
- 0x03d7a2b5e8c1f4a6d9e0c3f5b8a1d4e7c0f2a5b7d9e1c4f6a8b0d3e5f7c9a2b4d6

Threshold: 2 (require 2-of-3 signatures)
Domain: 5 (Kaspa domain ID in Hyperlane)
```

**Option B: Become Hyperlane Validators (Advanced)**

Signers can run their own Hyperlane validator infrastructure:

1. **Deploy Hyperlane validator nodes**: https://docs.hyperlane.xyz/operate/validators/run-validators
2. **Register validators on ISM contract**: Deploy or update the ISM to use your validator set
3. **Generate validator keys**: Each validator generates secp256k1 ECDSA keypair
4. **Configure Igra to use your own validator set**

**This requires**:
- Running Hyperlane validator software (additional infrastructure)
- Deploying/updating ISM contracts on the source chain
- Economic stake (if using Hyperlane's staking model)

**For most deployments, Option A (use existing validators) is recommended.**

### 6.2 Configure Hyperlane in Igra

**Add to `igra-config.toml`**:

```toml
[hyperlane]
# Per-domain configuration (recommended)
[[hyperlane.domains]]
domain = 5                              # Kaspa domain ID (example)
validators = [
    "039a8d46f1c3e7b2a5d8f9e0c4a6b3d1e7f2a9c5b8d0e3f6a1c4d7e9b2f5a8c0d3",
    "02f5c3508d1a7e4b9c2f6d0e8a3b5c7d9e1f4a6c8b0d2e5f7a9c1d4e6b8f0a2c5",
    "03d7a2b5e8c1f4a6d9e0c3f5b8a1d4e7c0f2a5b7d9e1c4f6a8b0d3e5f7c9a2b4d6",
]
threshold = 2                           # Require 2-of-3
mode = "message_id_multisig"           # ISM mode

# If supporting multiple source chains, add more [[hyperlane.domains]] sections
[[hyperlane.domains]]
domain = 1                              # Ethereum Mainnet
validators = ["0x...", "0x...", "0x..."]
threshold = 2
mode = "message_id_multisig"
```

**Validator key format**:
- **secp256k1 ECDSA** (compressed: 33 bytes, or uncompressed: 65 bytes)
- **Hex-encoded** with optional `0x` prefix
- **NOT Schnorr** (different from Igra signing keys)

### 6.3 Verify Hyperlane Configuration

**Discord announcement**:

```markdown
## Hyperlane Validator Configuration

**Domain**: 5 (Kaspa)
**Threshold**: 2-of-3
**ISM Mode**: message_id_multisig

**Validator Pubkeys**:
1. `039a8d46f1c3e7b2a5d8f9e0c4a6b3d1e7f2a9c5b8d0e3f6a1c4d7e9b2f5a8c0d3`
2. `02f5c3508d1a7e4b9c2f6d0e8a3b5c7d9e1f4a6c8b0d2e5f7a9c1d4e6b8f0a2c5`
3. `03d7a2b5e8c1f4a6d9e0c3f5b8a1d4e7c0f2a5b7d9e1c4f6a8b0d3e5f7c9a2b4d6`

**Source**: Hyperlane Registry (link to commit hash)

**Auditor verification**: Query ISM contract on source chain and confirm validator set matches.
```

**Auditors verify**:
- Validator pubkeys match on-chain ISM contract
- Threshold matches ISM contract
- All signers configured identically

---

## 7. Phase 6: Iroh Gossip Network Setup

### 7.1 Bootstrap Node Selection

**Requirement**: At least one signer must be reachable as a bootstrap node for initial peer discovery.

**Recommendation**: Use 2-3 signers as bootstrap nodes for redundancy.

**Bootstrap node requirements**:
- **Static IP or DNS name** (other nodes must be able to reach it)
- **Open port** (default: 4242, configurable via `bind_port`)
- **High uptime** (if the only bootstrap is down, new nodes cannot join)

**Example**:
- Signer 1 (Alice): `bootstrap.alice.example.com:4242`
- Signer 2 (Bob): `bootstrap.bob.example.com:4242`

### 7.2 Generate Iroh Endpoint IDs

**Endpoint ID** is an Iroh-specific peer identifier (different from `peer_id`).

**Automatic (via Iroh)**: When a node starts, Iroh generates an `EndpointId` based on its network identity.

**Manual extraction** (after first startup):

```bash
# Start the node
KASPA_DATA_DIR=.igra/signer-1 igra-service --profile signer-1

# Check logs for:
# "gossip endpoint: iroh://abc123def456..."

# Extract EndpointId
# Example: iroh://abc123def456789012345678901234567890abcdef012345678901234567890ab
```

**Share endpoint IDs privately** (Signal/TG):

```
Signer 1 (Alice):
  Endpoint: iroh://abc123def456789012345678901234567890abcdef012345678901234567890ab
  Address: bootstrap.alice.example.com:4242

Signer 2 (Bob):
  Endpoint: iroh://def789012abc345678901234567890abcdef012345678901234567890abcdef
  Address: bootstrap.bob.example.com:4242
```

### 7.3 Configure Iroh Gossip

**Each signer adds to `igra-config.toml`**:

```toml
[iroh]
network_id = 2                          # Must match across all signers
group_id = "79760c31d4e8f5a6b3c9..."  # Computed from GroupConfig (see Phase 7)

# All signers' Ed25519 verifier keys (peer_id:pubkey format)
verifier_keys = [
    "peer-65a408b407328577:2c44f8b1a7d6e3c9f0b2a1d5e8c7f9a3b6c4d2e0f1a9b8c7d6e5f4a3b2c1d0e9",
    "peer-a7b3c9d1e4f8a2b5:5d7e9a1c3f6b8d0e2a4c6f8b1d3e5a7c9b2d4e6f8a0c2d5e7b9a1c4d6e8f0a3b5",
    "peer-c2e5f8a0d3b6e9c1:8f0a2c4d6e8b1a3c5d7e9b1c3e5f7a9b2d4e6f8a0c2d5e7b9a1c4d6e8f0a3b5c7",
]

# Bootstrap nodes (at least 1 required)
bootstrap = [
    "iroh://abc123def456789012345678901234567890abcdef012345678901234567890ab",
    "iroh://def789012abc345678901234567890abcdef012345678901234567890abcdef",
]

# Bootstrap addresses (must match bootstrap order)
bootstrap_addrs = [
    "bootstrap.alice.example.com:4242",
    "bootstrap.bob.example.com:4242",
]

# Per-signer overrides (in [profiles.signer-1.iroh])
[profiles.signer-1.iroh]
peer_id = "peer-65a408b407328577"
signer_seed_hex = "65a408b407328577681a2d53b7a3e36a1c7f8b9d0e5c4f3a2b1d0e9c8f7a6b5c"
bind_port = 4242                       # Only for bootstrap nodes
```

**CRITICAL**: All signers must have **identical**:
- `network_id`
- `group_id`
- `verifier_keys` (all signers, same order)
- `bootstrap` + `bootstrap_addrs` (same bootstrap nodes)

**Per-signer unique**:
- `peer_id`
- `signer_seed_hex`
- `bind_port` (only for nodes accepting inbound)

### 7.4 Verify Iroh Configuration

**Discord announcement**:

```markdown
## Iroh Gossip Configuration

**Network ID**: 2
**Group ID**: `79760c31d4e8f5a6b3c9e1d7f0a4b8c2d5e9f1a3c6d8e0b4f7a9c2d5e8b1f4a7`

**Verifier Keys** (peer_id:ed25519_pubkey):
1. `peer-65a408b407328577:2c44f8b1a7d6e3c9f0b2a1d5e8c7f9a3b6c4d2e0f1a9b8c7d6e5f4a3b2c1d0e9`
2. `peer-a7b3c9d1e4f8a2b5:5d7e9a1c3f6b8d0e2a4c6f8b1d3e5a7c9b2d4e6f8a0c2d5e7b9a1c4d6e8f0a3b5`
3. `peer-c2e5f8a0d3b6e9c1:8f0a2c4d6e8b1a3c5d7e9b1c3e5f7a9b2d4e6f8a0c2d5e7b9a1c4d6e8f0a3b5c7`

**Bootstrap Nodes**:
- Signer 1 (Alice): `bootstrap.alice.example.com:4242`
- Signer 2 (Bob): `bootstrap.bob.example.com:4242`

**All signers MUST use this exact configuration.**
```

**Each signer verifies**:
- Their own peer ID is in `verifier_keys`
- Their own Ed25519 pubkey matches their seed
- All other signers' peer IDs are present

---

## 8. Phase 7: Configuration File Creation

### 8.1 Compute Group ID

**Group ID derivation** (using agreed parameters):

```bash
# Using Igra CLI (if available) or devnet-keygen
cargo run --release --bin compute-group-id -- \
  --threshold-m 2 \
  --threshold-n 3 \
  --pubkeys a4ebef8e...,b93ff1e1...,ca1582f4... \
  --network-id 2 \
  --fee-rate 1000 \
  --finality-threshold 100

# Output:
# Group ID: 79760c31d4e8f5a6b3c9e1d7f0a4b8c2d5e9f1a3c6d8e0b4f7a9c2d5e8b1f4a7
```

**Or use the devnet-keygen output** (includes group_id in JSON).

**CRITICAL**: All parameters that affect group_id:
- `threshold_m`, `threshold_n`
- `member_pubkeys` (sorted)
- `network_id`
- `fee_rate_sompi_per_gram`
- `finality_blue_score_threshold`
- `dust_threshold_sompi`
- `min_recipient_amount_sompi`
- `session_timeout_seconds`
- `group_metadata` (serialized)
- `policy` (serialized)

**Any change to these parameters = different group ID = different gossip topic = nodes won't communicate.**

### 8.2 Complete Configuration Template

**Base configuration** (shared by all signers):

```toml
# igra-config.toml (base)

[service]
node_rpc_url = "grpc://127.0.0.1:16110"  # Kaspa node RPC
data_dir = "./.igra"                     # Will be overridden per signer

[service.pskt]
source_addresses = ["kaspadev:qzczw26cseqrcrsneqlhlfv4v7a9pvrukvwaw22fst7czc8ef42wyhn89ljng"]
redeem_script_hex = "5220a4ebef8e3553bd43ea837e07cfe2cfee87f1827799e5e00ef134eb9eb942c43c20b93ff1e12a7c4f3d5e6b9a8c7d2e1f0a3b5c4d6e8f9a0b1c2d3e4f5a6b7c8d9e20ca1582f4d6e9b7a3c5f2e8d1b4a7c9e6f3d0b5a8c2e4f1d7b9a6c3e0f5d8b1a453ae"
sig_op_count = 2
fee_payment_mode = "recipient_pays"
change_address = "kaspadev:qzczw26cseqrcrsneqlhlfv4v7a9pvrukvwaw22fst7czc8ef42wyhn89ljng"

[service.hd]
# OVERRIDE PER SIGNER IN PROFILES
mnemonics = []
required_sigs = 2
derivation_path = "m/45'/111111'/0'/0/0"  # Optional, default is root

[group]
network_id = 2
threshold_m = 2
threshold_n = 3
member_pubkeys = [
    "a4ebef8e3553bd43ea837e07cfe2cfee87f1827799e5e00ef134eb9eb942c43c",
    "b93ff1e12a7c4f3d5e6b9a8c7d2e1f0a3b5c4d6e8f9a0b1c2d3e4f5a6b7c8d9e",
    "ca1582f4d6e9b7a3c5f2e8d1b4a7c9e6f3d0b5a8c2e4f1d7b9a6c3e0f5d8b1a4",
]
fee_rate_sompi_per_gram = 1000
finality_blue_score_threshold = 100
dust_threshold_sompi = 546
min_recipient_amount_sompi = 100000000
session_timeout_seconds = 300

[group.group_metadata]
creation_timestamp_nanos = 1705939200000000000
group_name = "Kaspa-Hyperlane-Bridge-Devnet"
policy_version = 1

[policy]
allowed_destinations = []               # Empty = allow all
min_amount_sompi = 100000000            # 1 KAS
max_amount_sompi = 1000000000000        # 10,000 KAS
max_daily_volume_sompi = 5000000000000  # 50,000 KAS/day
require_reason = false

[hyperlane]
[[hyperlane.domains]]
domain = 5
validators = [
    "039a8d46f1c3e7b2a5d8f9e0c4a6b3d1e7f2a9c5b8d0e3f6a1c4d7e9b2f5a8c0d3",
    "02f5c3508d1a7e4b9c2f6d0e8a3b5c7d9e1f4a6c8b0d2e5f7a9c1d4e6b8f0a2c5",
    "03d7a2b5e8c1f4a6d9e0c3f5b8a1d4e7c0f2a5b7d9e1c4f6a8b0d3e5f7c9a2b4d6",
]
threshold = 2
mode = "message_id_multisig"

[iroh]
network_id = 2
group_id = "79760c31d4e8f5a6b3c9e1d7f0a4b8c2d5e9f1a3c6d8e0b4f7a9c2d5e8b1f4a7"
verifier_keys = [
    "peer-65a408b407328577:2c44f8b1a7d6e3c9f0b2a1d5e8c7f9a3b6c4d2e0f1a9b8c7d6e5f4a3b2c1d0e9",
    "peer-a7b3c9d1e4f8a2b5:5d7e9a1c3f6b8d0e2a4c6f8b1d3e5a7c9b2d4e6f8a0c2d5e7b9a1c4d6e8f0a3b5",
    "peer-c2e5f8a0d3b6e9c1:8f0a2c4d6e8b1a3c5d7e9b1c3e5f7a9b2d4e6f8a0c2d5e7b9a1c4d6e8f0a3b5c7",
]
bootstrap = [
    "iroh://abc123def456789012345678901234567890abcdef012345678901234567890ab",
    "iroh://def789012abc345678901234567890abcdef012345678901234567890abcdef",
]
bootstrap_addrs = [
    "bootstrap.alice.example.com:4242",
    "bootstrap.bob.example.com:4242",
]

# ===== PER-SIGNER PROFILES =====

[profiles.signer-1]
[profiles.signer-1.service]
data_dir = "./.igra/signer-1"

[profiles.signer-1.service.hd]
mnemonics = ["abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"]

[profiles.signer-1.iroh]
peer_id = "peer-65a408b407328577"
signer_seed_hex = "65a408b407328577681a2d53b7a3e36a1c7f8b9d0e5c4f3a2b1d0e9c8f7a6b5c"
bind_port = 4242  # This is a bootstrap node


[profiles.signer-2]
[profiles.signer-2.service]
data_dir = "./.igra/signer-2"

[profiles.signer-2.service.hd]
mnemonics = ["legal winner thank year wave sausage worth useful legal winner thank yellow"]

[profiles.signer-2.iroh]
peer_id = "peer-a7b3c9d1e4f8a2b5"
signer_seed_hex = "a7b3c9d1e4f8a2b5c6d9e0f1a3b5c7d9e1f3a5c7b9d0e2f4a6c8b0d2e4f6a8c1"
bind_port = 4242  # This is a bootstrap node


[profiles.signer-3]
[profiles.signer-3.service]
data_dir = "./.igra/signer-3"

[profiles.signer-3.service.hd]
mnemonics = ["letter advice cage absurd amount doctor acoustic avoid letter advice cage above"]

[profiles.signer-3.iroh]
peer_id = "peer-c2e5f8a0d3b6e9c1"
signer_seed_hex = "c2e5f8a0d3b6e9c1f4a7b2d5e8c0f3a6b9c1d4e7f0a3b6c9d2e5f8a1c4d7e0b3"
# No bind_port (not a bootstrap node)
```

### 8.3 Verification: Configuration Consistency

**Each signer independently verifies**:

```bash
# Check group_id computation
cargo run --release --bin verify-group-config -- --config igra-config.toml

# Expected output:
# ✓ Group ID: 79760c31d4e8f5a6b3c9e1d7f0a4b8c2d5e9f1a3c6d8e0b4f7a9c2d5e8b1f4a7
# ✓ Threshold: 2-of-3
# ✓ Member pubkeys: 3 (sorted)
# ✓ Redeem script: valid
# ✓ Policy: configured
```

**Discord announcement** (after all signers verify):

```markdown
## Configuration Consistency Verification

**Group ID**: `79760c31d4e8f5a6b3c9e1d7f0a4b8c2d5e9f1a3c6d8e0b4f7a9c2d5e8b1f4a7`

**Signer Confirmations**:
- ✅ Signer 1 (Alice): Group ID matches
- ✅ Signer 2 (Bob): Group ID matches
- ✅ Signer 3 (Charlie): Group ID matches

**Configuration Hash (SHA256 of canonical config)**:
```
b5a3d8f1c7e2a9b4d6f0c3e5a8b1d4f7c9e2a5b8d0f3a6c9e1d4f7b0a3c6d9e2
```

All signers confirm configuration hash matches.
```

---

## 9. Phase 8: Pre-Funding Verification

**Before sending real funds**, all signers and auditors must verify the setup.

### 9.1 Redeem Script Verification (Public)

**Each signer runs** (independently):

```bash
# Parse redeem script
echo "5220a4ebef..." | xxd -r -p | hexdump -C

# Verify:
# Byte 0: 0x52 (OP_2)
# Byte 1: 0x20 (PUSH 32 bytes)
# Bytes 2-33: First pubkey (a4ebef...)
# Byte 34: 0x20 (PUSH 32 bytes)
# Bytes 35-66: Second pubkey (b93ff1...)
# Byte 67: 0x20 (PUSH 32 bytes)
# Bytes 68-99: Third pubkey (ca1582...)
# Byte 100: 0x53 (OP_3)
# Byte 101: 0xae (OP_CHECKMULTISIG)
```

**Discord post** (each signer confirms):

```markdown
**Signer 1 (Alice)**: ✅ Redeem script verified. M=2, N=3, pubkeys match.
**Signer 2 (Bob)**: ✅ Redeem script verified. M=2, N=3, pubkeys match.
**Signer 3 (Charlie)**: ✅ Redeem script verified. M=2, N=3, pubkeys match.
```

### 9.2 Multisig Address Verification (Public)

**Each signer independently derives address**:

```bash
# Using Kaspa wallet tools
kaspa-wallet derive-multisig \
  --redeem-script "5220a4ebef..." \
  --network devnet

# Expected: kaspadev:qzczw26c...
```

**Discord post**:

```markdown
## Multisig Address Verification

**Signer 1 (Alice)**: `kaspadev:qzczw26cseqrcrsneqlhlfv4v7a9pvrukvwaw22fst7czc8ef42wyhn89ljng`
**Signer 2 (Bob)**: `kaspadev:qzczw26cseqrcrsneqlhlfv4v7a9pvrukvwaw22fst7czc8ef42wyhn89ljng`
**Signer 3 (Charlie)**: `kaspadev:qzczw26cseqrcrsneqlhlfv4v7a9pvrukvwaw22fst7czc8ef42wyhn89ljng`

✅ **All signers confirm: Address matches.**
```

**Auditors verify**:
- All signers derived the same address
- Address prefix matches network (`kaspadev` for devnet)
- Address checksum is valid

### 9.3 Peer ID Verification (Public)

**Each signer verifies their peer ID** derivation:

```bash
# Compute peer ID from Ed25519 seed
echo -n "65a408b407328577..." | xxd -r -p | b3sum --no-names | head -c 16
# Expected: 65a408b407328577

# Peer ID: "peer-65a408b407328577"
```

**Discord post**:

```markdown
## Peer ID Verification

**Signer 1 (Alice)**:
- Seed hash (first 8 bytes): `65a408b407328577`
- Peer ID: `peer-65a408b407328577`
- ✅ Verified

**Signer 2 (Bob)**:
- Seed hash: `a7b3c9d1e4f8a2b5`
- Peer ID: `peer-a7b3c9d1e4f8a2b5`
- ✅ Verified

**Signer 3 (Charlie)**:
- Seed hash: `c2e5f8a0d3b6e9c1`
- Peer ID: `peer-c2e5f8a0d3b6e9c1`
- ✅ Verified

All signers confirm: Peer IDs in `verifier_keys` match independently-derived IDs.
```

### 9.4 Group ID Verification (Public)

**Each signer computes group ID independently**:

```bash
# Using verification tool or manual computation
cargo run --release --bin verify-group-config -- --config igra-config.toml

# Output:
# ✓ Group ID: 79760c31d4e8f5a6b3c9e1d7f0a4b8c2d5e9f1a3c6d8e0b4f7a9c2d5e8b1f4a7
# ✓ Matches configured [iroh].group_id
```

**Discord post**:

```markdown
## Group ID Verification

**All signers computed**: `79760c31d4e8f5a6b3c9e1d7f0a4b8c2d5e9f1a3c6d8e0b4f7a9c2d5e8b1f4a7`

**Signer 1 (Alice)**: ✅ Matches
**Signer 2 (Bob)**: ✅ Matches
**Signer 3 (Charlie)**: ✅ Matches

**Verification**: All signers confirm group ID matches config and is derived from agreed parameters.
```

---

## 10. Phase 9: Funding the Multisig

### 10.1 Initial Test Funding (Small Amount)

**Before depositing large amounts, test with minimal funds.**

**Recommended: 0.1 KAS on devnet/testnet, 0.01 KAS on mainnet**

```bash
# Using kaspa-cli or Kaspa web wallet
kaspa-cli --testnet send \
  --to kaspadev:qzczw26cseqrcrsneqlhlfv4v7a9pvrukvwaw22fst7czc8ef42wyhn89ljng \
  --amount 10000000  # 0.1 KAS (in sompi: 1 KAS = 10^8 sompi)

# Or use Kaspa wallet UI
# Send to: kaspadev:qzczw26c...
# Amount: 0.1 KAS
```

**Wait for confirmation** (Kaspa: ~10 seconds for 10 confirmations).

**Verify UTXO arrival**:

```bash
# Query multisig address
kaspa-cli --testnet get-utxos-by-addresses \
  --addresses kaspadev:qzczw26c...

# Expected output:
# {
#   "address": "kaspadev:qzczw26c...",
#   "utxos": [
#     {
#       "outpoint": { "txid": "abc123...", "index": 0 },
#       "amount": 10000000,
#       "scriptPublicKey": "...",
#       "blockDaaScore": 12345678
#     }
#   ]
# }
```

**Discord announcement**:

```markdown
## Initial Funding Complete

**Transaction ID**: `abc123def456...`
**Amount**: 0.1 KAS
**Confirmations**: 10
**UTXO Outpoint**: `abc123def456...:0`

**All signers verify**: Query your local Kaspa node and confirm UTXO is visible.
```

### 10.2 Verify All Nodes See the UTXO

**Each signer queries independently**:

```bash
# Each signer checks their local node
kaspa-cli --rpc-server 127.0.0.1:16110 get-utxos-by-addresses \
  --addresses kaspadev:qzczw26c...

# Confirm same UTXO appears
```

**Discord post**:

```markdown
**Signer 1 (Alice)**: ✅ UTXO `abc123...:0` visible, amount 10000000
**Signer 2 (Bob)**: ✅ UTXO `abc123...:0` visible, amount 10000000
**Signer 3 (Charlie)**: ✅ UTXO `abc123...:0` visible, amount 10000000

All nodes synchronized.
```

---

## 11. Phase 10: System Initialization and Health Check

### 11.1 Set Wallet Encryption Secret

**Each signer (in their terminal, privately)**:

```bash
# Set environment variable for mnemonic encryption
export KASPA_IGRA_WALLET_SECRET="my-super-secure-passphrase-min-8-chars"

# Optionally, store in a secure file
echo "my-super-secure-passphrase" > ~/.igra-wallet-secret
chmod 600 ~/.igra-wallet-secret
export KASPA_IGRA_WALLET_SECRET=$(cat ~/.igra-wallet-secret)
```

**Security notes**:
- Use different passphrases per signer (no shared secrets)
- Minimum 8 characters (enforced by XChaCha20Poly1305)
- Store securely (password manager or encrypted file)

### 11.2 Start Igra Services

**Each signer starts their node**:

```bash
# Signer 1 (Alice)
KASPA_DATA_DIR=.igra/signer-1 \
KASPA_IGRA_WALLET_SECRET="alice-secret" \
  cargo run --release --bin igra-service -- \
    --config igra-config.toml \
    --profile signer-1 \
    --loglevel info

# Signer 2 (Bob)
KASPA_DATA_DIR=.igra/signer-2 \
KASPA_IGRA_WALLET_SECRET="bob-secret" \
  cargo run --release --bin igra-service -- \
    --config igra-config.toml \
    --profile signer-2 \
    --loglevel info

# Signer 3 (Charlie)
KASPA_DATA_DIR=.igra/signer-3 \
KASPA_IGRA_WALLET_SECRET="charlie-secret" \
  cargo run --release --bin igra-service -- \
    --config igra-config.toml \
    --profile signer-3 \
    --loglevel info
```

**Expected log output**:

```
[INFO] Config loaded from: igra-config.toml
[INFO] Profile: signer-1
[INFO] Data directory: .igra/signer-1
[INFO] Group ID: 79760c31d4e8f5a6b3c9e1d7f0a4b8c2d5e9f1a3c6d8e0b4f7a9c2d5e8b1f4a7
[INFO] Multisig address: kaspadev:qzczw26cseqrcrsneqlhlfv4v7a9pvrukvwaw22fst7czc8ef42wyhn89ljng
[INFO] Threshold: 2-of-3
[INFO] Hyperlane domains: 1 configured (domain 5)
[INFO] Iroh peer ID: peer-65a408b407328577
[INFO] Iroh network: 2
[INFO] Iroh bootstrap: 2 nodes
[INFO] Starting Iroh transport...
[INFO] Gossip joined topic: kaspa-sign/v1/2/79760c31...
[INFO] Discovered peers: [peer-a7b3c9d1e4f8a2b5, peer-c2e5f8a0d3b6e9c1]
[INFO] Service ready. Listening on 127.0.0.1:8088
```

### 11.3 Health Check: Peer Discovery

**Verify gossip connectivity**:

```bash
# Check logs for successful peer discovery
grep "Discovered peers" .igra/signer-1/igra.log

# Expected: All N-1 other peers discovered
# Signer 1 should see: [signer-2, signer-3]
# Signer 2 should see: [signer-1, signer-3]
# Signer 3 should see: [signer-1, signer-2]
```

**Discord post** (each signer):

```markdown
**Signer 1 (Alice)**: ✅ Gossip connected. Discovered 2 peers.
**Signer 2 (Bob)**: ✅ Gossip connected. Discovered 2 peers.
**Signer 3 (Charlie)**: ✅ Gossip connected. Discovered 2 peers.

All nodes connected to Iroh gossip network.
```

### 11.4 Health Check: Hyperlane Validation

**Test event validation** (using sample event):

```bash
# Create a test event (JSON)
cat > test-event.json <<EOF
{
  "external_id": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  "destination": "kaspadev:qr2t9kq5uf47w4znlg7plfhfcx3a7v8j2hq45nfzt",
  "amount_sompi": "100000000",
  "source": {
    "hyperlane": {
      "origin_domain": 1,
      "message_id": "0x1234...",
      "checkpoint": "...",
      "signatures": ["0x...", "0x..."]
    }
  }
}
EOF

# Submit to Igra API
curl -X POST http://127.0.0.1:8088/api/v1/events \
  -H "Content-Type: application/json" \
  -d @test-event.json

# Check response:
# Should see validator verification logs
```

**Expected log output**:

```
[INFO] Event received: external_id=0x1234...
[INFO] Hyperlane verification: domain=1, validators=3, threshold=2
[INFO] Validator 1 signature: valid
[INFO] Validator 2 signature: valid
[INFO] Threshold reached: 2-of-3
[INFO] Event validation: SUCCESS
```

**If validation fails**:
- Check validator pubkeys in config match ISM contract
- Verify signatures in event payload are valid
- Confirm domain ID matches configured domains

---

## 12. Phase 11: First Test Transaction

### 12.1 Submit Test Event via Hyperlane

**Using Hyperlane relayer** or manual event injection:

```bash
# POST event to all signers
curl -X POST http://alice-node:8088/api/v1/events -d @test-event.json
curl -X POST http://bob-node:8088/api/v1/events -d @test-event.json
curl -X POST http://charlie-node:8088/api/v1/events -d @test-event.json
```

**Or use Hyperlane bridge UI** (if available) to initiate a real cross-chain message.

### 12.2 Monitor Coordination

**Each signer monitors logs**:

```bash
tail -f .igra/signer-1/igra.log | grep -E "proposal|commit|sign|submit"
```

**Expected flow** (healthy case):

```
[INFO] Event e4f7a9c2: ingested, event_id=79760c31...
[INFO] Event e4f7a9c2: validator verification passed (2-of-3)
[INFO] Event e4f7a9c2: policy check passed
[INFO] Event e4f7a9c2: building PSKT, querying UTXOs
[INFO] Event e4f7a9c2: selected 1 UTXO, total input 10000000 sompi
[INFO] Event e4f7a9c2: PSKT built, tx_template_hash=a1b2c3d4...
[INFO] Event e4f7a9c2: broadcasting proposal (round 0)
[INFO] Event e4f7a9c2: received proposal from peer-a7b3c9d1 (hash=a1b2c3d4...)
[INFO] Event e4f7a9c2: received proposal from peer-c2e5f8a0 (hash=a1b2c3d4...)
[INFO] Event e4f7a9c2: quorum reached for hash a1b2c3d4 (3 votes)
[INFO] Event e4f7a9c2: COMMITTED to hash a1b2c3d4
[INFO] Event e4f7a9c2: signing PSKT with local key
[INFO] Event e4f7a9c2: signed 1 input, broadcasting signatures
[INFO] Event e4f7a9c2: received signature from peer-a7b3c9d1 (input 0)
[INFO] Event e4f7a9c2: received signature from peer-c2e5f8a0 (input 0)
[INFO] Event e4f7a9c2: threshold reached (3-of-3 signatures)
[INFO] Event e4f7a9c2: finalizing transaction
[INFO] Event e4f7a9c2: transaction finalized, txid=f8e9d0c1...
[INFO] Event e4f7a9c2: submitting to blockchain
[INFO] Event e4f7a9c2: COMPLETED, txid=f8e9d0c1..., blue_score=12345700
```

### 12.3 Verify Transaction on Blockchain

**Query blockchain explorer**:

```bash
# Kaspa block explorer (devnet)
# https://explorer.kaspa.org/tx/f8e9d0c1...

# Or via RPC
kaspa-cli --testnet get-transaction --txid f8e9d0c1...
```

**Discord announcement**:

```markdown
## First Transaction Complete! 🎉

**Event ID**: `79760c31d4e8f5a6b3c9...`
**Transaction ID**: `f8e9d0c1b2a3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9`
**Amount**: 0.01 KAS (1000000 sompi)
**Destination**: `kaspadev:qr2t9kq5uf47w4znlg7plfhfcx3a7v8j2hq45nfzt`
**Confirmations**: 10
**Status**: ✅ SUCCESS

**All signers confirm**: Transaction visible on-chain.

**Multisig System**: OPERATIONAL
```

---

## Appendix A: Verification Checklist for Auditors

External auditors should verify the following before approving the multisig for production use.

### A.1 Pre-Funding Checklist

- [ ] **Threshold parameters agreed publicly**: M-of-N values posted to Discord
- [ ] **All signer identities verified**: GPG signatures or other proof of identity
- [ ] **Schnorr pubkeys verified**: 32 bytes each, on secp256k1 curve
- [ ] **Pubkey ordering canonical**: Sorted lexicographically
- [ ] **Redeem script valid**: Decoded successfully, M/N match, pubkeys match
- [ ] **Multisig address consistent**: All signers derived same address
- [ ] **Network correct**: Address prefix matches network (kaspa/kaspatest/kaspadev/kaspasim)
- [ ] **Iroh peer IDs verified**: Derived from Ed25519 seeds correctly
- [ ] **Group ID consistent**: All signers computed same group_id
- [ ] **Hyperlane validators verified**: Pubkeys match on-chain ISM contract
- [ ] **Configuration hash verified**: All signers have identical base config
- [ ] **Policies reviewed**: Amount limits, velocity limits, whitelists reasonable
- [ ] **No duplicate keys**: Each signer has unique mnemonic/keys

### A.2 Post-Funding Checklist

- [ ] **Initial funding confirmed**: Small test amount visible on-chain
- [ ] **All nodes see UTXO**: Each signer's Kaspa node reports same UTXO
- [ ] **Gossip connectivity**: All signers discovered all other peers
- [ ] **Test transaction executed**: First withdrawal succeeded
- [ ] **Transaction structure valid**: Correct number of inputs/outputs, fee reasonable
- [ ] **Threshold signatures verified**: M valid signatures on first transaction
- [ ] **On-chain confirmation**: Transaction mined and confirmed on destination chain
- [ ] **No errors in logs**: All signers report clean execution
- [ ] **Completion record gossiped**: All nodes received completion CRDT state

### A.3 Ongoing Monitoring

- [ ] **Balance tracking**: Multisig balance monitored, alerts on low funds
- [ ] **Event throughput**: Successful vs. abandoned event ratio tracked
- [ ] **Retry rates**: Monitor quorum failure frequency
- [ ] **Node health**: All signers online and connected to gossip
- [ ] **Policy compliance**: All events respect amount/velocity limits
- [ ] **Validator liveness**: Hyperlane validators remain online
- [ ] **Incident response plan**: Procedure for handling abandoned events

---

## Appendix B: Configuration Reference

### B.1 Minimal Working Configuration

```toml
# igra-config.toml (minimal for testing)

[service]
node_rpc_url = "grpc://127.0.0.1:16110"

[service.pskt]
source_addresses = ["kaspadev:qzczw26c..."]
redeem_script_hex = "5220a4ebef..."
sig_op_count = 2

[group]
threshold_m = 2
threshold_n = 3
member_pubkeys = ["a4ebef...", "b93ff1...", "ca1582..."]

[hyperlane]
[[hyperlane.domains]]
domain = 5
validators = ["039a8d...", "02f5c3...", "03d7a2..."]
threshold = 2
mode = "message_id_multisig"

[iroh]
network_id = 2
group_id = "79760c31..."
verifier_keys = [
    "peer-65a408...:2c44f8...",
    "peer-a7b3c9...:5d7e9a...",
    "peer-c2e5f8...:8f0a2c...",
]
bootstrap = ["iroh://abc123..."]
bootstrap_addrs = ["bootstrap.alice.example.com:4242"]

[profiles.signer-1.service]
data_dir = ".igra/signer-1"

[profiles.signer-1.service.hd]
mnemonics = ["abandon abandon..."]

[profiles.signer-1.iroh]
peer_id = "peer-65a408b407328577"
signer_seed_hex = "65a408b4..."
```

### B.2 Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `KASPA_IGRA_WALLET_SECRET` | Encrypt mnemonics | `"my-secure-passphrase"` |
| `KASPA_DATA_DIR` | Data directory | `.igra/signer-1` |
| `KASPA_CONFIG_PATH` | Override config file | `/etc/igra/config.toml` |
| `IGRA_SERVICE__NODE_RPC_URL` | Override RPC URL | `grpc://node.example.com:16110` |
| `IGRA_GROUP__THRESHOLD_M` | Override threshold | `3` |
| `RUST_LOG` | Logging level | `info`, `debug` |

### B.3 Directory Structure

```
.igra/
├── signer-1/
│   ├── igra.log              # Service logs
│   ├── rocksdb/              # Persistent storage
│   │   ├── events/
│   │   ├── crdt/
│   │   ├── phase/
│   │   └── seen_messages/
│   └── igra-config.toml      # Optional: signer-specific config
├── signer-2/
│   └── ...
└── signer-3/
    └── ...
```

---

## Appendix C: Troubleshooting

### C.1 Common Issues

**Issue**: "No peers discovered after 60 seconds"

**Causes**:
- Bootstrap nodes unreachable (firewall, wrong address)
- `network_id` mismatch between nodes
- `group_id` mismatch
- Bootstrap node not started yet

**Fix**:
- Verify bootstrap addresses are reachable: `ping bootstrap.alice.example.com`
- Check firewall allows port 4242 (or configured `bind_port`)
- Confirm `network_id` and `group_id` identical across all configs
- Ensure at least one bootstrap node is running

---

**Issue**: "Group ID mismatch: computed X, expected Y"

**Causes**:
- Configuration parameters differ between signers
- `member_pubkeys` not in canonical order
- Policy or metadata differs

**Fix**:
- Compare configs byte-by-byte: `diff <(sort config1.toml) <(sort config2.toml)`
- Re-sort `member_pubkeys` lexicographically
- Ensure all signers use same policy and metadata

---

**Issue**: "Hyperlane validation failed: insufficient signatures"

**Causes**:
- Validator pubkeys in config don't match ISM contract
- Threshold in config doesn't match ISM
- Event signatures are invalid or corrupted

**Fix**:
- Query ISM contract on source chain, compare validator list
- Update `hyperlane.domains[].validators` to match on-chain
- Verify event payload has correct signature format

---

**Issue**: "PSKT signing failed: key derivation error"

**Causes**:
- Wrong mnemonic in config
- Wrong derivation path
- Wallet encryption secret mismatch

**Fix**:
- Verify mnemonic corresponds to correct pubkey (test derivation offline)
- Check `derivation_path` in config (default: `m/45'/111111'/0'/0/0`)
- Confirm `KASPA_IGRA_WALLET_SECRET` is correct

---

**Issue**: "Transaction rejected: UTXO already spent"

**Causes**:
- External wallet spent the UTXO
- Blockchain reorg invalidated UTXO
- Two events tried to use same UTXO concurrently

**Fix**:
- Ensure only Igra has access to multisig UTXOs
- Wait for deeper UTXO confirmations (increase `finality_blue_score_threshold`)
- Investigate if multisig was compromised (check for unauthorized transactions)

---

### C.2 Debug Commands

**Query local storage**:

```bash
# Check stored events
sqlite3 .igra/signer-1/rocksdb/events.db "SELECT * FROM events;"

# Check CRDT state
curl http://127.0.0.1:8088/api/v1/events/79760c31.../crdt
```

**Query gossip state**:

```bash
# Check connected peers (if RPC endpoint available)
curl http://127.0.0.1:8088/api/v1/gossip/peers

# Expected:
# {
#   "peers": [
#     {"peer_id": "peer-a7b3c9d1...", "last_seen": "2024-01-22T15:45:00Z"},
#     {"peer_id": "peer-c2e5f8a0...", "last_seen": "2024-01-22T15:45:01Z"}
#   ]
# }
```

**Test validator verification**:

```bash
# Manually verify a Hyperlane message
cargo run --release --bin verify-hyperlane-event -- \
  --event test-event.json \
  --config igra-config.toml

# Output: Valid / Invalid with details
```

---

## Appendix D: Security Best Practices

### D.1 Mnemonic Management

- **Never share mnemonics** (not even encrypted)
- Store in password manager (1Password, Bitwarden)
- Physical backup on paper (stored in safe)
- Use BIP39 passphrases for additional security
- Never enter into web forms (use offline tools only)

### D.2 Configuration Security

- **File permissions**: `chmod 600 igra-config.toml`
- **Encrypt at rest**: Disk encryption (LUKS, FileVault, BitLocker)
- **Backup configs**: Encrypted backups in separate location
- **Audit logs**: Enable logging, rotate logs, monitor for anomalies

### D.3 Network Security

- **Firewall rules**: Only allow required ports (4242 for Iroh, 16110 for Kaspa RPC)
- **VPN or private network**: Use WireGuard or similar for gossip traffic
- **DDoS protection**: Rate limiting, IP whitelisting
- **TLS/encryption**: If exposing RPC endpoints, use HTTPS

### D.4 Operational Security

- **Separate machines**: Each signer on independent hardware
- **Geographic distribution**: Signers in different regions (fault tolerance)
- **Monitoring**: Uptime monitoring, alerting on node failures
- **Incident response**: Documented procedures for key compromise, node failures
- **Regular audits**: Periodic review of configurations, logs, and transactions

---

**End of Bootstrap Guide**

For questions or issues, consult the Igra documentation or file issues at: `https://github.com/kaspanet/rusty-kaspa/issues`
