# Key Management in Igra Threshold Signing System

**Document Version**: 1.0
**Date**: 2025-12-31
**Status**: Production Documentation
**Classification**: Security-Sensitive

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Key Types Overview](#key-types-overview)
3. [HD Wallet Keys (Signing Keys)](#hd-wallet-keys-signing-keys)
4. [Transport Layer Keys (Authentication)](#transport-layer-keys-authentication)
5. [Key Storage](#key-storage)
6. [Key Encryption](#key-encryption)
7. [Key Derivation](#key-derivation)
8. [Key Lifecycle](#key-lifecycle)
9. [Environment Variables](#environment-variables)
10. [Security Best Practices](#security-best-practices)
11. [Operational Procedures](#operational-procedures)
12. [Threat Model](#threat-model)
13. [Compliance and Auditing](#compliance-and-auditing)
14. [Appendix](#appendix)

---

## Executive Summary

The Igra threshold signing system employs a multi-layered key management architecture designed for secure, decentralized transaction signing on the Kaspa blockchain. This document provides comprehensive documentation of all cryptographic keys used in the system, their storage, encryption, lifecycle, and security practices.

### Key Categories

| Key Type | Algorithm | Purpose | Storage | Lifecycle |
|----------|-----------|---------|---------|-----------|
| **HD Wallet Keys** | secp256k1 | Transaction signing | Encrypted in config DB | Long-term (months/years) |
| **Transport Keys** | Ed25519 | P2P authentication | Plaintext file (seed) | Long-term (persistent) |
| **Test Keys** | secp256k1/Ed25519 | Testing only | In-memory/hardcoded | Ephemeral |

### Security Posture

✅ **Strengths**:
- Encrypted at-rest storage for HD wallet mnemonics (XChaCha20Poly1305)
- BIP-32/BIP-44 hierarchical deterministic key derivation
- Automatic memory zeroization for sensitive key material
- Separation of signing keys from transport authentication
- Defense-in-depth with environment variable protection

⚠️ **Considerations**:
- Transport keys stored as plaintext seeds (acceptable for authentication)
- Master secret stored in environment variable (industry standard)
- No HSM integration (future enhancement)
- No key rotation mechanism (acceptable for threshold system)

---

## Key Types Overview

### 1. HD Wallet Keys (Transaction Signing)

**Purpose**: Generate threshold signature fragments for Kaspa transactions

**Algorithm**: secp256k1 (Schnorr signatures)

**Format**:
- **Master**: BIP-39 mnemonic phrase (12-24 words)
- **Derived**: 32-byte private key at specific derivation path

**Storage**: Encrypted in RocksDB configuration database

**Example Usage**:
```rust
// Derive keypair for specific path
let keypair = derive_keypair_from_key_data(
    &key_data,
    "m/45'/111111'/0'/0/0",
    payment_secret.as_ref()
)?;

// Sign transaction input
let signature = threshold_signer.sign(input_hash, &keypair)?;
```

---

### 2. Transport Layer Keys (P2P Authentication)

**Purpose**: Authenticate P2P messages between coordinators

**Algorithm**: Ed25519 (Edwards-curve Digital Signature Algorithm)

**Format**:
- **Private**: 32-byte seed
- **Public**: 32-byte Ed25519 public key

**Storage**: Plaintext JSON file at `<data_dir>/iroh/identity.json`

**Example Usage**:
```rust
// Sign gossip message
let ed25519_signer = Ed25519Signer::from_seed(peer_id, seed);
let signature = ed25519_signer.sign(&payload_hash);

// Verify message from peer
let verifier = StaticEd25519Verifier::new(peer_keys);
let valid = verifier.verify(&sender_peer_id, &payload_hash, &signature);
```

---

### 3. Test Keys (Development Only)

**Purpose**: Deterministic keys for integration testing

**Algorithms**: secp256k1 (Kaspa), Ed25519 (transport)

**Storage**: In-memory or hardcoded constants

**SECURITY WARNING**: ⚠️ NEVER use test mnemonics in production:
```rust
// TEST ONLY - from test_keys.rs
const SIGNER_MNEMONICS: [&str; 3] = [
    "abandon abandon abandon...",  // ❌ KNOWN TEST MNEMONIC
    "legal winner thank year...",  // ❌ KNOWN TEST MNEMONIC
    "letter advice cage absurd...", // ❌ KNOWN TEST MNEMONIC
];
```

---

## HD Wallet Keys (Signing Keys)

### Architecture

The system uses **BIP-32 Hierarchical Deterministic (HD) wallets** for generating signing keys. This allows deriving multiple keys from a single master seed while maintaining cryptographic independence.

### Key Hierarchy

```
BIP-39 Mnemonic (12-24 words)
    ↓
BIP-32 Master Key
    ↓
Purpose (m/45')        ← BIP-44 multisig purpose
    ↓
Coin Type (111111')    ← Kaspa testnet coin type
    ↓
Account (0')           ← Account index
    ↓
Chain (0)              ← External chain
    ↓
Address (0, 1, 2...)   ← Derivation index
```

**Standard Derivation Path**: `m/45'/111111'/0'/0/{index}`

**Implementation**: `igra-core/src/hd.rs`

### Master Key (Mnemonic)

**Generation**:
- **Production**: Generated externally using secure entropy source
- **Import**: Via configuration file as plaintext (encrypted on first load)

**Format**: BIP-39 compliant mnemonic phrase
- **12 words**: 128 bits entropy (minimum acceptable)
- **24 words**: 256 bits entropy (recommended)

**Language**: English (BIP-39 standard wordlist)

**Example Configuration**:
```ini
[service.hd]
# LEGACY: Plaintext mnemonics (auto-encrypted on first load)
mnemonics = [
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "legal winner thank year wave sausage worth useful legal winner thank yellow"
]

# MODERN: Pre-encrypted (preferred)
# encrypted_mnemonics stored in RocksDB after first run

xpubs = [
    "xpub6F...",  # Extended public keys for non-signing members
    "xpub6A..."
]

required_sigs = 2
passphrase = "optional-bip39-passphrase"  # Extra security layer
```

### Derived Keys (SigningKeypair)

**Structure** (`igra-core/src/hd.rs:17-53`):
```rust
pub struct SigningKeypair {
    pub public_key: PublicKey,     // secp256k1 public key (33 bytes compressed)
    secret_bytes: [u8; 32],        // Private key bytes (SENSITIVE)
}

impl Drop for SigningKeypair {
    fn drop(&mut self) {
        self.zeroize();  // ✅ Automatic memory cleanup
    }
}
```

**Security Features**:
1. **Memory Zeroization**: Private keys automatically zeroed on drop
2. **Minimal Lifetime**: Keys derived on-demand, not stored long-term
3. **Scope Isolation**: Keys used immediately for signing, then dropped

### Derivation Process

**Implementation** (`igra-core/src/hd.rs:80-100`):
```rust
pub fn derive_keypair_from_key_data(
    key_data: &PrvKeyData,           // Encrypted key data
    derivation_path: &str,           // e.g., "m/45'/111111'/0'/0/0"
    payment_secret: Option<&Secret>, // Optional BIP-39 passphrase
) -> Result<SigningKeypair, ThresholdError> {
    // 1. Parse BIP-32 derivation path
    let path = DerivationPath::from_str(derivation_path)?;

    // 2. Decrypt master key with payment secret
    let xprv = key_data
        .get_xprv(payment_secret)?
        .derive_path(&path)?;

    // 3. Extract private key
    let secret = xprv.private_key();
    let secret_bytes = secret.secret_bytes();

    // 4. Derive public key
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secret);

    Ok(SigningKeypair {
        public_key,
        secret_bytes,  // ⚠️ SENSITIVE
    })
}
```

**Key Points**:
- Derivation happens in-memory only
- No intermediate keys written to disk
- Payment secret provides additional encryption layer
- Uses Kaspa's wallet-core for BIP-32 implementation

### Public Key Derivation (Non-Signing Members)

For coordinators that don't sign but participate in verification:

```rust
pub fn derive_pubkeys(inputs: HdInputs<'_>) -> Result<Vec<PublicKey>, ThresholdError> {
    let mut pubkeys = Vec::new();

    // Derive from encrypted mnemonics (signing members)
    for key_data in inputs.key_data {
        let xprv = key_data
            .get_xprv(inputs.payment_secret)?
            .derive_path(&path)?;
        pubkeys.push(xprv.private_key().get_public_key());
    }

    // Derive from extended public keys (non-signing members)
    for xpub_str in inputs.xpubs {
        let xpub = ExtendedPublicKey::<PublicKey>::from_str(xpub_str)?
            .derive_path(&path)?;
        pubkeys.push(xpub.public_key().clone());
    }

    Ok(pubkeys)
}
```

**Use Case**: Observer nodes that validate but don't sign

### Multisig Script Generation

**Implementation** (`igra-core/src/hd.rs:102-112`):
```rust
pub fn redeem_script_from_pubkeys(
    pubkeys: &[PublicKey],
    required_sigs: usize
) -> Result<Vec<u8>, ThresholdError> {
    // Convert secp256k1 keys to x-only (Schnorr)
    let xonly_keys: Vec<[u8; 32]> = pubkeys
        .iter()
        .map(|key| {
            let (xonly, _parity) = key.x_only_public_key();
            xonly.serialize()
        })
        .collect();

    // Generate Kaspa multisig redeem script
    multisig_redeem_script(xonly_keys.iter(), required_sigs)?
}
```

**Output**: P2SH-compatible multisig script for Kaspa

---

## Transport Layer Keys (Authentication)

### Purpose and Design

Transport keys authenticate P2P messages in the Iroh gossip network. These keys are separate from signing keys to provide:
- **Isolation**: Compromise of transport key doesn't affect signing capability
- **Performance**: Ed25519 is faster than secp256k1 for authentication
- **Revocation**: Transport keys can be rotated without changing signing keys

### Key Structure

**Algorithm**: Ed25519 (Curve25519)
- **Private Key**: 32-byte seed
- **Public Key**: 32-byte Ed25519 point
- **Signature**: 64 bytes

**Implementation** (`igra-core/src/transport/identity.rs`):
```rust
pub struct Ed25519Signer {
    pub peer_id: PeerId,           // Human-readable peer identifier
    key: SigningKey,               // Ed25519 signing key (SENSITIVE)
}

impl Ed25519Signer {
    pub fn from_seed(peer_id: PeerId, seed: [u8; 32]) -> Self {
        Self {
            peer_id,
            key: SigningKey::from_bytes(&seed),  // Deterministic
        }
    }

    pub fn sign_payload(&self, payload_hash: &Hash32) -> Vec<u8> {
        self.key.sign(payload_hash).to_bytes().to_vec()
    }
}
```

### Storage Location

**File Path**: `<data_dir>/iroh/identity.json`

**Default Data Directory**:
- Environment variable: `KASPA_DATA_DIR`
- Fallback: `<cwd>/.igra/`

**File Format**:
```json
{
  "peer_id": "peer-a1b2c3d4e5f6...",
  "seed_hex": "0123456789abcdef..."
}
```

**Permissions**: Should be restricted to owner only (chmod 600)

### Generation Process

**Implementation** (`igra-service/src/bin/kaspa-threshold-service/setup.rs:170-208`):
```rust
fn load_or_create_iroh_identity(data_dir: &str) -> Result<(PeerId, String), ThresholdError> {
    let identity_path = base_dir.join("iroh").join("identity.json");

    // Try to load existing identity
    if identity_path.exists() {
        let bytes = std::fs::read(&identity_path)?;
        let record: IdentityRecord = serde_json::from_slice(&bytes)?;
        return Ok((PeerId::from(record.peer_id), record.seed_hex));
    }

    // Generate new identity with cryptographically secure randomness
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);  // ✅ Secure RNG

    let mut peer_id_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut peer_id_bytes);

    let record = IdentityRecord {
        peer_id: format!("peer-{}", hex::encode(peer_id_bytes)),
        seed_hex: hex::encode(seed),
    };

    // Save to file
    std::fs::create_dir_all(&identity_dir)?;
    let json = serde_json::to_vec_pretty(&record)?;
    std::fs::write(&identity_path, json)?;

    Ok((PeerId::from(record.peer_id), record.seed_hex))
}
```

**Key Generation**:
1. **Check**: If identity file exists, load it
2. **Generate**: Use OS-provided CSPRNG (OsRng) for seed
3. **Persist**: Save to JSON file
4. **Load**: Read on subsequent startups

**Persistence**: Identity is permanent once created

### Configuration Options

**Option 1: Automatic Generation** (Recommended for single-node development)
```ini
# No transport configuration needed
# Auto-generated on first run
```

**Option 2: Explicit Configuration** (Required for production multi-node)
```ini
[iroh]
peer_id = "coordinator-alice"
signer_seed_hex = "0123456789abcdef..."  # 64 hex chars (32 bytes)
verifier_keys = [
    "coordinator-bob:abcdef0123456789...",
    "coordinator-charlie:456789abcdef0123..."
]
```

**Environment Variable Override**:
```bash
export KASPA_IGRA_PEER_ID="coordinator-alice"
export KASPA_IGRA_SIGNER_SEED_HEX="0123..."
```

### Signature Verification

**Implementation** (`igra-core/src/transport/identity.rs:40-62`):
```rust
pub struct StaticEd25519Verifier {
    keys: HashMap<PeerId, VerifyingKey>,  // Known peer public keys
}

impl SignatureVerifier for StaticEd25519Verifier {
    fn verify(
        &self,
        sender_peer_id: &PeerId,
        payload_hash: &Hash32,
        signature: &[u8]
    ) -> bool {
        // 1. Look up sender's public key
        let key = match self.keys.get(sender_peer_id) {
            Some(key) => key,
            None => return false,  // ❌ Unknown peer
        };

        // 2. Parse signature
        let signature = match Signature::from_slice(signature) {
            Ok(sig) => sig,
            Err(_) => return false,  // ❌ Invalid format
        };

        // 3. Verify signature
        key.verify_strict(payload_hash, &signature).is_ok()
    }
}
```

**Trust Model**:
- **Static Trust**: Peer keys configured at startup
- **No PKI**: No certificate authority or key distribution
- **Pre-shared Keys**: Coordinators exchange public keys out-of-band

---

## Key Storage

### Storage Architecture

```
Data Directory: <KASPA_DATA_DIR> or <cwd>/.igra/
├── threshold-signing/          # RocksDB database
│   ├── CURRENT
│   ├── MANIFEST-*
│   ├── *.sst                   # Column families:
│   │                           #  - default (config with encrypted mnemonics)
│   │                           #  - group, event, request, etc.
│   └── ...
└── iroh/
    └── identity.json           # Transport keys (plaintext)
```

### HD Wallet Storage

**Database**: RocksDB (embedded key-value store)

**Encryption**: XChaCha20Poly1305 (AEAD cipher)

**Key Derivation**: Argon2 (via kaspa-wallet-core)

**Storage Path**: `<data_dir>/threshold-signing/`

**Data Structure**:
```rust
pub struct PsktHdConfig {
    // Encrypted mnemonic data
    pub encrypted_mnemonics: Option<Encryptable<Vec<PrvKeyData>>>,

    // Extended public keys (xpub) - not encrypted
    pub xpubs: Vec<String>,

    // Threshold configuration
    pub required_sigs: usize,

    // BIP-39 passphrase (additional security layer)
    pub passphrase: Option<String>,
}
```

**Column Family**: `default` (stores app configuration)

**Key**: `b"cfg:app"`

**Value**: JSON-serialized `AppConfig` including encrypted mnemonics

### Transport Key Storage

**Format**: JSON file (plaintext)

**Path**: `<data_dir>/iroh/identity.json`

**Content**:
```json
{
  "peer_id": "peer-a1b2c3d4e5f6789012345678",
  "seed_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

**Security Considerations**:
- ✅ **Acceptable**: Transport keys authenticate, not authorize spending
- ✅ **Defense-in-Depth**: Compromise requires file system access
- ✅ **Separation**: Independent from signing keys
- ⚠️ **No Encryption**: File is plaintext (rely on OS file permissions)

**Recommended Permissions**:
```bash
chmod 600 <data_dir>/iroh/identity.json
chown <service-user>:<service-group> <data_dir>/iroh/identity.json
```

### Configuration Storage

**Format**: TOML config file

**Location**:
- Environment: `KASPA_CONFIG_PATH`
- Default: `<data_dir>/igra-config.toml`

Notes:
- All fields can be overridden via `IGRA_*` env vars (e.g. `IGRA_SERVICE__NODE_RPC_URL`).
- If `service.hd.mnemonics` is present, the service requires `KASPA_IGRA_WALLET_SECRET` to encrypt/decrypt HD key material.

### Backup and Recovery

**What to Backup**:
1. ✅ **Mnemonics**: Write down 12/24-word phrase offline
2. ✅ **Transport Seed**: Backup `iroh/identity.json` securely
3. ✅ **Configuration**: Backup `igra-config.toml`
4. ⚠️ **Database**: Can be reconstructed from blockchain

**Recovery Procedure**:
```bash
# 1. Stop service
systemctl stop igra-coordinator

# 2. Restore configuration
cp backup/igra-config.toml <data_dir>/igra-config.toml

# 3. Restore transport identity
mkdir -p <data_dir>/iroh
cp backup/identity.json <data_dir>/iroh/identity.json
chmod 600 <data_dir>/iroh/identity.json

# 4. Set wallet secret
export KASPA_IGRA_WALLET_SECRET="your-secret-here"

# 5. Restart service (will auto-encrypt mnemonics)
systemctl start igra-coordinator
```

**Disaster Recovery**:
- Mnemonics can recreate all signing keys
- Transport keys can be regenerated (requires peer reconfiguration)
- Transaction history recovered from blockchain

---

## Key Encryption

### Encryption Architecture

**Algorithm**: **XChaCha20Poly1305** (AEAD - Authenticated Encryption with Associated Data)

**Key Derivation**: **Argon2id** (memory-hard password KDF)

**Provider**: `kaspa-wallet-core` (battle-tested wallet encryption)

**Implementation**: `igra-core/src/config/encryption.rs`

### Master Secret (Wallet Password)

**Source**: Environment variable `KASPA_IGRA_WALLET_SECRET`

**Purpose**: Encrypt HD wallet mnemonics at rest

**Format**: UTF-8 string (arbitrary length, recommend 32+ characters)

**Strength Requirements**:
- **Minimum**: 16 characters (128 bits entropy)
- **Recommended**: 32 characters (256 bits entropy)
- **Best Practice**: Generated from CSPRNG

**Loading** (`igra-core/src/config/encryption.rs:10-19`):
```rust
pub fn load_wallet_secret() -> Result<Secret, ThresholdError> {
    let value = std::env::var(HD_WALLET_SECRET_ENV).unwrap_or_default();
    if value.trim().is_empty() {
        return Err(ThresholdError::ConfigError(format!(
            "{} is required to manage HD mnemonics",
            HD_WALLET_SECRET_ENV
        )));
    }
    Ok(Secret::from(value))  // ✅ Zeroized on drop
}
```

**Security Properties**:
- ✅ **Never Logged**: Secret never written to logs
- ✅ **Never Persisted**: Only exists in environment/memory
- ✅ **Zeroized**: Cleared from memory when dropped
- ⚠️ **Process Visible**: Visible to `ps` (use systemd EnvironmentFile)

### Encryption Process

**Flow**:
```
Plaintext Mnemonic
    ↓
Parse as BIP-39 Mnemonic
    ↓
Convert to PrvKeyData (kaspa-wallet-core)
    ↓ [Encrypt with payment_secret]
Encrypted PrvKeyData (XChaCha20Poly1305)
    ↓ [Encrypt with wallet_secret]
Double-Encrypted Encryptable<Vec<PrvKeyData>>
    ↓
Store in RocksDB
```

**Implementation** (`igra-core/src/config/encryption.rs:21-38`):
```rust
pub fn encrypt_mnemonics(
    mut mnemonics: Vec<String>,
    payment_secret: Option<&Secret>,  // BIP-39 passphrase
    wallet_secret: &Secret,           // Master encryption key
) -> Result<Encryptable<Vec<PrvKeyData>>, ThresholdError> {
    let mut key_data = Vec::with_capacity(mnemonics.len());

    for mut phrase in mnemonics.drain(..) {
        // 1. Parse BIP-39 mnemonic
        let mnemonic = Mnemonic::new(phrase.trim(), Language::English)?;

        // 2. Encrypt with payment secret (layer 1)
        let prv_key_data = PrvKeyData::try_new_from_mnemonic(
            mnemonic,
            payment_secret,
            EncryptionKind::XChaCha20Poly1305  // AEAD cipher
        )?;

        key_data.push(prv_key_data);
        phrase.zeroize();  // ✅ Clear plaintext
    }

    // 3. Encrypt entire vector with wallet secret (layer 2)
    Encryptable::from(key_data)
        .into_encrypted(wallet_secret, EncryptionKind::XChaCha20Poly1305)
}
```

**Layers of Encryption**:
1. **Layer 1**: Each mnemonic encrypted with optional BIP-39 passphrase
2. **Layer 2**: Entire collection encrypted with wallet secret

### Decryption Process

**Implementation** (`igra-core/src/config/encryption.rs:40-52`):
```rust
impl PsktHdConfig {
    pub fn decrypt_mnemonics(&self) -> Result<Vec<PrvKeyData>, ThresholdError> {
        let encrypted = match self.encrypted_mnemonics.as_ref() {
            Some(encrypted) => encrypted,
            None => return Ok(Vec::new()),
        };

        // 1. Load wallet secret from environment
        let wallet_secret = load_wallet_secret()?;

        // 2. Decrypt outer layer
        let decrypted = encrypted.decrypt(Some(&wallet_secret))?;

        // 3. Return encrypted PrvKeyData (decrypted on-demand with payment_secret)
        Ok(decrypted.unwrap())
    }
}
```

**Usage in Derivation**:
```rust
let hd = config.service.hd.as_ref().ok_or(...)?;
let key_data = hd.decrypt_mnemonics()?;  // Decrypt outer layer
let payment_secret = hd.passphrase.as_deref().map(Secret::from);

// Decrypt inner layer and derive key
let keypair = derive_keypair_from_key_data(
    &key_data[0],      // Still encrypted with payment_secret
    derivation_path,
    payment_secret.as_ref()  // Decrypt on-demand
)?;
```

### Encryption Security

**Algorithm Security**:
- **XChaCha20**: 20-round ChaCha cipher with extended nonce
- **Poly1305**: Message authentication code
- **AEAD**: Authenticated encryption prevents tampering
- **Argon2id**: Memory-hard KDF resistant to GPU/ASIC attacks

**Key Properties**:
| Property | Value | Security Level |
|----------|-------|----------------|
| Cipher | XChaCha20 | 256-bit security |
| Auth | Poly1305 | 128-bit security |
| Nonce | 192 bits (XChaCha) | Never repeat |
| KDF | Argon2id | Memory-hard |
| KDF Memory | Configurable | Tunable security/performance |

**Threat Mitigation**:
- ✅ **Offline Attacks**: Argon2id makes brute-force expensive
- ✅ **Tampering**: Poly1305 MAC detects modifications
- ✅ **Replay**: Nonce ensures unique ciphertexts
- ✅ **Side-Channel**: Constant-time operations

### Payment Secret (BIP-39 Passphrase)

**Purpose**: Optional additional security layer for mnemonics

**Configuration**:
```ini
[service.hd]
passphrase = "extra-security-passphrase"
```

**Behavior**:
- **With Passphrase**: Different keys derived than without
- **Lost Passphrase**: Funds permanently inaccessible
- **Empty Passphrase**: Same as no passphrase

**Use Cases**:
- **Plausible Deniability**: Different passphrases → different wallets
- **Inheritance Planning**: Mnemonic + passphrase split between heirs
- **Extra Security**: Even if mnemonic leaked, need passphrase

---

## Key Derivation

### BIP-32 Hierarchical Deterministic Derivation

**Standard**: BIP-32 (Bitcoin Improvement Proposal 32)

**Algorithm**: HMAC-SHA512 based key derivation

**Path Notation**:
- `m` = master key
- `'` (apostrophe) = hardened derivation
- `/` = path separator

### Derivation Levels

**Level 0: Purpose** - `m/45'`
- **Value**: 45 (BIP-44 multisig)
- **Hardened**: Yes (prevents xpub derivation)

**Level 1: Coin Type** - `m/45'/111111'`
- **Value**: 111111 (Kaspa testnet)
- **Mainnet**: 111111 (same as testnet for now)
- **Hardened**: Yes

**Level 2: Account** - `m/45'/111111'/0'`
- **Value**: 0 (first account)
- **Hardened**: Yes (account privacy)

**Level 3: Chain** - `m/45'/111111'/0'/0`
- **Value**: 0 (external chain)
- **Not Hardened**: Allows xpub derivation

**Level 4: Address Index** - `m/45'/111111'/0'/0/{index}`
- **Value**: 0, 1, 2, ... (sequential index)
- **Not Hardened**: Allows xpub derivation

### Derivation Example

```rust
// Full derivation from mnemonic
let mnemonic = "abandon abandon abandon...";
let payment_secret = Some(Secret::from("passphrase"));

// Path: m/45'/111111'/0'/0/5
let path = DerivationPath::from_str("m/45'/111111'/0'/0/5")?;

// Derive key
let keypair = derive_keypair_from_key_data(
    &key_data,
    "m/45'/111111'/0'/0/5",
    payment_secret.as_ref()
)?;

// Result: Private key for index 5
// Public key: 03a1b2c3d4e5f6...
```

### Index Management

**Current Implementation**: Index specified in `SigningEvent.derivation_index`

**Strategy**:
- Each transaction uses unique index
- Prevents address reuse
- Enhances privacy

**Index Source**:
```rust
pub struct SigningEvent {
    pub derivation_path: String,        // Full path
    pub derivation_index: Option<u32>,  // Index value
    // ...
}
```

**Helper Function** (`igra-core/src/hd.rs:114-116`):
```rust
pub fn derivation_path_from_index(index: u32) -> String {
    format!("m/45'/111111'/0'/0/{}", index)
}
```

### Extended Public Keys (xpub)

**Purpose**: Allow public key derivation without private key access

**Format**: Base58-encoded extended public key
```
xpub6F... (78 characters)
```

**Use Case**:
- Observer coordinators (verify, don't sign)
- Auditors (track transactions, don't spend)
- Public monitoring (transparency)

**Derivation**:
```rust
// From xpub string
let xpub = ExtendedPublicKey::<PublicKey>::from_str(xpub_str)?;

// Derive child public key (non-hardened only)
let child_xpub = xpub.derive_path(&path)?;
let public_key = child_xpub.public_key();
```

**Limitations**:
- ❌ Cannot derive hardened children
- ❌ Cannot sign transactions
- ✅ Can verify signatures
- ✅ Can generate addresses

### Security Considerations

**Hardened vs Non-Hardened**:
- **Hardened** (`'`): Requires private key, more secure
- **Non-Hardened**: Allows xpub derivation, convenient but less private

**Privacy Implications**:
- **xpub Leak**: All derived addresses exposed
- **Private Key Leak**: Only affects that key (if hardened parent)
- **Best Practice**: Use hardened derivation for accounts

**Implementation Choice**:
- ✅ Hardened through account level (m/45'/111111'/0')
- ✅ Non-hardened for address indices (allows xpub distribution)
- ✅ Balance between security and functionality

---

## Key Lifecycle

### Phase 1: Key Generation

#### HD Wallet Keys

**Method 1: External Generation** (Recommended for Production)
```bash
# Generate 24-word mnemonic using external tool
kaspa-cli wallet create --generate

# Copy mnemonic to configuration
# Add to igra-config.toml:
[service.hd]
mnemonics = ["word1 word2 word3 ..."]
```

**Method 2: Import Existing**
```toml
[service.hd]
mnemonics = [
    "existing mnemonic phrase from backup..."
]
```

**Method 3: Programmatic Generation** (Testing Only)
```rust
use kaspa_bip32::{Mnemonic, Language};
use rand::RngCore;

let mut entropy = [0u8; 32];  // 256 bits = 24 words
rand::rngs::OsRng.fill_bytes(&mut entropy);

let mnemonic = Mnemonic::from_entropy(
    &entropy,
    Language::English
)?;

println!("Mnemonic: {}", mnemonic.phrase());
// ⚠️ Store securely, never log in production
```

#### Transport Keys

**Automatic Generation**:
```bash
# First run - auto-generates identity
./kaspa-threshold-service

# Check generated identity
cat <data_dir>/iroh/identity.json
```

**Manual Generation**:
```bash
# Generate seed
openssl rand -hex 32 > transport_seed.txt

# Create identity file
cat > iroh/identity.json <<EOF
{
  "peer_id": "coordinator-alice",
  "seed_hex": "$(cat transport_seed.txt)"
}
EOF

chmod 600 iroh/identity.json
```

### Phase 2: Key Storage

**Initial Configuration**:
```bash
# 1. Create configuration
cat > igra-config.toml <<EOF
[service]
node_rpc_url = "grpc://localhost:16110"
data_dir = "/var/lib/igra"

[service.hd]
mnemonics = ["your mnemonic phrase here"]
required_sigs = 2
EOF

# 2. Set wallet secret
export KASPA_IGRA_WALLET_SECRET="your-secure-password-here"

# 3. First run - encrypts and stores mnemonics
./kaspa-threshold-service
```

**Production Note**:
- Prefer providing `service.hd.xpubs` and omitting `service.hd.mnemonics` in configuration files.

### Phase 3: Key Usage

**Signing Flow**:
```rust
// 1. Receive signing request
let signing_event = proposal.signing_event;

// 2. Decrypt mnemonics (requires KASPA_IGRA_WALLET_SECRET)
let key_data = config.service.hd.decrypt_mnemonics()?;

// 3. Derive signing key for this transaction
let keypair = derive_keypair_from_key_data(
    &key_data[0],
    &signing_event.derivation_path,
    payment_secret.as_ref()
)?;

// 4. Sign transaction input
let signature = threshold_signer.sign(&keypair, input_hash)?;

// 5. Keypair automatically zeroized on drop
// (keypair goes out of scope here)
```

**Key Lifetime**: Milliseconds (derive → sign → zeroize)

### Phase 4: Key Rotation

**Current Status**: ⚠️ **Not Implemented**

**Rationale**:
- Threshold multisig changes require all participants
- Blockchain address changes visible
- Coordination complexity high

**Future Enhancement**:
```
1. Generate new mnemonics
2. Derive new public keys
3. Create new multisig address
4. Migrate funds from old to new address
5. Update configuration across all coordinators
6. Decommission old keys
```

**Workaround**: Create new threshold group with new keys

### Phase 5: Key Backup

**Mnemonic Backup** (Critical):
```bash
# Write down on paper (offline)
# Store in secure location (safe, safety deposit box)
# Consider splitting between multiple locations
# NEVER store digitally unencrypted
```

**Configuration Backup**:
```bash
# Backup encrypted configuration
tar czf igra-backup-$(date +%Y%m%d).tar.gz \
    <data_dir>/threshold-signing/ \
    <data_dir>/iroh/ \
    igra-config.toml

# Encrypt backup
gpg --encrypt --recipient your@email.com igra-backup-*.tar.gz

# Store offsite
```

**Verification**:
```bash
# Test restore on separate machine
# Verify keys derive correctly
# Confirm can sign test transaction
```

### Phase 6: Key Destruction

**Normal Decommission**:
```bash
# 1. Drain funds from multisig address
# 2. Stop service
systemctl stop igra-coordinator

# 3. Securely delete keys
shred -vfz -n 10 <data_dir>/iroh/identity.json
rm -rf <data_dir>/threshold-signing/

# 4. Clear environment
unset KASPA_IGRA_WALLET_SECRET

# 5. Document decommission
echo "Decommissioned $(date)" >> /var/log/igra/decommission.log
```

**Emergency Revocation**:
```bash
# If keys compromised:
# 1. IMMEDIATELY transfer funds to new address
# 2. Alert other coordinators
# 3. Generate new keys
# 4. Update threshold configuration
```

**Data Retention**:
- ✅ Keep transaction history for audit
- ❌ Delete private key material
- ⚠️ Retain mnemonics in cold storage (recovery)

---

## Environment Variables

### Complete Reference

| Variable | Purpose | Required | Default | Example |
|----------|---------|----------|---------|---------|
| `KASPA_IGRA_WALLET_SECRET` | Encrypt HD mnemonics | ✅ Yes (if using mnemonics) | - | `devnet-test-secret-please-change` |
| `KASPA_DATA_DIR` | Data directory | No | `<cwd>/.igra` | `/var/lib/igra` |
| `KASPA_CONFIG_PATH` | Config file path | No | `<data_dir>/igra-config.toml` | `/etc/igra/config.toml` |
| `IGRA_SERVICE__NODE_RPC_URL` | Kaspad RPC URL override | No | Config file | `grpc://localhost:16110` |
| `KASPA_IGRA_PEER_ID` | Transport peer ID | No | Auto-generated | `coordinator-alice` |
| `KASPA_IGRA_SIGNER_SEED_HEX` | Transport seed | No | Auto-generated | `0123456789abcdef...` |
| `KASPA_IGRA_TEST_NOW_NANOS` | Mock time (testing) | No | System time | `1700000000000000000` |
| `KASPA_FINALIZE_PSKT_JSON` | Finalize mode input | No | - | `/tmp/pskt.json` |
| `KASPA_AUDIT_REQUEST_ID` | Audit mode filter | No | - | `req_abc123` |

### Security Configuration

**Production Setup** (systemd):
```ini
# /etc/systemd/system/igra-coordinator.service
[Service]
User=igra
Group=igra
EnvironmentFile=/etc/igra/secrets.env
ExecStart=/usr/local/bin/kaspa-threshold-service

[Install]
WantedBy=multi-user.target
```

**Secrets File** (`/etc/igra/secrets.env`):
```bash
KASPA_IGRA_WALLET_SECRET=your-secure-password-here
KASPA_DATA_DIR=/var/lib/igra
```

**Permissions**:
```bash
chmod 600 /etc/igra/secrets.env
chown igra:igra /etc/igra/secrets.env
```

### Development Setup

**Test Environment**:
```bash
export KASPA_IGRA_WALLET_SECRET="devnet-test-secret-please-change"
export KASPA_DATA_DIR="./test-data"
export IGRA_SERVICE__NODE_RPC_URL="grpc://localhost:16110"
```

**Docker Compose**:
```yaml
services:
  coordinator:
    image: igra-coordinator
    environment:
      - KASPA_IGRA_WALLET_SECRET=${WALLET_SECRET}
      - KASPA_DATA_DIR=/data
      - KASPA_IGRA_PEER_ID=coordinator-1
    volumes:
      - coordinator-data:/data
    secrets:
      - wallet_secret

secrets:
  wallet_secret:
    file: ./secrets/wallet_secret.txt
```

### Secret Management Best Practices

**DO**:
- ✅ Use systemd `EnvironmentFile`
- ✅ Restrict file permissions (chmod 600)
- ✅ Use secret management systems (Vault, AWS Secrets Manager)
- ✅ Rotate secrets periodically
- ✅ Audit secret access

**DON'T**:
- ❌ Hardcode secrets in scripts
- ❌ Commit secrets to version control
- ❌ Log secret values
- ❌ Share secrets via email/chat
- ❌ Use weak passwords

---

## Security Best Practices

### Principle 1: Defense in Depth

**Layer 1: Key Generation**
- ✅ Use cryptographically secure RNG (OsRng)
- ✅ Generate keys offline when possible
- ✅ Verify entropy source quality

**Layer 2: Key Storage**
- ✅ Encrypt at rest (XChaCha20Poly1305)
- ✅ Separate encryption keys (wallet secret vs payment secret)
- ✅ File system permissions (chmod 600)

**Layer 3: Key Usage**
- ✅ Minimal key lifetime (derive on-demand)
- ✅ Memory zeroization (automatic)
- ✅ Process isolation

**Layer 4: Access Control**
- ✅ Service user account (non-root)
- ✅ Environment variable protection
- ✅ Audit logging

### Principle 2: Least Privilege

**Service Account**:
```bash
# Create dedicated user
sudo useradd -r -s /bin/false igra

# Restrict data directory
sudo chown -R igra:igra /var/lib/igra
sudo chmod 700 /var/lib/igra

# Run service as igra user
systemctl start igra-coordinator
```

**File Permissions**:
```bash
# Configuration files
chmod 640 igra-config.toml
chown igra:igra igra-config.toml

# Data directory
chmod 700 /var/lib/igra
chown igra:igra /var/lib/igra

# Identity file
chmod 600 /var/lib/igra/iroh/identity.json
```

### Principle 3: Secure Key Generation

**Entropy Sources**:
- ✅ **Operating System**: `/dev/urandom` (Linux)
- ✅ **Hardware**: CPU RDRAND instruction
- ❌ **Pseudo-Random**: Do not use `rand::thread_rng()` for keys

**Implementation Verification**:
```rust
use rand::rngs::OsRng;

let mut seed = [0u8; 32];
OsRng.fill_bytes(&mut seed);  // ✅ Cryptographically secure

// NOT THIS:
// let mut rng = rand::thread_rng();  // ❌ Not for keys
```

**External Generation** (Recommended):
```bash
# Generate mnemonic offline
kaspa-cli wallet create --generate

# Generate random password
openssl rand -base64 32

# Generate transport seed
openssl rand -hex 32
```

### Principle 4: Secure Key Distribution

**Mnemonic Distribution**:
1. ❌ **Never Email**: Unencrypted email is insecure
2. ❌ **Never Chat**: Slack/Discord/WhatsApp retain history
3. ✅ **In Person**: Hand-write and deliver in person
4. ✅ **Encrypted Channel**: PGP-encrypted email acceptable
5. ✅ **Split Secret**: Use Shamir Secret Sharing for critical keys

**Configuration Distribution**:
```bash
# Encrypt configuration for transfer
gpg --encrypt --recipient coordinator@example.com config.toml.gpg

# Transfer over secure channel
scp config.toml.gpg coordinator@server:/tmp/

# Decrypt on destination
gpg --decrypt config.toml.gpg > /etc/igra/config.toml
shred -vfz config.toml.gpg
```

### Principle 5: Key Lifecycle Management

**Checklist**:
- [ ] Keys generated with secure randomness
- [ ] Backups created and stored securely
- [ ] Backups tested (restore verification)
- [ ] File permissions configured
- [ ] Service account created
- [ ] Environment variables protected
- [ ] Audit logging enabled
- [ ] Incident response plan documented

### Principle 6: Monitoring and Auditing

**Key Usage Monitoring**:
```rust
// All key operations are audited
audit(AuditEvent::PartialSignatureCreated {
    request_id: request_id.to_string(),
    signer_peer_id: peer_id.to_string(),
    input_count: signatures.len(),
    timestamp_ns: now_nanos(),
});
```

**Audit Log Analysis**:
```bash
# Monitor signing activity
grep "PartialSignatureCreated" /var/log/igra/audit.log

# Detect anomalies
# - Unexpected signing times
# - Unusual request rates
# - Failed authentication attempts
```

**Alerting**:
```yaml
# Prometheus alert rules
groups:
  - name: key_security
    rules:
      - alert: UnusualSigningActivity
        expr: rate(igra_signatures_created[5m]) > 10
        annotations:
          summary: "High signing rate detected"
```

### Principle 7: Incident Response

**Suspected Key Compromise**:
1. **Immediate**: Stop service, isolate system
2. **Assess**: Determine scope of compromise
3. **Mitigate**: Transfer funds to new address
4. **Notify**: Alert all coordinators
5. **Investigate**: Analyze logs, determine root cause
6. **Remediate**: Generate new keys, update configuration
7. **Document**: Post-mortem, lessons learned

**Response Checklist**:
```markdown
- [ ] Service stopped
- [ ] Funds secured (transferred to safe address)
- [ ] Other coordinators notified
- [ ] Logs preserved for forensics
- [ ] Root cause identified
- [ ] New keys generated
- [ ] Configuration updated
- [ ] Service restarted
- [ ] Post-mortem completed
- [ ] Preventive measures implemented
```

---

## Operational Procedures

### Procedure 1: Initial Setup

**Prerequisites**:
- Kaspad node running and synced
- Service account created (`igra` user)
- Data directory created (`/var/lib/igra`)

**Steps**:
```bash
# 1. Generate HD wallet mnemonic (offline)
kaspa-cli wallet create --generate
# Output: 24-word mnemonic phrase
# WRITE DOWN AND STORE SECURELY

# 2. Create configuration file
cat > /etc/igra/config.toml <<EOF
[service]
node_rpc_url = "grpc://localhost:16110"
data_dir = "/var/lib/igra"

[service.hd]
mnemonics = ["your 24-word mnemonic phrase here"]
xpubs = []
required_sigs = 2

[iroh]
network_id = 11
group_id = "your_group_id_here"
bootstrap = ["peer1:9000", "peer2:9000"]
EOF

# 3. Set file permissions
chmod 640 /etc/igra/config.toml
chown igra:igra /etc/igra/config.toml

# 4. Generate secure wallet secret
openssl rand -base64 32 > /tmp/wallet_secret.txt

# 5. Configure environment
cat > /etc/igra/secrets.env <<EOF
KASPA_IGRA_WALLET_SECRET=$(cat /tmp/wallet_secret.txt)
KASPA_DATA_DIR=/var/lib/igra
KASPA_CONFIG_PATH=/etc/igra/config.toml
EOF

chmod 600 /etc/igra/secrets.env
chown igra:igra /etc/igra/secrets.env
shred -vfz /tmp/wallet_secret.txt

# 6. Create systemd service
cat > /etc/systemd/system/igra-coordinator.service <<EOF
[Unit]
Description=Igra Threshold Signing Coordinator
After=network.target kaspad.service

[Service]
Type=simple
User=igra
Group=igra
EnvironmentFile=/etc/igra/secrets.env
ExecStart=/usr/local/bin/kaspa-threshold-service
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

# 7. First run (encrypts mnemonics)
systemctl daemon-reload
systemctl start igra-coordinator

# 8. Verify encryption
systemctl status igra-coordinator
# Check logs for "encrypted mnemonics" message

# 9. Remove plaintext mnemonics from config
sed -i 's/^mnemonics = .*/# mnemonics removed - now encrypted in DB/' /etc/igra/config.ini

# 10. Enable autostart
systemctl enable igra-coordinator
```

### Procedure 2: Adding New Coordinator

**Scenario**: Adding 3rd coordinator to 2-of-3 threshold group

**Steps**:
```bash
# On new coordinator:

# 1. Install software
# 2. Create configuration with xpubs from existing coordinators
cat > /etc/igra/config.ini <<EOF
[service.hd]
xpubs = [
    "xpub6F...",  # From coordinator 1
    "xpub6A..."   # From coordinator 2
]
required_sigs = 2
EOF

# 3. Set wallet secret (same as other coordinators if sharing keys)
export KASPA_IGRA_WALLET_SECRET="shared-secret"

# 4. Generate transport identity
./kaspa-threshold-service  # Auto-generates iroh/identity.json

# 5. Extract public key
cat /var/lib/igra/iroh/identity.json
# {
#   "peer_id": "coordinator-3",
#   "seed_hex": "..."
# }

# 6. Derive verifying key
# (Helper script needed to extract public key from seed)

# On existing coordinators:

# 7. Add new peer's verifying key
[iroh]
verifier_keys = [
    "coordinator-1:pubkey1...",
    "coordinator-2:pubkey2...",
    "coordinator-3:pubkey3..."  # NEW
]

# 8. Restart all coordinators
systemctl restart igra-coordinator
```

### Procedure 3: Key Rotation (Future)

**Not Currently Implemented**

**Planned Process**:
```bash
# 1. Generate new mnemonics for all coordinators
# 2. Create new multisig address
# 3. Update configuration with new keys
# 4. Restart services
# 5. Transfer funds from old to new address
# 6. Decommission old keys
# 7. Verify new configuration
```

### Procedure 4: Backup and Recovery

**Backup**:
```bash
# 1. Write down mnemonics (paper)
# 2. Store in secure location (safe)
# 3. Backup configuration
tar czf igra-backup-$(date +%Y%m%d).tar.gz \
    /var/lib/igra/iroh/identity.json \
    /etc/igra/config.ini \
    /etc/igra/secrets.env

# 4. Encrypt backup
gpg --encrypt --recipient admin@example.com igra-backup-*.tar.gz

# 5. Store offsite
rsync igra-backup-*.tar.gz.gpg backup-server:/backups/
```

**Recovery**:
```bash
# 1. Install software on new system
# 2. Restore backup
scp backup-server:/backups/igra-backup-*.tar.gz.gpg .
gpg --decrypt igra-backup-*.tar.gz.gpg | tar xz

# 3. Restore files
cp iroh/identity.json /var/lib/igra/iroh/
cp config.ini /etc/igra/
cp secrets.env /etc/igra/

# 4. Set permissions
chmod 600 /var/lib/igra/iroh/identity.json
chmod 640 /etc/igra/config.ini
chmod 600 /etc/igra/secrets.env
chown -R igra:igra /var/lib/igra /etc/igra

# 5. Start service
systemctl start igra-coordinator

# 6. Verify operation
systemctl status igra-coordinator
tail -f /var/log/igra/coordinator.log
```

### Procedure 5: Security Audit

**Monthly Checklist**:
```bash
# 1. Review audit logs
grep "RateLimitExceeded\|PolicyEnforced" /var/log/igra/audit.log

# 2. Check file permissions
find /var/lib/igra /etc/igra -type f -exec ls -l {} \;

# 3. Verify backup integrity
gpg --decrypt igra-backup-latest.tar.gz.gpg | tar tz

# 4. Test restore procedure
# (On test system)

# 5. Review access logs
journalctl -u igra-coordinator --since "30 days ago" | grep "key\|signature"

# 6. Update documentation
# Document any changes or incidents

# 7. Report findings
# Generate monthly security report
```

---

## Threat Model

### Assets

**Primary Assets**:
1. **HD Wallet Mnemonics**: Control funds in threshold addresses
2. **Derived Private Keys**: Sign specific transactions
3. **Transport Seeds**: Authenticate coordinator identity
4. **Wallet Secret**: Decrypt encrypted mnemonics

**Secondary Assets**:
5. Configuration files
6. Audit logs
7. Transaction history

### Threat Actors

| Actor | Capability | Motivation | Likelihood |
|-------|------------|------------|------------|
| **External Attacker** | Network access | Financial gain | High |
| **Malicious Insider** | System access | Financial gain, sabotage | Low |
| **Compromised Coordinator** | Full node access | Propagate malware | Medium |
| **Nation State** | Advanced persistent threat | Surveillance, disruption | Low |

### Attack Vectors

#### 1. Mnemonic Compromise

**Threat**: Attacker obtains plaintext mnemonic

**Attack Scenarios**:
- Physical access to backup
- Shoulder surfing during initial setup
- Malware keylogger
- Social engineering

**Mitigations**:
- ✅ Encrypted storage (XChaCha20Poly1305)
- ✅ Memory zeroization
- ✅ Access controls (file permissions)
- ✅ Offline backup storage

**Residual Risk**: **LOW** (after encryption implementation)

#### 2. Wallet Secret Compromise

**Threat**: Attacker obtains `KASPA_IGRA_WALLET_SECRET`

**Attack Scenarios**:
- Environment variable dump
- Process memory inspection (`/proc/<pid>/environ`)
- Log file exposure
- Configuration file leak

**Mitigations**:
- ✅ Systemd EnvironmentFile (not visible in `ps`)
- ✅ File permissions (chmod 600)
- ✅ Secret never logged
- ✅ Argon2id makes offline attacks expensive

**Residual Risk**: **MEDIUM** (requires system access)

#### 3. Transport Key Compromise

**Threat**: Attacker obtains Ed25519 transport seed

**Attack Scenarios**:
- Read `iroh/identity.json` file
- File system traversal vulnerability
- Backup exposure

**Impact**:
- Attacker can impersonate coordinator
- Cannot spend funds (signing keys separate)
- Other coordinators detect invalid signatures

**Mitigations**:
- ✅ File permissions (chmod 600)
- ✅ Separate from signing keys
- ✅ Signature verification by peers
- ✅ Audit logging of messages

**Residual Risk**: **LOW** (limited impact)

#### 4. Memory Dump Attack

**Threat**: Attacker dumps process memory to extract private keys

**Attack Scenarios**:
- Root access + `gcore` command
- Kernel module attack
- Cold boot attack (physical access)

**Mitigations**:
- ✅ Memory zeroization (automatic)
- ✅ Minimal key lifetime (milliseconds)
- ✅ Process isolation
- ⚠️ No memory encryption (OS-level defense)

**Residual Risk**: **MEDIUM** (requires root access + timing)

#### 5. Side-Channel Attacks

**Threat**: Extract keys via timing, power, or EM analysis

**Attack Scenarios**:
- Timing attacks on signing operation
- Power analysis during key derivation
- Cache timing attacks

**Mitigations**:
- ✅ Constant-time comparison (`subtle::ConstantTimeEq`)
- ✅ Standard crypto libraries (audited)
- ⚠️ No hardware countermeasures

**Residual Risk**: **LOW** (requires physical proximity + expertise)

#### 6. Threshold Subversion

**Threat**: Attacker compromises m-of-n coordinators

**Attack Scenarios**:
- Compromise 2-of-3 coordinators
- Social engineering multiple operators
- Supply chain attack (malicious build)

**Mitigations**:
- ✅ Distributed trust model
- ✅ Independent coordinator operation
- ✅ Audit logging
- ⚠️ No formal verification of binaries

**Residual Risk**: **MEDIUM** (depends on operational security)

### Threat Summary

| Threat | Likelihood | Impact | Risk | Status |
|--------|------------|--------|------|--------|
| Mnemonic Compromise | Low | Critical | Medium | ✅ Mitigated |
| Wallet Secret Compromise | Medium | Critical | High | ⚠️ Partial |
| Transport Key Compromise | Low | Low | Low | ✅ Mitigated |
| Memory Dump | Low | Critical | Medium | ⚠️ Partial |
| Side-Channel | Very Low | Critical | Low | ✅ Acceptable |
| Threshold Subversion | Low | Critical | Medium | ⚠️ Operational |

**Recommendation**: Focus on:
1. Wallet secret protection (consider HSM integration)
2. Operational security (coordinator independence)
3. Incident response planning

---

## Compliance and Auditing

### Audit Trail

**What is Logged**:
- ✅ Every signature created
- ✅ Every proposal validated
- ✅ Policy enforcement decisions
- ✅ Rate limit violations
- ❌ Key material (never logged)
- ❌ Wallet secrets (never logged)

**Audit Events Related to Keys**:
```rust
// Signature creation
AuditEvent::PartialSignatureCreated {
    request_id: "req_abc123",
    signer_peer_id: "coordinator-1",
    input_count: 5,
    timestamp_ns: 1234567890000000000,
}

// Transport authentication failure
AuditEvent::SignatureVerificationFailed {
    sender_peer_id: "unknown-peer",
    reason: "invalid signature",
    timestamp_ns: 1234567890000000000,
}
```

**Log Location**:
- Structured: JSON-formatted audit log
- Destination: Configured via tracing subscriber
- Retention: Configure per compliance requirements

### Compliance Requirements

**SOC 2 Type II**:
- ✅ Encryption at rest
- ✅ Access controls
- ✅ Audit logging
- ✅ Incident response
- ⚠️ HSM requirement (optional)

**PCI DSS** (if applicable):
- ✅ Strong cryptography (256-bit)
- ✅ Key protection (encrypted storage)
- ✅ Access controls (file permissions)
- ✅ Logging and monitoring
- ⚠️ Key rotation (not implemented)

**GDPR** (minimal personal data):
- ✅ No PII in keys
- ✅ Right to erasure (key deletion)
- ✅ Data breach notification (incident response)

### Audit Checklist

**Monthly Review**:
- [ ] Verify file permissions unchanged
- [ ] Review audit logs for anomalies
- [ ] Test backup restore procedure
- [ ] Verify all coordinators operational
- [ ] Check for software updates
- [ ] Review access control lists

**Quarterly Review**:
- [ ] Full security assessment
- [ ] Penetration testing
- [ ] Disaster recovery drill
- [ ] Update incident response plan
- [ ] Review and update documentation

**Annual Review**:
- [ ] Comprehensive security audit
- [ ] Threat model review
- [ ] Compliance assessment
- [ ] Key rotation planning (if implemented)
- [ ] Insurance review

---

## Appendix

### A. Key Formats Reference

**BIP-39 Mnemonic**:
```
Format: Space-separated words
Length: 12, 15, 18, 21, or 24 words
Language: English (BIP-39 wordlist)
Example: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

**BIP-32 Extended Private Key (xprv)**:
```
Format: Base58-encoded
Length: 111 characters
Prefix: xprv (mainnet), tprv (testnet)
Example: "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
```

**BIP-32 Extended Public Key (xpub)**:
```
Format: Base58-encoded
Length: 111 characters
Prefix: xpub (mainnet), tpub (testnet)
Example: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
```

**secp256k1 Private Key**:
```
Format: Raw bytes or hex
Length: 32 bytes (256 bits)
Example: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

**secp256k1 Public Key (Compressed)**:
```
Format: Hex
Length: 33 bytes (02/03 prefix + x-coordinate)
Example: "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
```

**Ed25519 Seed**:
```
Format: Raw bytes or hex
Length: 32 bytes
Example: "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
```

**Ed25519 Public Key**:
```
Format: Raw bytes or hex
Length: 32 bytes
Example: "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
```

### B. File Locations Reference

```
<data_dir>/                              # Default: ./.igra or $KASPA_DATA_DIR
├── threshold-signing/                   # RocksDB database
│   ├── CURRENT                          # Current manifest
│   ├── MANIFEST-000001                  # Database manifest
│   ├── 000003.log                       # Write-ahead log
│   ├── default/                         # Column family (config)
│   │   └── *.sst                        # Sorted string tables
│   ├── group/                           # Column family
│   ├── event/                           # Column family
│   ├── request/                         # Column family
│   ├── proposal/                        # Column family
│   ├── request_input/                   # Column family
│   ├── signer_ack/                      # Column family
│   ├── partial_sig/                     # Column family
│   ├── volume/                          # Column family (with merge operator)
│   └── seen/                            # Column family
└── iroh/
    └── identity.json                    # Transport keys (plaintext)

Config Files:
- /etc/igra/config.ini                   # Main configuration
- /etc/igra/secrets.env                  # Environment secrets

Systemd:
- /etc/systemd/system/igra-coordinator.service

Logs:
- journalctl -u igra-coordinator         # Service logs
- /var/log/igra/audit.log                # Audit trail (if configured)
```

### C. Cryptographic Specifications

**XChaCha20Poly1305**:
- **Type**: AEAD (Authenticated Encryption with Associated Data)
- **Key Size**: 256 bits
- **Nonce Size**: 192 bits (extended from ChaCha20's 96)
- **Tag Size**: 128 bits
- **Security**: 256-bit security against key recovery
- **Standard**: RFC 8439 (ChaCha20), draft-irtf-cfrg-xchacha (XChaCha20)

**Argon2id**:
- **Type**: Memory-hard password KDF
- **Memory**: Configurable (e.g., 64 MB)
- **Iterations**: Configurable (e.g., 3)
- **Parallelism**: Configurable (e.g., 4 threads)
- **Security**: Resistant to GPU/ASIC attacks
- **Standard**: RFC 9106

**secp256k1**:
- **Type**: Elliptic curve (Koblitz curve)
- **Field**: 256-bit prime field
- **Order**: 256-bit prime order group
- **Security**: 128-bit security level
- **Usage**: Bitcoin, Kaspa transaction signing

**Ed25519**:
- **Type**: Edwards curve signature scheme
- **Curve**: Curve25519 in twisted Edwards form
- **Security**: 128-bit security level
- **Key Size**: 256 bits (32 bytes)
- **Signature Size**: 512 bits (64 bytes)
- **Standard**: RFC 8032

**BIP-32**:
- **Type**: Hierarchical deterministic key derivation
- **Hash**: HMAC-SHA512
- **Path**: m/purpose'/coin_type'/account'/chain/index
- **Hardened**: Denoted by apostrophe (')
- **Standard**: BIP-32, BIP-44

### D. Command Reference

**Generate Mnemonic**:
```bash
# Using kaspa-cli
kaspa-cli wallet create --generate

# Using openssl (entropy only)
openssl rand -hex 32 | xxd -r -p | base64
```

**Encrypt Configuration**:
```bash
# Using GPG
gpg --encrypt --recipient admin@example.com config.ini

# Using openssl
openssl enc -aes-256-cbc -salt -in config.ini -out config.ini.enc
```

**Verify Backup**:
```bash
# Test restore
tar xzf backup.tar.gz -C /tmp/test-restore
diff -r /var/lib/igra /tmp/test-restore
```

**Monitor Signing Activity**:
```bash
# Watch audit log
tail -f /var/log/igra/audit.log | jq 'select(.type == "partial_signature_created")'

# Count signatures
journalctl -u igra-coordinator --since today | grep -c "signature created"
```

**Check File Permissions**:
```bash
# Audit permissions
find /var/lib/igra /etc/igra -ls

# Fix permissions
chmod 700 /var/lib/igra
chmod 600 /var/lib/igra/iroh/identity.json
chmod 600 /etc/igra/secrets.env
chown -R igra:igra /var/lib/igra /etc/igra
```

### E. Glossary

**Terms**:
- **BIP**: Bitcoin Improvement Proposal (standards)
- **HD Wallet**: Hierarchical Deterministic wallet
- **KDF**: Key Derivation Function
- **AEAD**: Authenticated Encryption with Associated Data
- **CSPRNG**: Cryptographically Secure Pseudo-Random Number Generator
- **Mnemonic**: Human-readable backup phrase (BIP-39)
- **xprv**: Extended private key (BIP-32)
- **xpub**: Extended public key (BIP-32)
- **Zeroization**: Securely erasing sensitive data from memory
- **Schnorr**: Signature scheme used by Kaspa
- **Ed25519**: Edwards-curve signature scheme

### F. References

**Standards**:
- BIP-32: Hierarchical Deterministic Wallets
- BIP-39: Mnemonic Code for Generating Deterministic Keys
- BIP-44: Multi-Account Hierarchy for Deterministic Wallets
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
- RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
- RFC 9106: Argon2 Memory-Hard Function

**Libraries**:
- `kaspa-bip32`: BIP-32 implementation for Kaspa
- `kaspa-wallet-core`: Wallet encryption and key management
- `secp256k1`: Bitcoin secp256k1 bindings
- `ed25519-dalek`: Ed25519 implementation
- `zeroize`: Memory zeroization
- `rand`: Cryptographic random number generation

**Documentation**:
- Kaspa Documentation: https://kaspa.org/docs
- BIP Standards: https://github.com/bitcoin/bips
- IETF RFCs: https://www.ietf.org/rfc/

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-31 | Claude Code | Initial comprehensive documentation |

---

**Document Classification**: Security-Sensitive
**Distribution**: Internal Use Only
**Next Review**: 2026-03-31
