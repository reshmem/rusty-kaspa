# secrets.bin File Format Specification

**File:** `${data_dir}/secrets.bin`
**Permissions:** `0600` (owner read/write only, enforced on Unix)
**Format Version:** 1
**Encryption:** Argon2id + XChaCha20-Poly1305 AEAD (header authenticated as AAD)

**Note:** This document may lag the implementation details. The authoritative format is `igra-core/src/infrastructure/keys/backends/file_format.rs` and `docs/dev/passphrase-rotation.md`.

**Important (2026-01):** Legacy HD config secrets (`igra.hd.wallet_secret`, `igra.hd.payment_secret`) and config fields (`encrypted_mnemonics`) are removed. Mnemonics and payment secrets are now per-signer secrets keyed by profile (e.g., `igra.signer.mnemonic_signer-01`, `igra.signer.payment_secret_signer-01`).

---

## Table of Contents

1. [Binary Layout](#binary-layout)
2. [Header Structure](#header-structure)
3. [Encryption Process](#encryption-process)
4. [Decryption Process](#decryption-process)
5. [Plaintext Payload (SecretMap)](#plaintext-payload-secretmap)
6. [Secret Naming Convention](#secret-naming-convention)
7. [Example Secrets](#example-secrets)
8. [Implementation Reference](#implementation-reference)

---

## Binary Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│                    secrets.bin BINARY STRUCTURE                      │
└─────────────────────────────────────────────────────────────────────┘

Byte Range    Size    Field                    Description
═══════════════════════════════════════════════════════════════════════
[0-3]         4       MAGIC                    ASCII "ISEC" (0x49 0x53 0x45 0x43)
[4]           1       VERSION                  Format version (currently 1)
[5-8]         4       ARGON2_M_COST           Memory cost (KB, little-endian)
[9-12]        4       ARGON2_T_COST           Time cost (iterations, little-endian)
[13-16]       4       ARGON2_P_COST           Parallelism (threads, little-endian)
[17-48]       32      SALT                     Random salt for KDF (OsRng)
[49-72]       24      NONCE                    Random nonce for AEAD (OsRng)
[73-76]       4       ROTATION_TAG             ASCII "RTM1" (rotation metadata tag)
[77-84]       8       CREATED_AT_NANOS         Unix timestamp (nanos, little-endian)
[85-92]       8       LAST_ROTATED_AT_NANOS    Unix timestamp (nanos, little-endian)
[93-EOF]      VAR     CIPHERTEXT_AND_TAG       Encrypted payload + 16-byte Poly1305 tag

Total Header: 93 bytes
Total File:   93 + len(ciphertext) + 16 bytes
```

**Constants:**
- Magic: `MAGIC = *b"ISEC"` (Igra SECrets)
- Version: `VERSION = 1`
- Rotation tag: `ROTATION_TAG = *b"RTM1"`
- Header length: `HEADER_LEN = 4 + 1 + 12 + 32 + 24 + 4 + 8 + 8 = 93 bytes`

---

## Header Structure

### Magic Bytes (Offset 0-3)

```
Bytes: 0x49 0x53 0x45 0x43
ASCII: "ISEC"
```

**Purpose:** File type identification
**Validation:** Must match exactly, or file is rejected

---

### Version (Offset 4)

```
Byte:  0x01
Value: 1 (uint8)
```

**Purpose:** Format version for future compatibility
**Current:** Version 1 is the only supported version

---

### Argon2 Parameters (Offset 5-16)

All parameters stored as **little-endian u32**.

#### m_cost (Memory Cost) - Offset 5-8

```
Bytes:    4 bytes (little-endian u32)
Default:  65536 (KB) = 64 MB RAM
Range:    8192 - 4,194,304 (8 MB - 4 GB)
```

**Purpose:** Controls memory usage during key derivation
**Security:** Higher = more GPU/ASIC resistant
**Trade-off:** Higher = slower unlock

---

#### t_cost (Time Cost) - Offset 9-12

```
Bytes:    4 bytes (little-endian u32)
Default:  3 (iterations)
Range:    1 - 4,294,967,295
```

**Purpose:** Number of iterations through memory
**Security:** Higher = more brute-force resistant
**Trade-off:** Higher = slower unlock

---

#### p_cost (Parallelism) - Offset 13-16

```
Bytes:    4 bytes (little-endian u32)
Default:  4 (threads)
Range:    1 - 16,777,215
```

**Purpose:** Number of parallel lanes
**Security:** Higher = better CPU utilization
**Trade-off:** Requires multi-core CPU

---

### Salt (Offset 17-48)

```
Bytes:    32 random bytes (256 bits)
Source:   OsRng (cryptographically secure RNG)
Unique:   Per file (generated on creation)
```

**Purpose:** Prevents rainbow table attacks
**Security:** MUST be random, unique per file
**Format:** Raw binary (no encoding)

---

### Nonce (Offset 49-72)

```
Bytes:    24 random bytes (192 bits)
Source:   OsRng (cryptographically secure RNG)
Unique:   Per file encryption operation
```

**Purpose:** Ensures unique ciphertext even with same plaintext
**Security:** MUST NEVER be reused with same key
**Format:** Raw binary (no encoding)
**Algorithm:** XChaCha20-Poly1305 nonce (extended nonce space)

---

### Ciphertext + Tag (Offset 73-EOF)

```
Bytes:    Variable length
Format:   [encrypted_payload][16-byte Poly1305 tag]
Tag:      Last 16 bytes = authentication tag
```

**Structure:**
```
[73 ... EOF-16]    Ciphertext    Encrypted serialized SecretMap
[EOF-16 ... EOF]   Tag           Poly1305 authentication tag (16 bytes)
```

**Purpose:**
- Ciphertext: Encrypted payload (bincode-serialized SecretMap)
- Tag: Authentication (detects tampering/corruption)

---

## Encryption Process

```
┌─────────────────────────────────────────────────────────────────────┐
│                     ENCRYPTION WORKFLOW                              │
└─────────────────────────────────────────────────────────────────────┘

Step 1: Generate Random Values
─────────────────────────────────
OsRng → 32-byte Salt
OsRng → 24-byte Nonce


Step 2: Key Derivation (Argon2id)
──────────────────────────────────
Input:
  • Passphrase: User-provided string (UTF-8)
  • Salt: 32 random bytes
  • m_cost: 65536 KB (64 MB RAM)
  • t_cost: 3 iterations
  • p_cost: 4 threads

Algorithm:
  Argon2id (v0x13)
  ↓
  32-byte encryption key

Argon2id Configuration:
  Algorithm: Argon2id (hybrid of Argon2i + Argon2d)
  Version:   0x13 (latest)
  Output:    32 bytes (256 bits)


Step 3: Serialize Secrets (Bincode)
────────────────────────────────────
SecretMap {
  secrets: HashMap<SecretName, Vec<u8>> {
    "igra.hd.payment_secret" → [0x48, 0x65, 0x6C, ...]
    "igra.signer.mnemonic_default" → [0x61, 0x62, 0x63, ...]
    "igra.iroh.signer_seed_1" → [0x12, 0x34, 0x56, ...]
  }
}
  ↓ bincode::serialize()
  ↓
[Variable-length binary blob]


Step 4: AEAD Encryption (XChaCha20-Poly1305)
──────────────────────────────────────────────
Input:
  • Key: 32 bytes (from Argon2id)
  • Nonce: 24 bytes (random)
  • AAD: [] (empty - no additional authenticated data)
  • Plaintext: Serialized SecretMap

Algorithm:
  XChaCha20-Poly1305
  ↓
  Ciphertext + 16-byte Tag

Output Structure:
  [Ciphertext (variable)] [Poly1305 Tag (16 bytes)]


Step 5: Write to File
─────────────────────
[MAGIC (4)]
[VERSION (1)]
[m_cost (4)]
[t_cost (4)]
[p_cost (4)]
[Salt (32)]
[Nonce (24)]
[Ciphertext + Tag (variable)]
  ↓
Atomic write: .tmp → rename
  ↓
chmod 0600 (Unix)
```

---

## Decryption Process

```
┌─────────────────────────────────────────────────────────────────────┐
│                     DECRYPTION WORKFLOW                              │
└─────────────────────────────────────────────────────────────────────┘

Step 1: Read and Parse File
────────────────────────────
Read bytes from secrets.bin
  ↓
Validate Magic = "ISEC"
  ↓
Validate Version = 1
  ↓
Parse Argon2 params (m_cost, t_cost, p_cost)
  ↓
Extract Salt (32 bytes)
  ↓
Extract Nonce (24 bytes)
  ↓
Extract Ciphertext + Tag (remaining bytes)


Step 2: Key Derivation
───────────────────────
User Passphrase + Salt
  ↓
Argon2id (with parsed params)
  ↓
32-byte encryption key


Step 3: AEAD Decryption
────────────────────────
Key + Nonce + Ciphertext+Tag
  ↓
XChaCha20-Poly1305 decrypt
  ↓ (if tag verification succeeds)
Plaintext bytes


Step 4: Deserialize
────────────────────
Plaintext bytes
  ↓
bincode::deserialize()
  ↓
SecretMap { secrets: HashMap<SecretName, Vec<u8>> }


Step 5: Cache in Memory
────────────────────────
For each (name, bytes) in SecretMap:
  Cache[name] = CachedSecret {
    value: SecretBytes::from(bytes),
    expires_at: now + 300s (production) or 2s (tests),
    access_count: 0,
  }
```

---

## Plaintext Payload (SecretMap)

**Before Encryption (in memory only):**

```rust
pub struct SecretMap {
    pub secrets: HashMap<SecretName, Vec<u8>>,
}
```

**Example in-memory representation:**

```
SecretMap {
  secrets: {
    SecretName("igra.signer.mnemonic_signer-01") → Vec[97, 98, 97, 110, 100, 111, ...]
                                                     ("abandon abandon abandon...")

    SecretName("igra.signer.payment_secret_signer-01") → Vec[112, 97, 115, 115, 112, 104, ...]
                                                           ("passph...")

    SecretName("igra.signer.private_key_signer-01") → Vec[0x3a, 0x2f, 0x1c, ...]
                                                        (32-byte raw key)

    SecretName("igra.iroh.signer_seed_signer-01") → Vec[0x42, 0x8e, 0x9a, ...]
                                                      (32-byte Ed25519 seed)

    SecretName("igra.hyperlane.validator_1_key") → Vec[0x5c, 0x3d, 0x2b, ...]
                                                     (32-byte validator key)
  }
}
```

**Serialization:** Bincode (binary format, efficient, deterministic)

**Bincode Format:**
```
HashMap:
  - Length: varint (number of entries)
  - For each entry:
    - Key: String (length as varint, then UTF-8 bytes)
    - Value: Vec<u8> (length as varint, then raw bytes)
```

---

## Secret Naming Convention

### Pattern: `<namespace>.<component>.<key_id>_<profile>`

**Namespace:**
- `igra` - Igra-specific secrets

**Components:**
- `signer` - Signing keys (mnemonics, private keys)
- `iroh` - Transport identity keys (signer seeds)
- `hyperlane` - Cross-chain bridge keys (validator keys, deployer)

**Examples:**

```
Signing Keys:
  igra.signer.mnemonic_signer-01            24-word mnemonic (UTF-8, dev/test only; mainnet forbids mnemonic-based signing)
  igra.signer.payment_secret_signer-01      UTF-8 passphrase (optional BIP39 "25th word", per signer)
  igra.signer.private_key_signer-01         32-byte raw secp256k1 key (binary)

Transport Identity Keys:
  igra.iroh.signer_seed_signer-01           32-byte Ed25519 seed (binary)

Hyperlane Validator Keys:
  igra.hyperlane.validator_0_key            32-byte secp256k1 key (binary)
  igra.hyperlane.validator_1_key            32-byte secp256k1 key (binary)
  igra.hyperlane.evm_deployer               32-byte EVM private key (binary)
```

**Profile Suffix:**
- Determined explicitly by CLI `--profile` or `service.active_profile`
- Canonical format: `signer-XX` (01-99)
- FileSecretStore uses the profile string as-is (e.g., `..._signer-01`)
- EnvSecretStore uses underscores for the suffix (e.g., `..._signer_01`) because environment variables cannot contain `-`

---

## Example: secrets.bin Breakdown

### Example File Hex Dump

```
Offset    Hex                                               ASCII
══════════════════════════════════════════════════════════════════════
00000000  49 53 45 43 01 00 00 01 00 03 00 00 00 04 00 00  ISEC............
          ^^^^^^^^^^^ ^^^ ^^^^^^^^^^^ ^^^^^^^^^^^ ^^^^^^^^^^^
          Magic       Ver m_cost      t_cost      p_cost
          "ISEC"      1   65536       3           4

00000010  00 A7 3F 2C 8E 91 44 7B C3 29 8F 12 6D 45 E8 1A  ..?,..D{.)..mE..
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
          Salt (32 bytes, random)

00000020  92 7C 38 BB 05 F2 C9 43 D1 A8 76 2F 94 3E 81 0C  .|8....C..v/.>..
00000030  4F 3A 29 71 8C B5 6E 2A F4 19 62 8D 3B E7 50 94  O:)q..n*..b.;.P.
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ (salt continued)

00000040  D8 7E 1F 42 9A 6C 33 88 F1 25 A9 7D C2 58 0B 34  .~.B.l3..%.}.X.4
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
          Nonce (24 bytes, random)

00000050  E5 91 68 2F B7 4A DD 20 53 C6 72 A1 8F 3E 95 6B  ..h/.J. S.r..>.k
          ^^^^^^^^^^^^^^^^^^^^^^^^ (nonce continued)

00000060  <encrypted payload starts here>
          7A 3B 9C 2F 8E 45 ... [ciphertext] ... D3 8A 7F 2E
          ^^^^^^^^^^^^^^^^^^^     variable     ^^^^^^^^^^^^^
          Encrypted bincode                    Poly1305 Tag
                                               (last 16 bytes)
```

---

## Encryption Process (Detailed)

### Step 1: Generate Random Values

**Implementation:** `file_format.rs:55-59`

```rust
let mut salt = [0u8; 32];
let mut nonce = [0u8; 24];
let mut rng = OsRng;
rng.fill_bytes(&mut salt);  // 32 random bytes
rng.fill_bytes(&mut nonce); // 24 random bytes
```

**Constants:**
- `SALT_SIZE_BYTES = 32`
- `NONCE_SIZE_BYTES = 24`
- `AUTH_TAG_SIZE_BYTES = 16`

---

### Step 2: Key Derivation (Argon2id)

**Implementation:** `file_format.rs:142-155`

```rust
fn derive_key(
    passphrase: &str,
    salt: &[u8; 32],
    params: &Argon2Params
) -> Result<[u8; 32], ThresholdError> {
    let mut key = [0u8; 32];

    let argon2_params = ParamsBuilder::new()
        .m_cost(params.m_cost)      // 65536 KB
        .t_cost(params.t_cost)      // 3 iterations
        .p_cost(params.p_cost)      // 4 threads
        .build()?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,              // Latest Argon2 version
        argon2_params
    );

    argon2.hash_password_into(
        passphrase.as_bytes(),       // Input: UTF-8 bytes
        salt,                        // Input: 32-byte salt
        &mut key                     // Output: 32-byte key
    )?;

    Ok(key)
}
```

**Argon2id Algorithm:**
```
Argon2id(
  passphrase:  "my-strong-passphrase-123"
  salt:        [32 random bytes]
  m_cost:      65536 KB (64 MB RAM required)
  t_cost:      3 iterations
  p_cost:      4 parallel threads
  version:     0x13
  output_len:  32 bytes
)
  ↓
[32-byte encryption key]
```

**Security Properties:**
- Memory-hard: Requires 64 MB RAM (resists GPU/ASIC)
- Time-hard: 3 iterations (resists brute force)
- Parallelizable: 4 threads (efficient on multi-core CPUs)
- Side-channel resistant: Constant-time operations

---

### Step 3: Serialize SecretMap

**Implementation:** `file_format.rs:62-63`

```rust
let plaintext = bincode::serialize(secrets)?;
```

**Bincode Format for HashMap<SecretName, Vec<u8>>:**

```
Example SecretMap:
  "igra.hd.wallet_secret" → b"MyPassword123"
  "igra.signer.mnemonic_default" → b"abandon abandon abandon..."

Serialized (bincode):
  [02]                                    // HashMap length (2 entries)

  // Entry 1: igra.hd.wallet_secret
  [16]                                    // String length (22 bytes)
  [69 67 72 61 2E 68 64 2E ... 74]       // "igra.hd.wallet_secret" UTF-8
  [0D]                                    // Vec<u8> length (13 bytes)
  [4D 79 50 61 73 73 77 6F ... 33]       // "MyPassword123" bytes

  // Entry 2: igra.signer.mnemonic_default
  [1E]                                    // String length (30 bytes)
  [69 67 72 61 2E ... 75 6C 74]          // "igra.signer.mnemonic_default"
  [A7 01]                                 // Vec<u8> length (423 bytes, varint)
  [61 62 61 6E 64 6F 6E 20 ...]          // "abandon abandon..." bytes
```

**Note:** Bincode uses variable-length encoding (varint) for integers/lengths.

---

### Step 4: AEAD Encryption

**Implementation:** `file_format.rs:65-71`

```rust
let cipher = XChaCha20Poly1305::new(&key.into());
let ciphertext_and_tag = cipher.encrypt(
    &nonce.into(),              // 24-byte nonce
    plaintext.as_ref()          // Serialized SecretMap
)?;
```

**XChaCha20-Poly1305 Algorithm:**

```
┌─────────────────────────────────────────┐
│ XChaCha20 Stream Cipher                 │
│ ─────────────────────────              │
│ Key:    32 bytes (from Argon2)          │
│ Nonce:  24 bytes (random)               │
│ Block:  Plaintext XOR keystream         │
└──────────┬──────────────────────────────┘
           │
           ▼
[Ciphertext (same length as plaintext)]
           │
           ▼
┌─────────────────────────────────────────┐
│ Poly1305 MAC                            │
│ ─────────────────                       │
│ Key:    Derived from XChaCha20          │
│ Data:   AAD + Ciphertext                │
│ Output: 16-byte authentication tag      │
└──────────┬──────────────────────────────┘
           │
           ▼
[Ciphertext] [16-byte Tag]
```

**Output:** `ciphertext_and_tag` includes both encrypted payload AND tag.

---

### Step 5: Assemble Binary File

**Implementation:** `file_format.rs:93-104`

```rust
pub fn to_bytes(&self) -> Result<Vec<u8>, ThresholdError> {
    let mut buf = Vec::with_capacity(HEADER_LEN + self.ciphertext_and_tag.len());
    buf.extend_from_slice(&MAGIC);                               // [0-3]
    buf.push(self.version);                                      // [4]
    buf.extend_from_slice(&self.kdf_params.m_cost.to_le_bytes()); // [5-8]
    buf.extend_from_slice(&self.kdf_params.t_cost.to_le_bytes()); // [9-12]
    buf.extend_from_slice(&self.kdf_params.p_cost.to_le_bytes()); // [13-16]
    buf.extend_from_slice(&self.salt);                           // [17-48]
    buf.extend_from_slice(&self.nonce);                          // [49-72]
    buf.extend_from_slice(&self.ciphertext_and_tag);             // [73-EOF]
    Ok(buf)
}
```

**Constants Used:**
- `HEADER_LEN = 73` (4 + 1 + 12 + 32 + 24)

---

## Decryption Process (Detailed)

### Step 1: Parse Binary File

**Implementation:** `file_format.rs:106-140`

```rust
pub fn from_bytes(data: &[u8]) -> Result<Self, ThresholdError> {
    // Validate minimum length
    if data.len() < HEADER_LEN {
        return Err(...); // File too short
    }

    // Validate magic
    if &data[0..4] != &MAGIC {
        return Err(...); // Invalid magic bytes
    }

    // Extract version
    let version = data[4];
    if version != VERSION {
        return Err(...); // Unsupported version
    }

    // Extract Argon2 params (little-endian)
    let m_cost = u32::from_le_bytes(data[5..9].try_into()?);
    let t_cost = u32::from_le_bytes(data[9..13].try_into()?);
    let p_cost = u32::from_le_bytes(data[13..17].try_into()?);

    // Extract salt and nonce
    let salt: [u8; 32] = data[17..49].try_into()?;
    let nonce: [u8; 24] = data[49..73].try_into()?;

    // Extract ciphertext + tag
    let ciphertext_and_tag = data[73..].to_vec();

    Ok(Self {
        version,
        kdf_params: Argon2Params { m_cost, t_cost, p_cost },
        salt,
        nonce,
        ciphertext_and_tag,
    })
}
```

---

### Step 2: Decrypt

**Implementation:** `file_format.rs:76-91`

```rust
pub fn decrypt(&self, passphrase: &str) -> Result<SecretMap, ThresholdError> {
    // Validate version
    if self.version != VERSION {
        return Err(...);
    }

    // Derive key
    let key = Self::derive_key(passphrase, &self.salt, &self.kdf_params)?;

    // Decrypt with AEAD
    let cipher = XChaCha20Poly1305::new(&key.into());
    let plaintext = cipher.decrypt(
        &self.nonce.into(),
        self.ciphertext_and_tag.as_ref()
    )?; // Automatic tag verification

    // Deserialize
    let secrets: SecretMap = bincode::deserialize(&plaintext)?;

    Ok(secrets)
}
```

**Error Cases:**
- Wrong passphrase → Poly1305 tag verification fails
- Corrupted file → Tag verification fails
- Wrong version → Rejected before decryption

---

## Secret Value Formats

**Different secrets have different binary representations:**

### 1. UTF-8 Strings (Passwords, Mnemonics)

```rust
// Example: wallet_secret = "MyPassword123"
let bytes: Vec<u8> = "MyPassword123".as_bytes().to_vec();
// bytes = [0x4D, 0x79, 0x50, 0x61, 0x73, 0x73, ...]
//         ("M",  "y",  "P",  "a",  "s",  "s",  ...)

// Example: mnemonic = "abandon abandon abandon about"
let bytes: Vec<u8> = "abandon abandon abandon about".as_bytes().to_vec();
// bytes = [0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E, 0x20, ...]
//         ("a",  "b",  "a",  "n",  "d",  "o",  "n",  " ", ...)
```

**Retrieval:**
```rust
let secret_str = String::from_utf8(bytes)?;
```

---

### 2. Raw Binary Keys (32-byte keys)

```rust
// Example: private_key = 0x3a2f1c8e... (32 bytes)
let bytes: Vec<u8> = hex::decode("3a2f1c8e9d4b...")?.to_vec();
// bytes = [0x3A, 0x2F, 0x1C, 0x8E, 0x9D, 0x4B, ...]
//         (raw binary, exactly 32 bytes)

// Example: Ed25519 seed = 32 random bytes
let bytes: Vec<u8> = vec![0x42, 0x8E, 0x9A, ...]; // 32 bytes
```

**Retrieval:**
```rust
let key_bytes: [u8; 32] = bytes.try_into()?;
let secret_key = secp256k1::SecretKey::from_slice(&key_bytes)?;
```

---

### 3. Legacy: Nested Encryption (Removed)

Older versions supported `encrypted_mnemonics` in TOML plus a global `igra.hd.wallet_secret`.
This flow is removed: mnemonics are now stored directly in `secrets.bin` as profile-scoped secrets.

```rust
// Mnemonics go directly in secrets.bin (no nested encryption)
secrets_map.insert("igra.signer.mnemonic_signer-01", mnemonic.as_bytes());
```

---

## Complete Example: 3-Signer Setup

**secrets.bin (signer-01):**

```
After Decryption, SecretMap contains:
┌──────────────────────────────────────────────────────────────────┐
│ Secret Name                              │ Value (bytes)          │
├──────────────────────────────────────────┼────────────────────────┤
│ igra.signer.payment_secret_signer-01     │ "strong-passphrase-456"│
│                                          │ (UTF-8 string, 22 bytes)│
├──────────────────────────────────────────┼────────────────────────┤
│ igra.signer.mnemonic_signer-01           │ "abandon abandon ..."  │
│                                          │ (24 words, ~280 bytes) │
├──────────────────────────────────────────┼────────────────────────┤
│ igra.iroh.signer_seed_signer-01          │ [0x3A, 0x2F, ... ]     │
│                                          │ (32 bytes binary)      │
├──────────────────────────────────────────┼────────────────────────┤
│ igra.hyperlane.validator_1_key           │ [0x5C, 0x3D, ... ]     │
│                                          │ (32 bytes binary)      │
└──────────────────────────────────────────┴────────────────────────┘
```

**On Disk (encrypted):**
```
File: /var/lib/igra/signer-01/secrets.bin
Permissions: -rw------- (0600)
Size: ~500 bytes (73 header + ~400 encrypted payload + 16 tag)

[ISEC][1][params...][salt][nonce][encrypted_data][tag]
```

---

## File Operations

### Create New secrets.bin

**Command:**
```bash
export IGRA_SECRETS_PASSPHRASE="strong-passphrase"
secrets-admin --path /var/lib/igra/signer-01/secrets.bin init
```

**Process:**
1. Check file doesn't exist
2. Create empty SecretMap: `{ secrets: {} }`
3. Encrypt with Argon2id + XChaCha20-Poly1305
4. Write to file
5. Set permissions to 0600 (Unix)

**Resulting File:**
- Size: ~89 bytes (73 header + ~0 payload + 16 tag)
- Empty secrets map (no entries)

---

### Add Secret

**Command:**
```bash
export IGRA_SECRETS_PASSPHRASE="passphrase"
secrets-admin --path /var/lib/igra/signer-01/secrets.bin set \
  igra.signer.mnemonic_signer-01 \
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

**Process:**
1. Decrypt existing file with passphrase
2. Load SecretMap into memory
3. Insert new entry: `map.secrets.insert(name, value.as_bytes())`
4. Re-serialize entire map with bincode
5. Re-encrypt with NEW random nonce (old nonce discarded)
6. Atomic write: write to `.tmp`, rename to `.bin`
7. Set permissions to 0600

**Note:** Salt stays the same, but nonce is regenerated on every write!

---

### Retrieve Secret

**Command:**
```bash
export IGRA_SECRETS_PASSPHRASE="passphrase"
secrets-admin --path /var/lib/igra/signer-01/secrets.bin get \
  igra.signer.mnemonic_signer-01 \
  --unsafe-print \
  --encoding utf8
```

**Process:**
1. Read file bytes
2. Parse header (magic, version, params, salt, nonce)
3. Derive key from passphrase + salt
4. Decrypt ciphertext with key + nonce
5. Verify Poly1305 tag (automatic in AEAD)
6. Deserialize bincode → SecretMap
7. Lookup secret by name
8. Return value (redacted by default)

**In-Memory Cache (FileSecretStore):**
- Entire SecretMap cached after first load
- Individual secrets expire per TTL (300s production, 2s tests)
- Reload from disk on cache miss

---

## Security Properties

### Encryption Strength

**Key Derivation (Argon2id):**
- **Memory:** 64 MB RAM required (GPU-resistant)
- **Time:** ~0.3-1.0 seconds per attempt (brute-force resistant)
- **Parallelism:** 4 threads (ASIC-resistant)

**Brute Force Analysis:**
- Assuming 1 billion attempts/sec (optimistic for attacker)
- 64 MB per attempt → 64 PB RAM to parallelize fully
- Not feasible with current hardware

**AEAD (XChaCha20-Poly1305):**
- **Confidentiality:** XChaCha20 stream cipher (ChaCha20 variant)
- **Integrity:** Poly1305 MAC (16-byte tag)
- **Authentication:** Tag prevents tampering
- **Nonce Space:** 192 bits (2^192 = no collision risk)

---

### File Integrity

**Tamper Detection:**
- Poly1305 tag detects ANY modification to ciphertext
- Changing 1 bit → tag verification fails → decryption aborts
- Cannot partially decrypt or selectively modify secrets

**Atomic Writes:**
```rust
// Write to temporary file first
tokio::fs::write(&temp_path, &bytes).await?;

// Atomic rename (crash-safe)
tokio::fs::rename(&temp_path, &secrets_path).await?;
```

**Benefits:**
- Crash during write → old file intact
- No partially-written files
- No corruption on power loss (filesystem dependent)

---

### Permission Enforcement (Unix)

**Implementation:** `file_secret_store.rs:159`

```rust
#[cfg(target_family = "unix")]
fn set_file_permissions(path: &Path) -> Result<(), ThresholdError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}
```

**Verification on Load:**
- Checked by NetworkMode validation rules
- Mainnet: ERROR if not 0600
- Testnet: WARNING if group/world readable
- Devnet: No enforcement

---

## In-Memory Representation

### FileSecretStore Structure

```rust
pub struct FileSecretStore {
    /// Path to encrypted file
    file_path: PathBuf,

    /// Passphrase (kept in memory, zeroized on drop)
    passphrase: SecretString,

    /// Decrypted secrets cache with TTL
    cache: Arc<tokio::sync::RwLock<HashMap<SecretName, CachedSecret>>>,

    /// Shutdown signal for background cleanup task
    cleanup_shutdown: watch::Sender<bool>,

    /// Background task handle
    cleanup_task: tokio::task::JoinHandle<()>,

    /// Pending operations (not yet persisted)
    pending_ops: tokio::sync::RwLock<HashMap<SecretName, PendingOp>>,
}
```

### Cache Entry Structure

```rust
struct CachedSecret {
    /// The secret value (zeroized on drop)
    value: SecretBytes,

    /// When this cache entry expires
    expires_at: Instant,

    /// Access counter (for LRU eviction)
    access_count: u64,
}
```

### Memory Protection

**SecretBytes Wrapper:**
```rust
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.inner.zeroize(); // Overwrite with zeros
    }
}
```

**Memory Locking (Unix):**
- Secrets locked in RAM via `mlock()`
- Prevents swapping to disk
- Reduces attack surface from swap files

---

## Implementation Reference

**Core Files:**

1. **File Format:**
   - `igra-core/src/infrastructure/keys/backends/file_format.rs`
   - Lines 14-16: Magic, version, header length constants
   - Lines 19-25: SecretFile structure
   - Lines 28-37: Argon2Params with defaults
   - Lines 40-43: SecretMap (HashMap wrapper)
   - Lines 54-74: Encryption logic
   - Lines 76-91: Decryption logic
   - Lines 93-104: Binary serialization (to_bytes)
   - Lines 106-140: Binary deserialization (from_bytes)
   - Lines 142-155: Argon2id key derivation

2. **File Store:**
   - `igra-core/src/infrastructure/keys/backends/file_secret_store.rs`
   - Lines 118-145: open() method (load + cache)
   - Lines 147-174: create() method (new file)
   - Lines 185-190: set() method (pending operation)
   - Lines 199-227: save() method (atomic write)
   - Lines 158-159: Permission enforcement

3. **Secret Types:**
   - `igra-core/src/infrastructure/keys/types.rs`
   - Lines 8-17: SecretName newtype
   - Lines 38-75: KeyRef structure (namespace.key_id.version)

---

## Example: Manual Inspection

**Using hexdump to inspect secrets.bin:**

```bash
hexdump -C /var/lib/igra/secrets.bin | head -20
```

**Expected Output:**
```
00000000  49 53 45 43 01 00 00 01  00 03 00 00 00 04 00 00  |ISEC............|
          ^^^^^^^^^^^^^ ^^ ^^^^^^^^^^ ^^^^^^^^^^ ^^^^^^^^^^
          Magic         V  m_cost     t_cost     p_cost
          "ISEC"        1  65536      3          4

00000010  00 [32 bytes of random salt...]
00000030  [24 bytes of random nonce...]
00000040  [encrypted payload + 16-byte tag...]
```

**Parse Header Manually:**
```bash
# Extract magic
head -c 4 secrets.bin | xxd
# Output: 49 53 45 43  ("ISEC")

# Extract version
head -c 5 secrets.bin | tail -c 1 | xxd
# Output: 01

# Extract m_cost (little-endian)
head -c 9 secrets.bin | tail -c 4 | od -An -t u4
# Output: 65536

# Extract salt (hex)
head -c 49 secrets.bin | tail -c 32 | xxd -p
# Output: a73f2c8e91447bc3298f126d45e81a927c38bb05f2c943d1a8762f943e810c4f
```

---

## Size Calculations

### Empty secrets.bin

```
Header:           73 bytes
Payload:          ~16 bytes (empty HashMap serialized)
Tag:              16 bytes
────────────────────────────
Total:            ~105 bytes
```

---

### Single Mnemonic (24 words)

```
Header:           73 bytes
Payload:
  - HashMap len:  1 byte (varint)
  - Key name:     ~31 bytes ("igra.signer.mnemonic_default")
  - Value len:    2 bytes (varint ~280)
  - Mnemonic:     ~280 bytes (24 words × ~11 chars/word)
Tag:              16 bytes
────────────────────────────
Total:            ~403 bytes
```

---

### Full Keyset (3-signer setup)

```
Header:                           73 bytes

Payload (encrypted):
  HashMap with 5 entries:
    1. igra.hd.payment_secret      → ~20 bytes (passphrase)
    2. igra.signer.mnemonic_*      → ~280 bytes (24-word mnemonic)
    3. igra.iroh.signer_seed_*     → 32 bytes (Ed25519 seed)
    4. igra.hyperlane.validator_0  → 32 bytes (secp256k1 key)
    5. igra.hyperlane.validator_1  → 32 bytes (secp256k1 key)

  Bincode overhead:                ~50 bytes (map length, string lengths)
  Total plaintext:                 ~446 bytes

Tag:                              16 bytes
────────────────────────────────────────────
Total File Size:                  ~535 bytes
```

---

## Security Best Practices

### 1. Passphrase Requirements

**Minimum Recommendations:**
- Length: ≥16 characters
- Complexity: Mixed case, numbers, symbols
- Entropy: ≥80 bits (passphrase generator recommended)
- Storage: Password manager, HSM, or KMS

**Example Strong Passphrases:**
```
# Good (16+ chars, high entropy)
"Xy7$mK9#nQ2@pL8!wR5&vZ3%"
"correct-horse-battery-staple-2026"
"MyD0g!Ate#MyH0mew0rk@1997"

# Bad (too short, low entropy)
"password123"  ❌
"admin"        ❌
"changeme"     ❌
```

---

### 2. Backup Strategy

**What to Backup:**
```
CRITICAL (encrypted, backup immediately):
  /var/lib/igra/secrets.bin

IMPORTANT (encrypted, backup regularly):
  /var/lib/igra/config.toml

OPTIONAL (logs, audit trail):
  /var/log/igra/key-audit.log
```

**Backup Process:**
```bash
# Encrypted backup (safe to store offsite)
tar -czf igra-backup-$(date +%Y%m%d).tar.gz \
  /var/lib/igra/secrets.bin \
  /var/lib/igra/config.toml

# Verify backup
tar -tzf igra-backup-20260124.tar.gz

# Store backup
# - Encrypted cloud storage (AWS S3, Google Cloud Storage)
# - Hardware encrypted USB drive
# - Paper backup (for passphrase only - QR code)
```

**Recovery Process:**
```bash
# Extract backup
tar -xzf igra-backup-20260124.tar.gz -C /tmp/restore/

# Verify secrets.bin integrity
hexdump -C /tmp/restore/var/lib/igra/secrets.bin | head -1
# Should show "ISEC" magic bytes

# Test decryption
secrets-admin list /tmp/restore/var/lib/igra/secrets.bin "passphrase"

# If successful, restore
cp /tmp/restore/var/lib/igra/secrets.bin /var/lib/igra/
chmod 600 /var/lib/igra/secrets.bin
```

---

### 3. Passphrase Rotation

**Current Process (Manual):**

```bash
# 1. Create new secrets.bin with new passphrase
secrets-admin init /tmp/secrets-new.bin "new-strong-passphrase"

# 2. Copy all secrets from old to new
for secret in $(secrets-admin list secrets.bin "old-pass" | grep igra); do
  value=$(secrets-admin get secrets.bin "old-pass" $secret --unsafe-print)
  secrets-admin set /tmp/secrets-new.bin "new-pass" $secret "$value"
done

# 3. Verify new file
secrets-admin list /tmp/secrets-new.bin "new-pass"

# 4. Atomic replace
cp /var/lib/igra/secrets.bin /var/lib/igra/secrets.bin.old
mv /tmp/secrets-new.bin /var/lib/igra/secrets.bin
chmod 600 /var/lib/igra/secrets.bin

# 5. Update environment
export IGRA_SECRETS_PASSPHRASE="new-strong-passphrase"

# 6. Restart service
systemctl restart igra-threshold-service

# 7. Verify service started successfully
systemctl status igra-threshold-service

# 8. After confirmation, securely delete old file
shred -vfz -n 7 /var/lib/igra/secrets.bin.old
```

---

### 4. Disaster Recovery

**If secrets.bin is Corrupted:**

```bash
# 1. Check file integrity
hexdump -C /var/lib/igra/secrets.bin | head -1
# If doesn't show "ISEC", file is corrupted

# 2. Try decryption
secrets-admin list /var/lib/igra/secrets.bin "passphrase"
# If "Decryption failed" → wrong passphrase or corruption

# 3. Restore from backup
cp /backups/igra-backup-latest/secrets.bin /var/lib/igra/
chmod 600 /var/lib/igra/secrets.bin

# 4. Verify restoration
secrets-admin list /var/lib/igra/secrets.bin "passphrase"

# 5. Restart service
systemctl restart igra-threshold-service
```

**If Passphrase Lost:**
- ⚠️ **NO RECOVERY POSSIBLE** - Argon2id is designed to be irreversible
- Secrets are lost permanently
- Must regenerate keys and update multisig configuration
- This is intentional (security vs. recoverability trade-off)

---

## Constants Reference

**File Format Constants:**
```rust
const MAGIC: [u8; 4] = *b"ISEC";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 73; // 4 + 1 + 12 + 32 + 24
const SALT_SIZE_BYTES: usize = 32;
const NONCE_SIZE_BYTES: usize = 24;
const AUTH_TAG_SIZE_BYTES: usize = 16;
```

**Argon2 Default Parameters:**
```rust
const DEFAULT_ARGON2_M_COST_KB: u32 = 65536; // 64 MB RAM
const DEFAULT_ARGON2_T_COST: u32 = 3;        // 3 iterations
const DEFAULT_ARGON2_P_COST: u32 = 4;        // 4 threads
const ARGON2_KEY_OUTPUT_SIZE_BYTES: usize = 32;
```

**Cache Parameters (Production):**
```rust
const PRODUCTION_CACHE_TTL_SECS: u64 = 300;       // 5 minutes
const PRODUCTION_CLEANUP_INTERVAL_SECS: u64 = 60; // 1 minute
const PRODUCTION_GRACE_PERIOD_SECS: u64 = 5;      // 5 seconds
```

**Cache Parameters (Tests):**
```rust
const TEST_CACHE_TTL_SECS: u64 = 2;               // 2 seconds
const TEST_CLEANUP_INTERVAL_SECS: u64 = 1;        // 1 second
const TEST_GRACE_PERIOD_SECS: u64 = 1;            // 1 second
```

---

## Comparison with Other Secret Storage Systems

| Feature | secrets.bin (Igra) | Kubernetes Secrets | HashiCorp Vault | age-encryption |
|---------|-------------------|-------------------|----------------|----------------|
| **Encryption** | XChaCha20-Poly1305 | AES-256-GCM (etcd) | AES-256-GCM | ChaCha20-Poly1305 |
| **KDF** | Argon2id (64MB, 3 iter) | None (keys from external) | PBKDF2 or Argon2 | scrypt |
| **At-Rest** | Always encrypted | Base64 (no encryption!) | Encrypted | Encrypted |
| **Permissions** | 0600 enforced | RBAC | ACL policies | File system |
| **Multi-Value** | HashMap (multiple secrets) | One value per Secret | K/V store | One file per secret |
| **Versioning** | No (future: key rotation) | Yes (via resourceVersion) | Yes | No |
| **Audit** | Separate audit.log | Audit logs | Audit device | No |
| **Network** | Local file only | Cluster-wide | Networked | Local file only |

**Why secrets.bin is Suitable for Igra:**
- ✅ Local-first (no network dependency)
- ✅ Strong KDF (memory-hard, GPU-resistant)
- ✅ Single file (easy backup/restore)
- ✅ No external dependencies (no server to run)
- ✅ Atomic updates (crash-safe)
- ✅ Simple permissions model (0600)

---

## Future Enhancements

### Planned Improvements

1. **Key Versioning:**
   - Support multiple versions of same secret
   - Format: `igra.signer.mnemonic_default.v1`, `v2`, etc.
   - Enables key rotation without breaking old references

2. **Separate Metadata:**
   - Store secret metadata separately
   - Includes: created_at, rotated_at, last_used_at
   - Enables audit without decrypting secrets

3. **Compression:**
   - Compress plaintext before encryption (if >1KB)
   - Use zstd or gzip
   - Reduces file size for large secret sets

4. **HSM Integration:**
   - Store keys in Hardware Security Module
   - Keep metadata in secrets.bin
   - Reference HSM keys by ID

---

## Appendix: Command Reference

### secrets-admin CLI

**Create new file:**
```bash
secrets-admin init <file> <passphrase>
```

**List all secrets (values redacted):**
```bash
secrets-admin list <file> <passphrase>
```

**Get specific secret (redacted):**
```bash
secrets-admin get <file> <passphrase> <secret_name>
```

**Get specific secret (exposed - DANGEROUS):**
```bash
secrets-admin get <file> <passphrase> <secret_name> --unsafe-print
```

**Set/update secret:**
```bash
secrets-admin set <file> <passphrase> <secret_name> <value>
```

**Remove secret:**
```bash
secrets-admin remove <file> <passphrase> <secret_name>
```

---

## Quick Reference Card

**File Header (73 bytes):**
```
+0  (4)  Magic:    "ISEC"
+4  (1)  Version:  1
+5  (4)  m_cost:   65536 KB (64 MB)
+9  (4)  t_cost:   3 iterations
+13 (4)  p_cost:   4 threads
+17 (32) Salt:     Random (per file)
+49 (24) Nonce:    Random (per encryption)
+73 (*)  Payload:  Encrypted + 16-byte tag
```

**Secret Naming:**
```
Pattern: igra.<component>.<key_id>_<profile>

Examples:
  igra.hd.wallet_secret
  igra.signer.mnemonic_default
  igra.iroh.signer_seed_signer_1
```

**Security:**
```
Encryption:  XChaCha20-Poly1305 (AEAD)
KDF:         Argon2id v0x13
Salt:        32 bytes random (unique per file)
Nonce:       24 bytes random (unique per write)
Tag:         16 bytes (tamper detection)
Permissions: 0600 (owner only)
```

---

**Document Version:** 1.0
**Last Updated:** 2026-01-24
**Implementation:** `igra-core/src/infrastructure/keys/backends/file_format.rs`
