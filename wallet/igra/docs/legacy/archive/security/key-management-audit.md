# KASPA WALLET KEY MANAGEMENT SYSTEM - COMPREHENSIVE AUDIT

**Auditor:** Security Analysis
**Date:** 2026-01-23
**Version:** Current (devel branch)
**Scope:** wallet/core, wallet/bip32, wallet/keys

---

## EXECUTIVE SUMMARY

The Kaspa wallet implements a hierarchical deterministic (HD) wallet system following BIP32/BIP39/BIP44 standards with Kaspa-specific extensions. Keys are protected using XChaCha20-Poly1305 encryption with Argon2 key derivation, though **plaintext storage is optionally allowed** (security risk).

### Critical Security Findings:
1. **User-dependent encryption** - Keys can be stored in plaintext if no payment secret provided
2. **Non-cryptographic key IDs** - Uses xxHash3 (collision-resistant but not cryptographically secure)
3. **Dual derivation schemes** - Legacy (Gen0) and standard BIP44 (Gen1) paths coexist
4. **Memory safety** - Properly implements zeroization on drop

---

## 1. KEY TYPE HIERARCHY

```
┌─────────────────────────────────────────────────────────────────────┐
│                         KEY TYPE HIERARCHY                           │
└─────────────────────────────────────────────────────────────────────┘

                    ┌──────────────────────┐
                    │   Mnemonic (BIP39)   │
                    │ 12-24 English words  │
                    │   Zeroizing<String>  │
                    └──────────┬───────────┘
                               │ PBKDF2-HMAC-SHA512
                               │ (+ optional passphrase)
                               ▼
                    ┌──────────────────────┐
                    │    BIP39 Seed        │
                    │  16/32/64 bytes      │
                    │   Zeroizing<Vec>     │
                    └──────────┬───────────┘
                               │ HMAC-SHA512("Bitcoin seed")
                               ▼
        ┌──────────────────────────────────────────────┐
        │       ExtendedPrivateKey (XPrv)              │
        │  Format: kprv... (Kaspa prefix)              │
        │  ┌────────────────────────────────────────┐  │
        │  │ Private Key: secp256k1::SecretKey      │  │
        │  │              (32 bytes)                │  │
        │  ├────────────────────────────────────────┤  │
        │  │ Chain Code: [u8; 32]                   │  │
        │  ├────────────────────────────────────────┤  │
        │  │ Attributes:                            │  │
        │  │   - Depth: u8                          │  │
        │  │   - Parent Fingerprint: [u8; 4]        │  │
        │  │   - Child Number: u32                  │  │
        │  └────────────────────────────────────────┘  │
        └──────────────────┬───────────────────────────┘
                           │ BIP32 Derivation
                           ▼
        ┌──────────────────────────────────────────────┐
        │      Derived secp256k1::SecretKey            │
        │         (32 bytes, for signing)              │
        └──────────────────┬───────────────────────────┘
                           │ secp256k1 multiplication
                           ▼
        ┌──────────────────────────────────────────────┐
        │     secp256k1::PublicKey (33 bytes)          │
        │     or X-Only PublicKey (32 bytes)           │
        │     ─────────────────────────────────        │
        │     Used for address generation              │
        └──────────────────────────────────────────────┘

STANDALONE KEY TYPE:
        ┌──────────────────────────────────────────────┐
        │    SecretKey (Direct Import)                 │
        │    - 32 bytes hex-encoded                    │
        │    - No derivation capability                │
        │    - Used for keypair accounts               │
        └──────────────────────────────────────────────┘
```

---

## 2. KEY GENERATION FLOW

```
┌─────────────────────────────────────────────────────────────────────┐
│                    KEY GENERATION PATHWAYS                           │
└─────────────────────────────────────────────────────────────────────┘

PATH 1: MNEMONIC-BASED GENERATION (Standard)
═══════════════════════════════════════════════

  User Input                  Mnemonic Generation
  ──────────                  ───────────────────
      │                              │
      ▼                              ▼
┌───────────────┐           ┌─────────────────┐
│ User provides │           │ Random entropy  │
│ word count    │           │ (128-256 bits)  │
│ (12 or 24)    │           │ via OsRng       │
└───────┬───────┘           └────────┬────────┘
        │                            │
        │                            ▼
        │                   ┌─────────────────┐
        │                   │ BIP39 wordlist  │
        │                   │ (English only)  │
        │                   └────────┬────────┘
        │                            │
        └─────────┬──────────────────┘
                  │
                  ▼
        ┌──────────────────────┐
        │  Mnemonic::new()     │
        │  (kaspa-bip32 crate) │
        └──────────┬───────────┘
                   │
                   │ Optional: User Payment Secret (Passphrase)
                   │           (BIP39 extension)
                   ▼
        ┌──────────────────────┐
        │ Mnemonic::to_seed()  │
        │ ───────────────────  │
        │ PBKDF2-HMAC-SHA512   │
        │ • Rounds: 2048       │
        │ • Salt: "mnemonic" + │
        │         passphrase   │
        │ • Output: 64 bytes   │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────────────────┐
        │ ExtendedPrivateKey::new(seed)    │
        │ ────────────────────────────────  │
        │ HMAC-SHA512(                     │
        │   key: "Bitcoin seed",           │
        │   data: seed                     │
        │ )                                │
        │ Split: [privkey(32)][chain(32)]  │
        └──────────┬───────────────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │   Root XPrv (m)      │
        │   depth = 0          │
        └──────────────────────┘


PATH 2: DIRECT SEED IMPORT
═══════════════════════════

  User provides seed bytes
  (16, 32, or 64 bytes)
         │
         ▼
  ExtendedPrivateKey::new()
         │
         └──> [Same as above]


PATH 3: DIRECT SECRET KEY IMPORT
═════════════════════════════════

  User provides 32-byte
  hex-encoded secret key
         │
         ▼
  secp256k1::SecretKey::from_str()
         │
         ▼
  PrvKeyDataVariant::SecretKey
  (No derivation capability)


PATH 4: XPRV STRING IMPORT
═══════════════════════════

  User provides "kprv..." string
         │
         ▼
  ExtendedKey::from_str()
         │
         ▼
  ExtendedPrivateKey::try_from()
  (Full key with attributes restored)
```

---

## 3. KEY DERIVATION PATHS (BIP32)

```
┌─────────────────────────────────────────────────────────────────────┐
│                   HIERARCHICAL KEY DERIVATION                        │
└─────────────────────────────────────────────────────────────────────┘

ROOT
  m (Master Private Key)
  │
  └─ BIP44 Standard Path (Gen1):
     │
     ├─ m / 44' / 111' / account' / change / address_index
     │    │      │       │          │        │
     │    │      │       │          │        └─ Non-hardened: 0, 1, 2...
     │    │      │       │          │           (Can derive from XPub)
     │    │      │       │          │
     │    │      │       │          └─ Change Path:
     │    │      │       │             0 = Receive addresses
     │    │      │       │             1 = Change addresses
     │    │      │       │
     │    │      │       └─ Account Index (hardened):
     │    │      │          0', 1', 2'... (2^31 + n)
     │    │      │          (Requires private key)
     │    │      │
     │    │      └─ Coin Type: 111' (Kaspa)
     │    │
     │    └─ Purpose: 44' (BIP44)
     │
     ├─ Multisig Path (Gen1):
     │  │
     │  └─ m / 45' / 0' / cosigner_index / change / address_index
     │       │      │     │                │        │
     │       │      │     │                │        └─ Address: 0, 1, 2...
     │       │      │     │                │
     │       │      │     │                └─ Change: 0 (receive), 1 (change)
     │       │      │     │
     │       │      │     └─ Cosigner: 0, 1, 2... (for M-of-N)
     │       │      │
     │       │      └─ Reserved: 0'
     │       │
     │       └─ Purpose: 45' (BIP45 - Multisig)
     │
     └─ Legacy Path (Gen0):
        └─ m / 0' / ...
           (Non-standard, wallet-specific)


DERIVATION ALGORITHM:
═════════════════════

For child index i:

  IF i >= 2^31 (Hardened):
    ┌───────────────────────────────────────┐
    │ HMAC-SHA512(                          │
    │   key: parent_chain_code,             │
    │   data: 0x00 || parent_privkey || i   │
    │ )                                     │
    └─────────────┬─────────────────────────┘
                  │
                  └─> [child_privkey(32)][child_chain(32)]

  ELSE (Non-hardened):
    ┌───────────────────────────────────────┐
    │ HMAC-SHA512(                          │
    │   key: parent_chain_code,             │
    │   data: parent_pubkey || i            │
    │ )                                     │
    └─────────────┬─────────────────────────┘
                  │
                  └─> [offset(32)][child_chain(32)]

  child_privkey = (parent_privkey + offset) mod n
                  (where n = secp256k1 curve order)
```

---

## 4. ENCRYPTION & STORAGE ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────────────┐
│                   ENCRYPTION & STORAGE SYSTEM                        │
└─────────────────────────────────────────────────────────────────────┘

ENCRYPTION CONTAINER:
═════════════════════

    PrvKeyData
    ├── id: PrvKeyDataId (8 bytes, xxHash3 of key material)
    ├── name: Option<String> (user label)
    └── payload: Encryptable<PrvKeyDataPayload>
                     │
                     └───┬─────────────────────────────────┐
                         │                                 │
                         ▼                                 ▼
                 ┌───────────────┐            ┌────────────────────────┐
                 │ Plain(T)      │            │ XChaCha20Poly1305(E)   │
                 │ ─────────     │            │ ────────────────────   │
                 │ Plaintext     │            │ Encrypted              │
                 │ storage       │            │ (binary blob)          │
                 └───────────────┘            └────────────────────────┘
                       │                                  │
                       ▼                                  ▼
            ┌─────────────────────┐         ┌────────────────────────────┐
            │ PrvKeyDataPayload   │         │    Encrypted Payload       │
            │ ─────────────────── │         │    [nonce(24)][cipher][tag]│
            │ prv_key_variant:    │         └────────────────────────────┘
            │   - Mnemonic(String)│
            │   - Bip39Seed(Hex)  │
            │   - XPrv(String)    │
            │   - SecretKey(Hex)  │
            └─────────────────────┘


ENCRYPTION PROCESS:
═══════════════════

  User Password/Secret
        │
        ▼
  ┌─────────────────────────────────────┐
  │ SHA256(password)                    │
  │ ───────────────                     │
  │ Output: 32-byte salt                │
  └──────────┬──────────────────────────┘
             │
             ▼
  ┌─────────────────────────────────────┐
  │ Argon2id                            │
  │ ───────────────────────────────     │
  │ • Password: user_secret             │
  │ • Salt: SHA256(user_secret)         │
  │ • Output length: 32 bytes           │
  │ • Memory cost: 19456 KiB (default)  │
  │ • Time cost: 2 iterations           │
  │ • Parallelism: 1 thread             │
  └──────────┬──────────────────────────┘
             │
             ▼
  ┌─────────────────────────────────────┐
  │ XChaCha20-Poly1305 Key (32 bytes)   │
  └──────────┬──────────────────────────┘
             │
             ├──> Generate random 192-bit nonce (OsRng)
             │
             ▼
  ┌─────────────────────────────────────┐
  │ Borsh Serialize(PrvKeyDataPayload)  │
  └──────────┬──────────────────────────┘
             │
             ▼
  ┌─────────────────────────────────────────────────┐
  │ XChaCha20-Poly1305 AEAD Encryption              │
  │ ───────────────────────────────────             │
  │ cipher.encrypt_in_place(                        │
  │   nonce: 192-bit random,                        │
  │   aad: [] (empty),                              │
  │   buffer: serialized_payload                    │
  │ )                                               │
  └──────────┬──────────────────────────────────────┘
             │
             ▼
  ┌─────────────────────────────────────┐
  │ Output Format:                      │
  │ [nonce(24 bytes)]                   │
  │ [ciphertext(variable)]              │
  │ [auth_tag(16 bytes)]                │
  │                                     │
  │ Total: 24 + len(plaintext) + 16     │
  └─────────────────────────────────────┘


DECRYPTION PROCESS:
═══════════════════

  Encrypted Data + User Secret
        │
        ├──> Extract nonce (first 24 bytes)
        ├──> Extract ciphertext+tag (remaining bytes)
        │
        ▼
  Derive key via Argon2+SHA256 (same as encryption)
        │
        ▼
  ┌─────────────────────────────────────┐
  │ XChaCha20-Poly1305 Decryption       │
  │ ───────────────────────────────     │
  │ cipher.decrypt_in_place(            │
  │   nonce: extracted,                 │
  │   aad: [],                          │
  │   buffer: ciphertext+tag            │
  │ )                                   │
  │                                     │
  │ Authenticates with Poly1305 tag     │
  │ Decrypts with XChaCha20             │
  └──────────┬──────────────────────────┘
             │
             ▼ (On success)
  ┌─────────────────────────────────────┐
  │ Borsh Deserialize                   │
  │ ───────────────────                 │
  │ PrvKeyDataPayload restored          │
  └─────────────────────────────────────┘


STORAGE HIERARCHY:
══════════════════

Platform-Specific Paths:
  • Linux:   ~/.kaspa/wallet/
  • macOS:   ~/Library/Application Support/kaspa/wallet/
  • Windows: %APPDATA%\kaspa\wallet\
  • Web:     IndexedDB (browser storage)

Wallet Storage
├── accounts.db (Binary Borsh format)
│   ├── Account metadata
│   ├── Derivation indices
│   └── Associated PrvKeyData IDs
│
├── keydata.db (Binary Borsh format)
│   ├── PrvKeyData entries
│   │   ├── Magic: 0x5652504b
│   │   ├── Version: 0
│   │   ├── ID: xxHash3(key_material)
│   │   ├── Name: Optional<String>
│   │   └── Payload: Encryptable<...>
│   │
│   └── Encryption State:
│       ├── Plain: Unencrypted (if no password)
│       └── XChaCha20Poly1305: Encrypted blob
│
└── transactions.db (Transaction history)
    └── Transaction records with references
```

---

## 5. KEY USAGE FLOW (TRANSACTION SIGNING)

```
┌─────────────────────────────────────────────────────────────────────┐
│                     TRANSACTION SIGNING FLOW                         │
└─────────────────────────────────────────────────────────────────────┘

User initiates transaction with target addresses
        │
        ▼
┌──────────────────────────────────────────────────┐
│ Signer::try_sign(transaction, addresses)         │
└──────────────────┬───────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────┐
│ Step 1: Load PrvKeyData from storage             │
│         (by associated PrvKeyDataId)             │
└──────────────────┬───────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────┐
│ Step 2: Decrypt with payment secret              │
│                                                  │
│   payload.decrypt(payment_secret)?               │
│   ───────────────────────────────                │
│   • If Plain: return immediately                 │
│   • If Encrypted: XChaCha20Poly1305 decrypt      │
└──────────────────┬───────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────┐
│ Step 3: Extract Extended Private Key             │
│                                                  │
│   payload.get_xprv(payment_secret)?              │
│   ───────────────────────────────                │
│   • From Mnemonic: via to_seed()                 │
│   • From Bip39Seed: direct parse                 │
│   • From XPrv string: parse                      │
│   • From SecretKey: ERROR (no XPrv support)      │
└──────────────────┬───────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────┐
│ Step 4: Derive private keys for addresses       │
│                                                  │
│   create_private_keys(                           │
│     account_kind,                                │
│     account_index,                               │
│     xkey,                                        │
│     receive_addresses,                           │
│     change_addresses                             │
│   )                                              │
│   ───────────────────────────────                │
│   Process:                                       │
│   1. Build derivation paths:                     │
│      • BIP44: m/44'/111'/acct'/0/{idx}          │
│      • Multisig: m/45'/0'/cosigner/0/{idx}      │
│   2. Derive XPrv for receive & change paths      │
│   3. For each address index:                     │
│      - Derive child key (non-hardened)           │
│      - Extract secp256k1::SecretKey              │
└──────────────────┬───────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────┐
│ Step 5: Load keys into signing context          │
│                                                  │
│   keys.insert(address, private_key.to_bytes())   │
│   ──────────────────────────────────────         │
│   • Store as [u8; 32] in HashMap                 │
│   • One entry per address                        │
└──────────────────┬───────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────┐
│ Step 6: Sign transaction inputs                 │
│                                                  │
│   sign_with_multiple_v2(                         │
│     mutable_tx,                                  │
│     &keys_for_signing                            │
│   )                                              │
│   ───────────────────────────────                │
│   • For each input:                              │
│     - Find corresponding address                 │
│     - Retrieve private key                       │
│     - Create signature (ECDSA or Schnorr)        │
│     - Attach to transaction input                │
└──────────────────┬───────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────┐
│ Step 7: Zeroize sensitive data                   │
│                                                  │
│   keys_for_signing.zeroize()                     │
│   ───────────────────────────────                │
│   • Overwrites private key bytes with zeros      │
│   • Drops from memory                            │
└──────────────────┬───────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────┐
│ Return signed transaction                        │
└──────────────────────────────────────────────────┘


ADDRESS GENERATION (Companion Process):
════════════════════════════════════════

Extended Public Key (XPub) → Public Key Derivation
        │
        ├─ For non-hardened paths only
        │  (cannot derive hardened children from XPub)
        │
        ▼
┌──────────────────────────────────────────────────┐
│ Derive child public key for index i             │
│                                                  │
│   child_pubkey = parent_pubkey +                 │
│                  G * HMAC(chain_code, data)[0:32]│
│   ───────────────────────────────                │
│   • G = secp256k1 generator point                │
│   • Same HMAC as private derivation              │
│   • Mathematically equivalent result             │
└──────────────────┬───────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────┐
│ Convert to address                               │
│                                                  │
│   • Extract X-only (32 bytes) for Schnorr        │
│   • Or use compressed (33 bytes) for ECDSA       │
│   • Apply network prefix                         │
│   • Encode as Bech32m address                    │
└──────────────────────────────────────────────────┘
```

---

## 6. THIRD-PARTY CRYPTOGRAPHIC LIBRARIES

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CRYPTOGRAPHIC DEPENDENCIES                        │
└─────────────────────────────────────────────────────────────────────┘

CORE ELLIPTIC CURVE CRYPTOGRAPHY:
══════════════════════════════════

  secp256k1 (v0.28+)
  ├── Provider: rust-bitcoin/rust-secp256k1
  ├── Purpose: ECDSA & Schnorr signatures, key operations
  ├── Features:
  │   ├── SecretKey generation & validation
  │   ├── PublicKey derivation & compression
  │   ├── Signature creation (ECDSA & Schnorr)
  │   ├── X-only public keys (Schnorr/Taproot)
  │   └── Constant-time operations
  └── Security: Industry-standard, widely audited


SYMMETRIC ENCRYPTION:
═════════════════════

  chacha20poly1305 (AEAD cipher)
  ├── Provider: RustCrypto/AEADs
  ├── Purpose: Private key encryption
  ├── Algorithm: XChaCha20-Poly1305
  │   ├── Cipher: XChaCha20 (extended nonce ChaCha20)
  │   ├── Nonce: 192 bits (24 bytes) - randomly generated
  │   ├── MAC: Poly1305 (128-bit authentication tag)
  │   └── Key: 256 bits (32 bytes)
  └── Security: Modern AEAD, resistance to timing attacks

  aes (legacy support)
  ├── Provider: RustCrypto
  ├── Purpose: Legacy wallet compatibility
  └── Mode: CFB (Cipher Feedback)

  cfb-mode
  ├── Purpose: CFB mode implementation for AES
  └── Note: Legacy, not used for new keys


KEY DERIVATION:
═══════════════

  argon2 (Argon2id)
  ├── Provider: RustCrypto/password-hashes
  ├── Purpose: Password → encryption key derivation
  ├── Configuration:
  │   ├── Variant: Argon2id (default)
  │   ├── Memory: 19456 KiB
  │   ├── Iterations: 2
  │   ├── Parallelism: 1
  │   └── Output: 32 bytes
  ├── Salt: SHA256(password)
  └── Security: Winner of Password Hashing Competition (2015)

  pbkdf2 (PBKDF2-HMAC-SHA512)
  ├── Provider: RustCrypto/password-hashes
  ├── Purpose: BIP39 mnemonic → seed derivation
  ├── Configuration:
  │   ├── PRF: HMAC-SHA512
  │   ├── Iterations: 2048 (BIP39 standard)
  │   ├── Salt: "mnemonic" + optional passphrase
  │   └── Output: 64 bytes
  └── Usage: BIP39 specification requirement

  evpkdf
  ├── Purpose: EVP key derivation (legacy compatibility)
  └── Note: Not primary encryption mechanism


HASHING:
════════

  sha2 (SHA-256, SHA-512)
  ├── Provider: RustCrypto/hashes
  ├── Purpose:
  │   ├── Address fingerprints
  │   ├── Key ID generation (in combination with xxHash)
  │   └── Salt generation for Argon2
  └── Standard: FIPS 180-4

  ripemd (RIPEMD-160)
  ├── Provider: RustCrypto/hashes
  ├── Purpose: Public key fingerprints
  └── Usage: BIP32 parent fingerprint (first 4 bytes)

  sha1 (SHA-1)
  ├── Provider: RustCrypto/hashes
  ├── Purpose: Legacy compatibility
  └── Security: Deprecated, not used for key operations

  md-5 (MD5)
  ├── Purpose: Legacy format compatibility
  └── Security: Broken, not used for cryptographic purposes

  xxhash-rust (xxHash3)
  ├── Purpose: Fast key ID generation
  ├── Algorithm: xxHash3-64 (non-cryptographic)
  ├── Output: 8 bytes (u64)
  ├── Usage: PrvKeyDataId = xxh3_64(key_material_string)
  └── Note: NOT cryptographically secure (collision-resistant only)


MESSAGE AUTHENTICATION:
═══════════════════════

  hmac (HMAC-SHA256, HMAC-SHA512)
  ├── Provider: RustCrypto/MACs
  ├── Purpose: BIP32 child key derivation
  ├── Usage:
  │   ├── Seed → Master key derivation
  │   ├── Parent key → Child key derivation
  │   └── Chain code operations
  └── Standard: FIPS 198-1


RANDOM NUMBER GENERATION:
══════════════════════════

  rand (Random number generation)
  ├── Provider: rust-random
  ├── Purpose: Entropy source for key generation
  └── Backend: OsRng (OS-level CSPRNG)

  getrandom
  ├── Purpose: Cross-platform OS entropy access
  ├── Platforms:
  │   ├── Linux: /dev/urandom
  │   ├── macOS: getentropy()
  │   ├── Windows: BCryptGenRandom
  │   └── Web: crypto.getRandomValues() (JS)
  └── Security: OS-provided cryptographic randomness


MEMORY PROTECTION:
══════════════════

  zeroize (Secure memory clearing)
  ├── Provider: RustCrypto/utils
  ├── Purpose: Prevent key material leakage
  ├── Implementation:
  │   ├── Overwrites memory with zeros
  │   ├── Prevents compiler optimization removal
  │   └── Called on Drop trait
  ├── Applied to:
  │   ├── PrvKeyDataVariant
  │   ├── PrvKeyDataPayload
  │   ├── ExtendedPrivateKey
  │   ├── SecretKey
  │   └── All sensitive strings (via Zeroizing<T>)
  └── Standard: volatile_memset semantics


ENCODING:
═════════

  base64
  ├── Purpose: Binary-to-text encoding
  └── Usage: Data serialization, not key encoding

  faster-hex
  ├── Purpose: Hex encoding/decoding (optimized)
  └── Usage: Private key string representation


ELLIPTIC CURVE BOXING:
═══════════════════════

  crypto_box (NaCl-compatible)
  ├── Purpose: Public-key authenticated encryption
  ├── Note: Not primary wallet encryption
  └── Algorithm: X25519 + XSalsa20 + Poly1305
```

---

## 7. ACCOUNT TYPES & KEY MANAGEMENT PATTERNS

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ACCOUNT TYPE MATRIX                          │
└─────────────────────────────────────────────────────────────────────┘

ACCOUNT TYPE              KEY MATERIAL              DERIVATION  SIGNING
────────────────────────────────────────────────────────────────────────
BIP32 (Standard)          Extended Private Key      BIP44       ✓
kaspa-bip32-standard      (XPrv)                    m/44'/111'
                          + Optional Mnemonic        /acct'/...

BIP32 Watch-Only          Extended Public Key       BIP44       ✗
kaspa-bip32-watch         (XPub only)               (from XPub) (Watch)

Multisig (Standard)       Multiple XPubs            BIP45       ✓ (M/N)
kaspa-multisig-standard   + Optional XPrv(s)        m/45'/0'/...
                          M-of-N signature scheme

Keypair (Direct)          Single SecretKey          None        ✓
kaspa-keypair-standard    (32 bytes, no chain code) (Direct)

Legacy Account            Extended Private Key      Custom      ✓
kaspa-legacy              (Old derivation scheme)   m/0'/...    (Legacy)
────────────────────────────────────────────────────────────────────────

KEY STORAGE PATTERNS:
═════════════════════

┌─────────────────────────────────────────────────────────────────┐
│ Account                                                         │
│ ├── Account ID (u64)                                            │
│ ├── Account Type (enum)                                         │
│ ├── Derivation Meta ([receive_idx, change_idx])                │
│ └── Prv Key Data IDs: Arc<Vec<PrvKeyDataId>>                   │
│                            │                                    │
│                            └───> Reference to PrvKeyData        │
└─────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ PrvKeyData Store (Central Repository)                          │
│ ├── Entry 1: ID=0x1234... ──> Mnemonic (encrypted)             │
│ ├── Entry 2: ID=0x5678... ──> XPrv (encrypted)                 │
│ ├── Entry 3: ID=0xABCD... ──> SecretKey (plain)                │
│ └── ...                                                         │
└─────────────────────────────────────────────────────────────────┘

Multiple accounts can reference the same PrvKeyData entry
(e.g., different account indices from same mnemonic)
```

---

## 8. SECURITY ANALYSIS & RISK ASSESSMENT

```
┌─────────────────────────────────────────────────────────────────────┐
│                      SECURITY RISK MATRIX                            │
└─────────────────────────────────────────────────────────────────────┘

COMPONENT                 IMPLEMENTATION           RISK    NOTES
────────────────────────────────────────────────────────────────────────
Encryption Algorithm      XChaCha20-Poly1305       LOW     Modern AEAD,
                          256-bit keys                     resistant to
                                                           timing attacks

Key Derivation (Pass)     Argon2id                 LOW     Memory-hard,
                          + SHA256 salt                    PHC winner

Key Derivation (HD)       BIP32 HMAC-SHA512        LOW     Standard impl,
                          secp256k1                        constant-time

Random Generation         OsRng (getrandom)        LOW     OS-level CSPRNG,
                                                           platform-specific

Memory Safety             Zeroize on Drop          LOW     Proper cleanup,
                                                           volatile semantics

Key ID Generation         xxHash3 (64-bit)         MED     NON-cryptographic
                                                           hash, collision
                                                           risk in theory
                                                           (2^32 birthday)

Plaintext Storage         Encryptable::Plain       HIGH    ⚠️ CRITICAL:
                          (optional)                       Keys stored
                                                           unencrypted if
                                                           no password set

User Responsibility       Password requirement     HIGH    Security depends
                          optional                         entirely on user
                                                           providing strong
                                                           payment secret

Dual Derivation Paths     Gen0 (legacy) +          MED     Maintenance
                          Gen1 (standard)                  burden, potential
                                                           confusion

Nonce Reuse Protection    Per-message random       LOW     192-bit nonce,
                          (96-bit actual)                  negligible
                                                           collision risk

Salt Reuse (Argon2)       SHA256(password)         LOW-MED Deterministic
                                                           salt, but output
                                                           still secure

BIP39 Passphrase          Optional "25th word"     LOW     Standard impl,
                          via to_seed()                    user education
                                                           critical
────────────────────────────────────────────────────────────────────────


CRITICAL SECURITY FINDINGS:
═══════════════════════════

🔴 CRITICAL: Plaintext Key Storage
   ────────────────────────────────
   If user doesn't provide payment secret, keys stored as:

   payload: Encryptable::Plain(PrvKeyDataPayload)

   Risk: Complete compromise on disk/storage access
   Recommendation: Force encryption, warn users prominently

🟠 HIGH: User-Dependent Security
   ─────────────────────────────
   Wallet security model relies entirely on user providing
   strong payment secret. No enforced minimum strength.

   Recommendation: Implement password strength requirements

🟡 MEDIUM: Non-Cryptographic Key IDs
   ──────────────────────────────────
   PrvKeyDataId = xxh3_64(key_material_string)

   xxHash3 is NOT cryptographically secure. Theoretically
   possible to craft collision (birthday attack ~2^32).

   Recommendation: Use BLAKE3 or SHA256 for key IDs

🟡 MEDIUM: Dual Derivation Schemes
   ────────────────────────────────
   Gen0 (legacy) and Gen1 (BIP44) coexist in codebase.

   Risk: Confusion, maintenance burden, potential bugs
   Recommendation: Deprecation path for legacy accounts


POSITIVE SECURITY ASPECTS:
══════════════════════════

✅ Modern AEAD encryption (XChaCha20-Poly1305)
✅ Memory-hard KDF (Argon2)
✅ Proper zeroization (all key types)
✅ Constant-time comparisons (ExtendedPrivateKey)
✅ Standard BIP32/BIP39/BIP44 compliance
✅ OS-level CSPRNG (not userspace RNG)
✅ Nonce never reused (per-message random)
✅ Authenticated encryption (prevents tampering)
```

---

## 9. DATA FLOW DIAGRAM (END-TO-END)

```
┌─────────────────────────────────────────────────────────────────────┐
│                  COMPLETE KEY LIFECYCLE DATA FLOW                    │
└─────────────────────────────────────────────────────────────────────┘


CREATION PHASE:
═══════════════

User Input            Wallet Core               Storage Layer
──────────            ───────────               ─────────────

Generate Wallet
     │
     ├─> [Word count: 12/24]
     │         │
     │         ▼
     │    OsRng entropy
     │         │
     │         ▼
     │    BIP39 wordlist
     │         │
     │         ▼
     │    ┌────────────┐
     │    │  Mnemonic  │
     │    └─────┬──────┘
     │          │
     ├─ Payment Secret
     │  (optional)
     │          │
     │          ▼
     │    PBKDF2-HMAC-SHA512
     │          │
     │          ▼
     │    ┌────────────┐
     │    │ BIP39 Seed │
     │    └─────┬──────┘
     │          │
     │          ▼
     │    HMAC-SHA512
     │    ("Bitcoin seed")
     │          │
     │          ▼
     │    ┌───────────────────┐
     │    │ ExtendedPrivateKey│
     │    │ (Master, depth=0) │
     │    └─────┬─────────────┘
     │          │
     ├─ Encryption choice
     │  [Encrypt: Y/N]
     │          │
     │          ▼
     │    ┌──────────────────┐      ┌─────────────────┐
     │    │ If password set: │      │ Argon2 + SHA256 │
     │    │ XChaCha20Poly1305├─────>│ Nonce: random   │
     │    └──────────────────┘      └────────┬────────┘
     │          │                             │
     │          ▼                             │
     │    ┌──────────────────┐               │
     │    │ PrvKeyDataPayload│<──────────────┘
     │    │ ├─ variant       │
     │    │ └─ ID (xxHash3)  │
     │    └─────┬────────────┘
     │          │
     │          ▼
     │    ┌──────────────────┐
     │    │    PrvKeyData    │
     │    │ ├─ id: u64       │──────────────> Write to keydata.db
     │    │ ├─ name: Option  │                (Borsh serialized)
     │    │ └─ payload:      │
     │    │    Encryptable<> │
     │    └──────────────────┘
     │
     ▼
┌────────────────┐
│ Account Create │
│ ├─ type        │
│ ├─ index       │──────────────────────────> Write to accounts.db
│ └─ prv_key_ids │                            (Borsh serialized)
└────────────────┘


USAGE PHASE (Transaction Signing):
═══════════════════════════════════

User Action           Wallet Core              Cryptography
───────────           ───────────              ────────────

Send Transaction
     │
     ├─> [Addresses needed]
     │         │
     │         ▼
     │    Load Account ────────────────> Read accounts.db
     │         │
     │         ▼
     │    Get PrvKeyData IDs
     │         │
     │         ▼
     │    Load PrvKeyData ──────────────> Read keydata.db
     │         │
     │         ▼
     │    Check: Encrypted?
     │         │
     ├─ If encrypted:
     │  Payment Secret
     │         │
     │         ▼
     │    Argon2+SHA256 derive key
     │         │
     │         ▼
     │    XChaCha20Poly1305 decrypt
     │         │
     │         ▼
     │    ┌──────────────────┐
     │    │ Decrypted Payload│
     │    │ (in memory only) │
     │    └─────┬────────────┘
     │          │
     │          ▼
     │    Extract XPrv/Mnemonic
     │          │
     │          ▼
     │    ┌──────────────────────┐
     │    │ Build derivation path│
     │    │ m/44'/111'/acct'/... │
     │    └─────┬────────────────┘
     │          │
     │          ▼
     │    ┌──────────────────────┐       ┌────────────────┐
     │    │ Derive child keys    │──────>│ BIP32 HMAC-SHA │
     │    │ For each address     │       │ secp256k1 math │
     │    └─────┬────────────────┘       └────────────────┘
     │          │
     │          ▼
     │    ┌─────────────────────────┐
     │    │ secp256k1::SecretKey    │
     │    │ (one per input address) │
     │    └─────┬───────────────────┘
     │          │
     │          ▼
     │    ┌─────────────────────────┐
     │    │ Sign transaction inputs │─────> ECDSA/Schnorr
     │    │ (per-input signature)   │       signature
     │    └─────┬───────────────────┘
     │          │
     │          ▼
     │    ┌─────────────────────────┐
     │    │ Zeroize private keys    │
     │    │ (overwrite memory)      │
     │    └─────┬───────────────────┘
     │          │
     │          ▼
     │    Return signed transaction
     │
     ▼
Broadcast to network
```

---

## 10. RECOMMENDATIONS & MITIGATION STRATEGIES

### Immediate Actions (High Priority):

1. **Enforce Encryption by Default**
   - Remove `Encryptable::Plain` option for new wallets
   - Migrate existing plaintext wallets with user warning
   - Require minimum password strength (entropy check)

2. **Upgrade Key ID Hashing**
   - Replace xxHash3 with BLAKE3 or truncated SHA256
   - Maintain backward compatibility with migration path

3. **Add Security Warnings**
   - Prominently warn users about plaintext storage risks
   - Display encryption status in wallet UI
   - Require explicit opt-out for unencrypted storage

### Medium-Term Improvements:

4. **Deprecate Legacy Derivation**
   - Create migration tool for Gen0 → Gen1 accounts
   - Warn users of legacy accounts
   - Sunset support timeline

5. **Enhanced Password Policy**
   - Implement zxcvbn or similar strength estimator
   - Require minimum entropy (e.g., 60 bits)
   - Provide feedback during password creation

6. **Hardware Security Module (HSM) Support**
   - Add optional integration for hardware keys
   - Support for signing without exposing private keys

### Long-Term Considerations:

7. **Multi-Factor Key Encryption**
   - Support for Shamir's Secret Sharing
   - Multi-device key recovery schemes

8. **Audit Trail**
   - Log key access (encrypted, audit-only)
   - Detect unusual signing patterns

9. **Memory Encryption**
   - Consider encrypted memory pages for key storage
   - Platform-specific secure enclaves (SGX, SEV)

---

## 11. COMPLIANCE & STANDARDS CHECKLIST

```
STANDARD                  COMPLIANCE    NOTES
─────────────────────────────────────────────────────────────
BIP32 (HD Wallets)        ✅ FULL       Standard implementation
BIP39 (Mnemonic)          ✅ FULL       English wordlist only
BIP44 (Multi-Account)     ✅ FULL       Coin type: 111 (Kaspa)
BIP45 (Multisig)          ✅ FULL       For multisig accounts

NIST SP 800-132 (PBKDF)   ✅ MEETS      PBKDF2 with 2048 iters
NIST SP 800-63B (Creds)   ⚠️ PARTIAL   No enforced password strength

FIPS 180-4 (SHA)          ✅ COMPLIANT  SHA-256, SHA-512
FIPS 198-1 (HMAC)         ✅ COMPLIANT  HMAC-SHA256/512

RFC 7539 (ChaCha20)       ✅ COMPLIANT  XChaCha20-Poly1305 AEAD
RFC 9106 (Argon2)         ✅ COMPLIANT  Argon2id variant

OWASP MASVS               ⚠️ PARTIAL   Missing: key attestation,
(Mobile App Security)                   biometric protection

CWE-311 (Plaintext)       ⚠️ VIOLATION Optional plaintext storage
CWE-798 (Hardcoded Keys)  ✅ SAFE      No hardcoded secrets
CWE-327 (Weak Crypto)     ✅ SAFE      Modern algorithms only
```

---

## CONCLUSION

The Kaspa wallet implements a **sophisticated and largely secure** key management system with modern cryptographic primitives. The BIP32/39/44 compliance ensures interoperability, and the use of XChaCha20-Poly1305 + Argon2 provides strong encryption.

**However**, the critical security dependency on user-provided passwords and the **optional plaintext storage** represent significant risks. Immediate remediation is recommended to enforce encryption by default and implement password strength requirements.

The codebase demonstrates good cryptographic hygiene with proper memory zeroization, constant-time operations, and use of OS-level random number generation. The dual derivation scheme (legacy vs. standard) adds complexity but maintains backward compatibility.

**Overall Security Rating: B+ (Good, with critical caveats)**

**Key Strengths:**
- Modern AEAD encryption
- Memory-hard KDF
- Standard BIP compliance
- Proper zeroization

**Key Weaknesses:**
- Optional plaintext storage
- No enforced password strength
- Non-cryptographic key IDs
- Dual derivation complexity

---

**Audit Completed:** 2026-01-23
**Audited By:** Security Analysis (Claude Code)
**Codebase Version:** rusty-kaspa/devel branch (commit: af131b01)
