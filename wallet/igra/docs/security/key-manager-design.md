# KeyManager / SecretStore Design (Igra)

This document proposes a **minimal, extensible key-management abstraction** for Igra.
We start by implementing **secret retrieval** (a `SecretStore`) and then migrate the codebase to depend on a single facade: `KeyManager`.
`KeyManager` lets us swap implementations (local, KMS, HSM) without touching application/domain logic.

## Goals

- Centralize **how secrets are loaded** (dev env vars, local encrypted file, future KMS/HSM).
- Make secret access:
  - explicit in code (easy to review),
  - safe by default (avoid accidental logging),
  - compatible with Igra’s current crypto choices (allow **XChaCha20-Poly1305**).
- Keep **domain** independent of secret storage, KMS clients, OS keyrings, file paths.

## Non-goals (for this phase)

- Perfect “keys never in process memory” for every scheme (Kaspa Schnorr may remain local unless the backend supports Schnorr).
- Multi-tenant policy enforcement and RBAC inside Igra (belongs to KMS).
- Perfect secrecy in process memory (we reduce exposure, but signing still needs plaintext key material in memory unless the signing operation is remote/HSM).

## Layering

- **Domain**: defines signing protocols, message verification, invariants; contains *no* KMS/HSM logic.
- **Infrastructure (igra-core)**: implements `SecretStore` + `KeyManager` backends (env/file/KMS/HSM).
- **Application / Service**: wires a concrete `KeyManager` into startup and uses it for all secret/key/sign operations.

## Core types (infrastructure)

### `SecretName`

A stable identifier for a secret.

- Use string newtype to avoid mixing secret names with arbitrary strings.
- Names should be stable across deployments so they can map to:
  - env var names (dev),
  - file keys (local),
  - KMS object identifiers (prod).

Proposed examples:

- `igra.hd.wallet_secret` (the decryption secret for encrypted mnemonics)
- `igra.iroh.signer_seed`
- `igra.hyperlane.validator_key.<name>` (if we ever store validator signing keys in Igra)

### `SecretBytes`

Wrapper around secret bytes to avoid accidental logging.

- Backed by `secrecy::SecretVec<u8>` (no accidental `Debug`/`Display` leakage).
- Access is explicit via `ExposeSecret` (reviewable).
- Intermediate buffers should be `zeroize`d where possible.

## Traits

### `SecretStore`

First deliverable: the `SecretStore` trait (used by `KeyManager` implementations).

Requirements:
- Must support both local (sync) and future remote (async) sources.
- Must not require `async_trait` in domain; this trait lives in infrastructure so either approach is acceptable.

Proposed shape (no `async_trait` dependency):

```rust
pub trait SecretStore: Send + Sync {
    fn get<'a>(
        &'a self,
        name: &'a SecretName,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<SecretBytes, ThresholdError>> + Send + 'a>>;
}
```

Notes:
- Returning a boxed `Future` keeps the API async-capable without `async_trait`.
- Local stores can still implement this with `Box::pin(async move { ... })`.
- Call sites can `await` the secret, which fits service startup and KMS use-cases.

### `KeyManager`

`KeyManager` is the API that the *rest of Igra* will depend on.

It composes:
- a `SecretStore` (for secrets that must be exported to sign locally), and/or
- a remote signing backend (KMS/HSM) for schemes that backend can sign.

#### Key references: `KeyRef`

All call sites refer to keys by stable IDs, not by “where the key is stored”.

Examples:
- `KeyRef { namespace: "kaspa", key_id: "wallet_signer_0" }`
- `KeyRef { namespace: "iroh", key_id: "identity" }`
- `KeyRef { namespace: "hyperlane", key_id: "validator_1" }`

These IDs map to:
- env vars in dev (`IGRA_SECRET__...`),
- entries in an encrypted secrets file,
- KMS object IDs,
- PKCS#11 labels, etc.

#### Schemes we need (current Igra)

- `Secp256k1Schnorr` (Kaspa transaction signing)
- `Secp256k1Ecdsa` (Hyperlane checkpoint signatures in tools / potential future signing)
- `Ed25519` (iroh identity)

#### Proposed API (async-capable, no `async_trait`)

```rust
pub enum SignatureScheme {
    Secp256k1Schnorr,
    Secp256k1Ecdsa,
    Ed25519,
}

pub enum SigningPayload<'a> {
    Message(&'a [u8]),
    Digest(&'a [u8]),
}

pub struct KeyRef {
    pub namespace: &'static str,
    pub key_id: String,
}

pub struct KeyManagerCapabilities {
    pub supports_secp256k1_ecdsa: bool,
    pub supports_secp256k1_schnorr: bool,
    pub supports_ed25519: bool,
    pub supports_secret_export: bool,
}

pub trait KeyManager: Send + Sync {
    fn capabilities(&self) -> KeyManagerCapabilities;

    fn secret_store(&self) -> Option<&dyn SecretStore>;

    fn public_key<'a>(
        &'a self,
        key: &'a KeyRef,
        scheme: SignatureScheme,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, ThresholdError>> + Send + 'a>>;

    fn sign<'a>(
        &'a self,
        key: &'a KeyRef,
        scheme: SignatureScheme,
        payload: SigningPayload<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, ThresholdError>> + Send + 'a>>;
}
```

Notes:
- Returning raw `Vec<u8>` keeps the trait independent of specific crypto structs. Callers can parse into `secp256k1`/`iroh` types as needed.
- `secret_store()` is optional because “pure HSM” deployments may not export secrets at all.
- Unsupported operations must return structured errors (see Error Handling section).

#### Implementation strategy: local first, KMS/HSM later

We implement:
- `LocalKeyManager`: signs using in-process crypto libs; reads secret material via `SecretStore`.

Later add:
- `CosmianKmsKeyManager`: remote sign for ECDSA/EdDSA; Schnorr likely returns Unsupported (Cosmian repo scan found no Schnorr/BIP340).
- `Pkcs11KeyManager`: HSM-backed sign operations where available.

## Backends (implementation plan)

### 1) `EnvSecretStore` (devnet/tests only)

- Reads from environment variables.
- Supports explicit encodings:
  - `hex:<...>` → hex-decoded bytes
  - `b64:<...>` → base64-decoded bytes
  - otherwise treat as UTF-8 bytes
- Logs only `secret_name` and error context; never logs values.

Rationale:
- Quick iteration and CI-friendly.
- Not acceptable for production unless the runtime environment is a hardened secret injector.

### 2) `FileSecretStore` (local encrypted file)

Stores a map of secrets in a single encrypted file in `data_dir` (example: `data_dir/secrets.bin`).

Two supported file formats are under consideration:

#### Option A: Custom file format (Argon2id + XChaCha20-Poly1305)

- **KDF**: `argon2` crate (Argon2id) derives a 32-byte key from a passphrase and random salt.
- **AEAD**: `chacha20poly1305` crate using `XChaCha20Poly1305` encrypts/authenticates the secret map.

This yields a self-contained file format:
- header: magic/version + argon2 params + salt + nonce
- body: ciphertext of serialized secret map

Pros:
- Explicitly uses **XChaCha20-Poly1305** (our current preference).
- Straightforward to implement and reason about.
- No external tooling dependency.

Cons:
- We own the file format and must maintain backwards compatibility.

#### Option B: `age` encrypted file

`age` is a widely-used encrypted file format with established tooling and libraries.

Pros:
- Standard format with existing tooling (`age` CLI).
- Supports both:
  - passphrase encryption, and/or
  - recipient-based encryption (e.g., X25519 recipients)

Cons:
- It chooses its own internals (KDF/cipher suite) and we treat it as a black box.
- Less control over “we require XChaCha20-Poly1305 specifically”.
- Still encrypts the whole blob; random access is not a goal anyway.

**Practical summary of Argon2 vs age**

- **Argon2**: a **KDF** (turn passphrase → strong key). Not a file format by itself.
- **age**: a complete **file encryption format** (packaging + recipients + encryption scheme). You don’t pick Argon2 directly; you pick “age passphrase” or “age recipients”.

For Igra’s needs (a small, local “secrets vault” file), both are viable. If we want maximum control and a minimal dependency surface, use **Option A**. If we want maximum operational friendliness and interoperability, use **Option B**.

### 3) Future `CosmianKmsSecretStore` (KMS)

Implementation would map `SecretName` → KMS object id.

Important constraints from Cosmian KMS code (local scan):
- It supports **ECDSA (including secp256k1 in non-fips builds)** and **EdDSA** for sign/verify.
- No Schnorr/BIP340 signing was found.

So in Igra:
- KMS can be used immediately as a **secret store / envelope encryption** backend.
- Remote signing for Kaspa Schnorr is likely not possible without a Schnorr-capable HSM/KMS.

## Where code lives (exact folders)

All of this should live in `igra-core` (infrastructure layer), so `igra-service` and any future binaries (observer/tools) can reuse it:

- `igra-core/src/infrastructure/keys/`
  - `mod.rs`
  - `types.rs`
  - `secret_store.rs`
  - `key_manager.rs`
  - `backends/`
    - `env_secret_store.rs`
    - `file_secret_store.rs`
    - `local_key_manager.rs`
    - `cosmian_kms_key_manager.rs` (future)
    - `pkcs11_key_manager.rs` (future)

`igra-service` constructs the chosen `KeyManager` implementation at startup and passes it into runtime contexts.

## External dependencies (proposed)

We already use `zeroize` (keep it).

Add:
- `secrecy` — wraps secrets to prevent accidental logging and makes access explicit.
- `argon2` — passphrase KDF for local encrypted secrets file (Option A).
- `chacha20poly1305` — AEAD encryption; use `XChaCha20Poly1305` (Option A).
- `rand_core` (or `rand`) — secure salt/nonce generation.
- `serde` + `bincode` (or `serde_json`) — serialize the secret map before encryption.
- Optional alternative: `age` — if we choose Option B file format.

## Error handling & logging (CODE-GUIDELINE alignment)

- Add structured error variants (examples):
  - `SecretNotFound { name }`
  - `SecretDecodeFailed { name, encoding, details }`
  - `SecretStoreUnavailable { backend, details }`
  - `SecretDecryptFailed { backend, details }`
  - `UnsupportedSignatureScheme { scheme, backend }`
  - `KeyNotFound { key_ref }`
  - `KeyManagerOperationFailed { operation, details }`
- Logs must include:
  - `secret_name`
  - backend identifier (`env`, `file`, `cosmian_kms`)
  - correlation/request id where available
- Never log secret bytes; never `Debug` print secrets.

## Next steps (implementation order)

### A) Build the abstraction

1. Add `igra-core/src/infrastructure/keys/` with:
   - `SecretName`, `SecretBytes`
   - `SecretStore` trait
   - `KeyManager` trait + types (`KeyRef`, `SignatureScheme`, `KeyManagerCapabilities`)
2. Add structured error variants in `igra-core/src/foundation/error.rs`.
3. Implement `EnvSecretStore` + `LocalKeyManager` (devnet/tests).

### B) Wire it into runtime contexts

4. Add `key_manager: Arc<dyn KeyManager>` to:
   - `igra-core::application::EventContext`
   - `igra-service::service::ServiceFlow` (or a shared runtime context)
5. Construct one `KeyManager` at startup (`kaspa-threshold-service`) and pass it into all contexts.

### C) Migrate call sites (convert entire codebase)

6. Inventory and replace direct secret reads:
   - `std::env::var(...)` for wallet secrets / seeds
   - config fields that embed raw secrets (e.g., seed hex)
   - ad-hoc decrypt logic
7. Port these subsystems to KeyManager, one-by-one:
   - iroh identity seed handling
   - HD mnemonic decryption secret handling (wallet secret)
   - PSKT signing (Schnorr signing path)
   - any tool/binary signing paths (Hyperlane ECDSA signing in fake bins, if desired)

#### Concrete conversion checklist (current codebase)

These are the places we would change first to route secrets through `KeyManager`:

- HD wallet secret (mnemonic decrypt/encrypt)
  - Current: `igra-core/src/infrastructure/config/encryption.rs` reads `KASPA_IGRA_WALLET_SECRET` via `load_wallet_secret()`.
  - Target: `KeyManager` becomes the only component allowed to fetch the wallet secret.
    - Refactor direction:
      - move `PsktHdConfig::decrypt_mnemonics()` logic into a `LocalKeyManager` method (so it can call `SecretStore`),
      - or change `decrypt_mnemonics()` to accept `wallet_secret: &Secret` and make callers obtain it from `KeyManager`.

- PSKT signing
  - Current: `igra-core/src/application/pskt_signing.rs` signs using `ServiceConfig` + HD config decrypt.
  - Target: `sign_pskt_with_*` takes `&dyn KeyManager` (or a narrower trait) and never touches env/config secrets directly.

- iroh identity seed
  - Current: `igra-core/src/infrastructure/config/types.rs` supports `iroh.signer_seed_hex`, and `igra-service/src/bin/kaspa-threshold-service/setup.rs` derives the signer secret.
  - Target: `KeyManager` provides the Ed25519 seed (local) or performs Ed25519 signing (remote) depending on backend.

- “Fake” binaries (dev tooling)
  - Current: `igra-service/src/bin/fake_hyperlane_ism_api.rs` reads validator private keys from JSON (`hyperlane-keys.json`).
  - Target (optional): leave as-is for devnet, or route through `KeyManager` to test KMS/HSM-backed ECDSA signing paths.

#### What does “converted to KeyManager” mean

After migration, the rule is:
- Any code that needs a secret (wallet secret, seed, private key) must get it from `KeyManager` (or `KeyManager.secret_store()`).
- `std::env::var(...)` and “read secret from config” become dev-only, isolated to the `EnvSecretStore` implementation and startup wiring.

### D) Add “real storage” for production

8. Decide on file format:
   - Option A (Argon2id + XChaCha20-Poly1305) or
   - Option B (`age`)
9. Implement `FileSecretStore`.

### E) Future extensions

10. Add `CosmianKmsKeyManager` (remote sign for ECDSA/EdDSA; local fallback for Schnorr).
11. Add `Pkcs11KeyManager` (HSM).
