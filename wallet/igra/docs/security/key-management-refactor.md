# KeyManagement Refactor - Implementation Guide

**Status**: Phase 1 - Local Implementation Only
**Target**: Centralized, auditable, extensible key management for Igra
**Timeline**: ~4 weeks for complete implementation

---

## Table of Contents

1. [Overview](#overview)
2. [What We're NOT Doing (Yet)](#what-were-not-doing-yet)
3. [Architecture Overview](#architecture-overview)
4. [Directory Structure](#directory-structure)
5. [Implementation Steps](#implementation-steps)
6. [File-by-File Implementation](#file-by-file-implementation)
7. [Migration Guide](#migration-guide)
8. [Testing Strategy](#testing-strategy)
9. [Devnet Scripts Update](#devnet-scripts-update)
10. [Validation Checklist](#validation-checklist)

---

## Overview

### Goals

This refactor centralizes all secret and key management in Igra to:

1. **Single Source of Truth**: All secrets accessed through `KeyManager` trait
2. **Audit-Ready**: Every secret access and signing operation is logged
3. **Extensible**: Easy path to add KMS/HSM support later (Phase 2+)
4. **Safe by Default**: No accidental logging of secrets, explicit access patterns
5. **Development-Friendly**: Works seamlessly with devnet and testing

### Current Problems We're Solving

Based on codebase analysis:

- ✅ Wallet secret loaded from env var directly (`KASPA_IGRA_WALLET_SECRET`)
- ✅ Payment secret stored as plaintext in config (`hd.passphrase`)
- ✅ Iroh signer seed in config as hex string
- ✅ No centralized audit trail for key operations
- ✅ Secret access scattered across codebase
- ✅ No memory protection for sensitive data
- ✅ No key rotation capability

### What This Refactor Delivers

After completion:

- ✅ All secrets accessed through `KeyManager` interface
- ✅ Two storage backends: `EnvSecretStore` (devnet) and `FileSecretStore` (local encrypted)
- ✅ Comprehensive audit logging for all key operations
- ✅ Memory protection with zeroization and optional mlock
- ✅ Clean separation: domain knows nothing about storage/KMS
- ✅ Devnet scripts work unchanged (via `EnvSecretStore`)
- ✅ Production-ready local file encryption (Argon2id + XChaCha20-Poly1305)

---

## What We're NOT Doing (Yet)

**⚠️ IMPORTANT: Phase 1 = Local Implementation Only**

We are **explicitly NOT implementing** in this phase:

- ❌ Cosmian KMS integration
- ❌ AWS KMS integration
- ❌ Azure Key Vault integration
- ❌ Google Cloud KMS integration
- ❌ PKCS#11 / Hardware Security Module (HSM) support
- ❌ Remote signing services
- ❌ Multi-tenant key isolation
- ❌ Key server / distributed key management

These will come in **Phase 2+** after we validate the architecture with local implementations.

**What we ARE implementing**:

- ✅ `SecretStore` trait (abstraction for future KMS)
- ✅ `KeyManager` trait (abstraction for future HSM/remote signing)
- ✅ `EnvSecretStore` (environment variables - devnet/CI)
- ✅ `FileSecretStore` (encrypted file - local development/testing)
- ✅ `LocalKeyManager` (in-process signing - all three schemes)
- ✅ Audit logging infrastructure
- ✅ Memory protection utilities

---

## Architecture Overview

### Layered Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                         │
│  (igra-service: ServiceFlow, API handlers, business logic)  │
└─────────────────────────────────────────────────────────────┘
                           ↓ uses
┌─────────────────────────────────────────────────────────────┐
│                      DOMAIN LAYER                            │
│     (igra-core/domain: PSKT signing, validation logic)      │
└─────────────────────────────────────────────────────────────┘
                           ↓ uses
┌─────────────────────────────────────────────────────────────┐
│               KEY MANAGEMENT FACADE                          │
│            KeyManagerContext (with audit)                    │
│              ↓                                               │
│         KeyManager trait                                     │
│    (sign, public_key, capabilities)                         │
└─────────────────────────────────────────────────────────────┘
                           ↓ uses
┌─────────────────────────────────────────────────────────────┐
│                  INFRASTRUCTURE LAYER                        │
│                (igra-core/infrastructure)                    │
│                                                              │
│  ┌──────────────────┐         ┌─────────────────────┐      │
│  │ LocalKeyManager  │────────→│  SecretStore trait  │      │
│  │  (in-process)    │         │                     │      │
│  │  - Schnorr       │         │  ┌──────────────┐   │      │
│  │  - ECDSA         │         │  │EnvSecretStore│   │      │
│  │  - Ed25519       │         │  └──────────────┘   │      │
│  └──────────────────┘         │  ┌──────────────┐   │      │
│                                │  │FileSecretStore  │      │
│                                │  └──────────────┘   │      │
│                                └─────────────────────┘      │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │           Audit Logger (append-only)                  │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

**1. Trait-Based Abstraction**

- `SecretStore`: Retrieve raw secret bytes (async-capable)
- `KeyManager`: High-level signing and public key operations
- `KeyAuditLogger`: Log all security-relevant events

**2. KeyRef: Stable Key Identifiers**

All keys referenced by stable IDs, not storage locations:

```rust
KeyRef {
    namespace: "igra.hd",
    key_id: "wallet_secret",
    version: None,  // Phase 1: no versioning yet
}
```

**3. No async_trait Dependency**

We return `Pin<Box<dyn Future>>` directly to avoid `async_trait` in domain layer.

**4. Explicit Secret Access**

All secret access requires `.expose_secret()` call - easily auditable in code review.

**5. Memory Protection**

- `zeroize` crate for automatic cleanup
- Optional `mlock` on Unix for core dump protection
- Panic guards to ensure cleanup even on unwind

---

## Directory Structure

```
igra-core/src/infrastructure/keys/
├── mod.rs                           # Public API exports
├── types.rs                         # Core types (KeyRef, SecretName, etc.)
├── secret_store.rs                  # SecretStore trait + SecretBytes
├── key_manager.rs                   # KeyManager trait + capabilities
├── context.rs                       # KeyManagerContext (with audit)
├── audit.rs                         # Audit logging types + trait
├── protected_memory.rs              # ProtectedSecret with mlock
├── panic_guard.rs                   # Panic-safe secret cleanup
├── error.rs                         # Key management errors
├── backends/
│   ├── mod.rs
│   ├── env_secret_store.rs         # Environment variable backend
│   ├── file_secret_store.rs        # Encrypted file backend
│   ├── file_format.rs              # File encryption format
│   └── local_key_manager.rs        # Local signing implementation
└── tests/
    ├── mod.rs
    ├── env_store_tests.rs
    ├── file_store_tests.rs
    ├── key_manager_tests.rs
    └── audit_tests.rs

igra-core/src/foundation/
├── error.rs                         # UPDATE: Add key management errors

igra-service/src/bin/kaspa-threshold-service/
├── setup.rs                         # UPDATE: Wire KeyManager at startup
└── modes/
    ├── audit.rs                     # UPDATE: Use KeyManager
    └── finalize.rs                  # UPDATE: Use KeyManager

igra-service/src/service/
├── flow.rs                          # UPDATE: Add KeyManager to ServiceFlow

igra-core/src/application/
├── pskt_signing.rs                  # UPDATE: Sign via KeyManager
└── context.rs                       # UPDATE: Add KeyManager to EventContext

igra-core/src/infrastructure/config/
├── encryption.rs                    # UPDATE: Remove direct secret loading
├── loader.rs                        # UPDATE: Remove secret env var reads
└── types.rs                         # UPDATE: Remove plaintext passphrase

igra-core/src/bin/
├── devnet-keygen.rs                 # UPDATE: Generate secrets for FileSecretStore
└── secrets-admin.rs                 # NEW: Secrets file management tool
```

---

## Implementation Steps

### Phase 1A: Foundation (Week 1)

**Goal**: Build core abstractions and types

1. Create directory structure
2. Implement core types (`SecretName`, `SecretBytes`, `KeyRef`)
3. Implement `SecretStore` trait
4. Implement `KeyManager` trait
5. Implement error types
6. Implement audit logging types

**Deliverable**: Compiles, but no implementations yet

### Phase 1B: Storage Backends (Week 1-2)

**Goal**: Implement secret storage

7. Implement `ProtectedSecret` with memory protection
8. Implement `EnvSecretStore` (simple, for devnet)
9. Implement `FileSecretStore` with Argon2id + XChaCha20-Poly1305
10. Implement file format serialization
11. Write tests for both stores

**Deliverable**: Secret storage works, tested

### Phase 1C: Key Manager Implementation (Week 2)

**Goal**: Implement signing operations

12. Implement `LocalKeyManager` structure
13. Implement Schnorr signing (Kaspa transactions)
14. Implement ECDSA signing (Hyperlane compatibility)
15. Implement Ed25519 signing (Iroh identity)
16. Implement audit logging integration
17. Write comprehensive tests

**Deliverable**: Full signing capability with audit

### Phase 1D: Integration (Week 3)

**Goal**: Wire into existing codebase

18. Update `foundation/error.rs` with key management errors
19. Add `KeyManager` to `EventContext`
20. Add `KeyManager` to `ServiceFlow`
21. Update `kaspa-threshold-service/setup.rs` to construct KeyManager
22. Create KeyManager initialization logic
23. Update config types to remove plaintext secrets

**Deliverable**: Infrastructure in place, old code still works

### Phase 1E: Migration (Week 3-4)

**Goal**: Convert all secret access to KeyManager

24. Migrate HD wallet secret loading
25. Migrate payment secret (remove from config)
26. Migrate PSKT signing operations
27. Migrate Iroh signer seed
28. Update devnet-keygen script
29. Create secrets-admin tool

**Deliverable**: Zero direct secret access remaining

### Phase 1F: Validation & Documentation (Week 4)

**Goal**: Production-ready

30. Integration testing (end-to-end signing flows)
31. Security review (memory dumps, logs, panic safety)
32. Performance benchmarking
33. Documentation (operator runbook, API docs)
34. Team training materials

**Deliverable**: Ready for deployment

---

## File-by-File Implementation

### Step 1: Create Core Types

#### File: `igra-core/src/infrastructure/keys/types.rs`

```rust
//! Core types for key management system

use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable identifier for a secret
///
/// Examples:
/// - `igra.hd.wallet_secret` - HD wallet encryption key
/// - `igra.hd.payment_secret` - BIP39 passphrase
/// - `igra.iroh.signer_seed` - Iroh network identity
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretName(String);

impl SecretName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for SecretName {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for SecretName {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Stable identifier for a cryptographic key
///
/// Keys are referenced by namespace + key_id, independent of storage location.
/// This allows the same code to work with env vars, files, KMS, or HSM.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyRef {
    /// Namespace for grouping related keys (e.g., "igra.hd", "igra.iroh")
    pub namespace: &'static str,

    /// Unique identifier within the namespace
    pub key_id: String,

    /// Optional version for key rotation (Phase 2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
}

impl KeyRef {
    pub fn new(namespace: &'static str, key_id: impl Into<String>) -> Self {
        Self {
            namespace,
            key_id: key_id.into(),
            version: None,
        }
    }

    /// Create versioned key reference (for future key rotation)
    pub fn with_version(mut self, version: u32) -> Self {
        self.version = Some(version);
        self
    }

    /// Get fully qualified name for logging/mapping
    pub fn qualified_name(&self) -> String {
        match self.version {
            None => format!("{}.{}", self.namespace, self.key_id),
            Some(v) => format!("{}.{}.v{}", self.namespace, self.key_id, v),
        }
    }
}

impl fmt::Display for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.qualified_name())
    }
}

/// Signature scheme supported by KeyManager
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureScheme {
    /// Schnorr signatures on secp256k1 (Kaspa transactions)
    Secp256k1Schnorr,

    /// ECDSA signatures on secp256k1 (Hyperlane, legacy compatibility)
    Secp256k1Ecdsa,

    /// EdDSA signatures on Ed25519 (Iroh identity)
    Ed25519,
}

impl fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secp256k1Schnorr => write!(f, "secp256k1-schnorr"),
            Self::Secp256k1Ecdsa => write!(f, "secp256k1-ecdsa"),
            Self::Ed25519 => write!(f, "ed25519"),
        }
    }
}

/// Payload to be signed
#[derive(Debug, Clone, Copy)]
pub enum SigningPayload<'a> {
    /// Raw message to be hashed and signed
    Message(&'a [u8]),

    /// Pre-computed digest/hash to be signed directly
    Digest(&'a [u8]),
}

impl<'a> SigningPayload<'a> {
    pub fn as_bytes(&self) -> &'a [u8] {
        match self {
            Self::Message(m) => m,
            Self::Digest(d) => d,
        }
    }
}

/// Capabilities of a KeyManager implementation
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyManagerCapabilities {
    /// Can sign Schnorr signatures (Kaspa)
    pub supports_secp256k1_schnorr: bool,

    /// Can sign ECDSA signatures (Hyperlane)
    pub supports_secp256k1_ecdsa: bool,

    /// Can sign Ed25519 signatures (Iroh)
    pub supports_ed25519: bool,

    /// Can export raw secret bytes (local only)
    pub supports_secret_export: bool,

    /// Supports key rotation
    pub supports_key_rotation: bool,
}

/// Request ID for correlating operations in audit logs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(u64);

impl RequestId {
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "req-{:016x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_name() {
        let name = SecretName::new("igra.hd.wallet_secret");
        assert_eq!(name.as_str(), "igra.hd.wallet_secret");
    }

    #[test]
    fn test_key_ref_qualified_name() {
        let key = KeyRef::new("igra.hd", "wallet_secret");
        assert_eq!(key.qualified_name(), "igra.hd.wallet_secret");

        let versioned = key.with_version(2);
        assert_eq!(versioned.qualified_name(), "igra.hd.wallet_secret.v2");
    }

    #[test]
    fn test_request_id_unique() {
        let id1 = RequestId::new();
        let id2 = RequestId::new();
        assert_ne!(id1, id2);
    }
}
```

---

#### File: `igra-core/src/infrastructure/keys/secret_store.rs`

```rust
//! SecretStore trait and SecretBytes wrapper

use crate::foundation::error::ThresholdError;
use secrecy::{ExposeSecret, SecretVec, Zeroize};
use std::future::Future;
use std::pin::Pin;

use super::types::SecretName;

/// Wrapper around secret bytes that prevents accidental logging
///
/// Uses `secrecy` crate to prevent Debug/Display from exposing secrets.
/// Access requires explicit `.expose_secret()` call.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretBytes {
    inner: SecretVec<u8>,
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: SecretVec::new(bytes),
        }
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }

    /// Expose secret bytes for use (explicit, auditable)
    pub fn expose_secret(&self) -> &[u8] {
        self.inner.expose_secret()
    }

    /// Convert to owned Vec (caller responsible for zeroizing)
    pub fn expose_owned(self) -> Vec<u8> {
        self.inner.expose_secret().to_vec()
    }

    pub fn len(&self) -> usize {
        self.inner.expose_secret().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([REDACTED {} bytes])", self.len())
    }
}

/// Trait for retrieving secrets from various backends
///
/// Implementations:
/// - `EnvSecretStore`: Read from environment variables (devnet/CI)
/// - `FileSecretStore`: Read from encrypted file (local development)
/// - Future: `CosmianKmsSecretStore`, `AwsKmsSecretStore`, etc.
///
/// All methods are async-capable (returns Future) to support remote backends.
pub trait SecretStore: Send + Sync {
    /// Retrieve a secret by name
    ///
    /// Returns `SecretNotFound` if secret doesn't exist.
    /// Returns `SecretDecodeFailed` if secret exists but can't be decoded.
    fn get<'a>(
        &'a self,
        name: &'a SecretName,
    ) -> Pin<Box<dyn Future<Output = Result<SecretBytes, ThresholdError>> + Send + 'a>>;

    /// Check if a secret exists (without retrieving it)
    fn exists<'a>(
        &'a self,
        name: &'a SecretName,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ThresholdError>> + Send + 'a>> {
        Box::pin(async move {
            match self.get(name).await {
                Ok(_) => Ok(true),
                Err(ThresholdError::SecretNotFound { .. }) => Ok(false),
                Err(e) => Err(e),
            }
        })
    }

    /// List all available secret names (for management tools)
    fn list_secrets<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SecretName>, ThresholdError>> + Send + 'a>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_bytes_no_leak() {
        let secret = SecretBytes::new(b"password123".to_vec());
        let debug_str = format!("{:?}", secret);

        // Should NOT contain actual secret
        assert!(!debug_str.contains("password"));
        assert!(debug_str.contains("REDACTED"));
    }

    #[test]
    fn test_secret_bytes_expose() {
        let secret = SecretBytes::new(b"test_secret".to_vec());
        assert_eq!(secret.expose_secret(), b"test_secret");
    }

    #[test]
    fn test_secret_bytes_zeroize() {
        let data = vec![0x42u8; 32];
        let secret = SecretBytes::new(data);
        drop(secret);
        // Zeroize is called on drop - actual verification requires unsafe code
    }
}
```

---

#### File: `igra-core/src/infrastructure/keys/error.rs`

```rust
//! Error types for key management operations

use crate::foundation::error::ThresholdError;
use crate::infrastructure::keys::types::{KeyRef, SecretName, SignatureScheme, RequestId};
use thiserror::Error;

/// Extend ThresholdError with key management variants
///
/// These should be added to `foundation/error.rs` ThresholdError enum:

/*
Add to foundation/error.rs:

    // === Key Management Errors ===

    #[error("Secret not found: {name} (backend: {backend})")]
    SecretNotFound {
        name: String,
        backend: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Secret decode failed: {name} (encoding: {encoding}, details: {details})")]
    SecretDecodeFailed {
        name: String,
        encoding: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Secret store unavailable: {backend} - {details}")]
    SecretStoreUnavailable {
        backend: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Secret decryption failed: {backend} - {details}")]
    SecretDecryptFailed {
        backend: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Unsupported signature scheme: {scheme} (backend: {backend})")]
    UnsupportedSignatureScheme {
        scheme: String,
        backend: String,
    },

    #[error("Key not found: {key_ref}")]
    KeyNotFound {
        key_ref: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Key operation failed: {operation} on {key_ref} - {details}")]
    KeyOperationFailed {
        operation: String,
        key_ref: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Invalid secret file permissions: {path} has mode {mode:o}, expected 0600")]
    InsecureFilePermissions {
        path: String,
        mode: u32,
    },

    #[error("Audit log error: {details}")]
    AuditLogError {
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
*/

// Helper functions for constructing these errors

impl ThresholdError {
    pub fn secret_not_found(name: impl Into<String>, backend: impl Into<String>) -> Self {
        Self::SecretNotFound {
            name: name.into(),
            backend: backend.into(),
            source: None,
        }
    }

    pub fn secret_decode_failed(
        name: impl Into<String>,
        encoding: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self::SecretDecodeFailed {
            name: name.into(),
            encoding: encoding.into(),
            details: details.into(),
            source: None,
        }
    }

    pub fn secret_store_unavailable(
        backend: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self::SecretStoreUnavailable {
            backend: backend.into(),
            details: details.into(),
            source: None,
        }
    }

    pub fn unsupported_signature_scheme(
        scheme: SignatureScheme,
        backend: impl Into<String>,
    ) -> Self {
        Self::UnsupportedSignatureScheme {
            scheme: scheme.to_string(),
            backend: backend.into(),
        }
    }

    pub fn key_not_found(key_ref: &KeyRef) -> Self {
        Self::KeyNotFound {
            key_ref: key_ref.to_string(),
            source: None,
        }
    }

    pub fn key_operation_failed(
        operation: impl Into<String>,
        key_ref: &KeyRef,
        details: impl Into<String>,
    ) -> Self {
        Self::KeyOperationFailed {
            operation: operation.into(),
            key_ref: key_ref.to_string(),
            details: details.into(),
            source: None,
        }
    }
}
```

---

#### File: `igra-core/src/infrastructure/keys/protected_memory.rs`

```rust
//! Memory-protected secret storage with optional mlock

use secrecy::{ExposeSecret, SecretVec, Zeroize};
use std::fmt;

use crate::foundation::error::ThresholdError;

/// Secret bytes with optional memory locking
///
/// On Unix systems, attempts to lock memory pages with mlock to prevent
/// secrets from being swapped to disk or included in core dumps.
///
/// Falls back gracefully if mlock fails (requires elevated privileges).
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct ProtectedSecret {
    inner: SecretVec<u8>,

    #[cfg(target_family = "unix")]
    #[zeroize(skip)]
    mlocked: bool,
}

impl ProtectedSecret {
    /// Create new protected secret with automatic memory locking attempt
    pub fn new(data: Vec<u8>) -> Result<Self, ThresholdError> {
        let inner = SecretVec::new(data);

        #[cfg(target_family = "unix")]
        let mlocked = Self::try_mlock(&inner);

        Ok(Self {
            inner,
            #[cfg(target_family = "unix")]
            mlocked,
        })
    }

    /// Expose secret for use (explicit, auditable)
    pub fn expose_secret(&self) -> &[u8] {
        self.inner.expose_secret()
    }

    /// Check if memory was successfully locked
    #[cfg(target_family = "unix")]
    pub fn is_mlocked(&self) -> bool {
        self.mlocked
    }

    #[cfg(not(target_family = "unix"))]
    pub fn is_mlocked(&self) -> bool {
        false
    }

    pub fn len(&self) -> usize {
        self.inner.expose_secret().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(target_family = "unix")]
    fn try_mlock(secret: &SecretVec<u8>) -> bool {
        use secrecy::ExposeSecret;
        let slice = secret.expose_secret();

        let result = unsafe {
            libc::mlock(
                slice.as_ptr() as *const libc::c_void,
                slice.len(),
            )
        };

        if result != 0 {
            // mlock failed - usually requires CAP_IPC_LOCK capability
            // Log warning but don't fail
            log::warn!("Failed to mlock secret memory (may require elevated privileges)");
            false
        } else {
            log::debug!("Successfully mlocked {} bytes", slice.len());
            true
        }
    }
}

impl Drop for ProtectedSecret {
    fn drop(&mut self) {
        #[cfg(target_family = "unix")]
        if self.mlocked {
            use secrecy::ExposeSecret;
            let slice = self.inner.expose_secret();
            unsafe {
                libc::munlock(
                    slice.as_ptr() as *const libc::c_void,
                    slice.len(),
                );
            }
        }

        // SecretVec's Drop will zeroize the memory
    }
}

impl fmt::Debug for ProtectedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedSecret")
            .field("len", &self.len())
            .field("mlocked", &self.is_mlocked())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protected_secret_creation() {
        let secret = ProtectedSecret::new(b"test_data".to_vec()).unwrap();
        assert_eq!(secret.expose_secret(), b"test_data");
    }

    #[test]
    fn test_protected_secret_no_leak() {
        let secret = ProtectedSecret::new(b"password123".to_vec()).unwrap();
        let debug_str = format!("{:?}", secret);

        // Should NOT contain actual secret
        assert!(!debug_str.contains("password"));
    }
}
```

---

#### File: `igra-core/src/infrastructure/keys/panic_guard.rs`

```rust
//! Panic-safe secret cleanup

use zeroize::Zeroize;

/// Guard that ensures secrets are zeroized even if a panic occurs
///
/// Usage:
/// ```ignore
/// let secret_data = load_secret()?;
/// let mut guard = SecretPanicGuard::new(secret_data);
///
/// // Even if this panics, Drop will zeroize
/// let result = risky_operation(guard.as_slice())?;
///
/// // Explicitly take ownership when done
/// let secret = guard.take();
/// ```
pub struct SecretPanicGuard<T: Zeroize> {
    secret: Option<T>,
}

impl<T: Zeroize> SecretPanicGuard<T> {
    pub fn new(secret: T) -> Self {
        Self {
            secret: Some(secret),
        }
    }

    /// Access secret without taking ownership
    pub fn get(&self) -> &T {
        self.secret.as_ref().expect("secret already taken")
    }

    /// Take ownership of secret (caller must handle cleanup)
    pub fn take(&mut self) -> T {
        self.secret.take().expect("secret already taken")
    }
}

impl<T: Zeroize> Drop for SecretPanicGuard<T> {
    fn drop(&mut self) {
        if let Some(mut secret) = self.secret.take() {
            secret.zeroize();
        }
    }
}

// Implement Zeroize for Vec<u8> and [u8; N] if not already done by zeroize crate
// (usually already implemented, but this ensures it)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_panic_guard_normal_drop() {
        let data = vec![0x42u8; 32];
        {
            let _guard = SecretPanicGuard::new(data);
            // Normal drop
        }
        // Data should be zeroized
    }

    #[test]
    fn test_panic_guard_take() {
        let data = vec![0x42u8; 32];
        let mut guard = SecretPanicGuard::new(data);

        let taken = guard.take();
        assert_eq!(taken.len(), 32);
    }

    #[test]
    #[should_panic(expected = "secret already taken")]
    fn test_panic_guard_double_take() {
        let data = vec![0x42u8; 32];
        let mut guard = SecretPanicGuard::new(data);

        let _first = guard.take();
        let _second = guard.take(); // Should panic
    }
}
```

---

### Step 2: Implement Audit Logging

#### File: `igra-core/src/infrastructure/keys/audit.rs`

```rust
//! Audit logging for key management operations

use crate::foundation::error::ThresholdError;
use crate::infrastructure::keys::types::{KeyRef, SecretName, SignatureScheme, RequestId};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Timestamp in nanoseconds since Unix epoch
pub type Timestamp = u64;

/// Get current timestamp
pub fn now_nanos() -> Timestamp {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_nanos() as u64
}

/// Result of an operation (success or failure)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result")]
pub enum OperationResult {
    Success,
    Failure { error: String },
}

impl OperationResult {
    pub fn from_result<T, E: std::fmt::Display>(result: &Result<T, E>) -> Self {
        match result {
            Ok(_) => Self::Success,
            Err(e) => Self::Failure {
                error: e.to_string(),
            },
        }
    }
}

/// Secret access operation type
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SecretOperation {
    Get,
    List,
    Exists,
}

/// Event logged when a secret is accessed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretAccessEvent {
    pub timestamp: Timestamp,
    pub request_id: RequestId,
    pub secret_name: String,
    pub backend: String,
    pub operation: SecretOperation,
    pub result: OperationResult,

    /// Caller context for audit trail
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_module: Option<String>,
}

/// Event logged when a signing operation occurs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningEvent {
    pub timestamp: Timestamp,
    pub request_id: RequestId,
    pub key_ref: String,
    pub scheme: SignatureScheme,

    /// Blake3 hash of payload (NOT the payload itself!)
    pub payload_hash: String,

    pub result: OperationResult,
    pub duration_micros: u64,
}

/// Event logged when a public key is retrieved
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyEvent {
    pub timestamp: Timestamp,
    pub request_id: RequestId,
    pub key_ref: String,
    pub scheme: SignatureScheme,
    pub result: OperationResult,
}

/// Lifecycle operation on a key
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum KeyLifecycleOperation {
    Created,
    Rotated,
    Revoked,
    Deleted,
}

/// Event logged for key lifecycle changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyLifecycleEvent {
    pub timestamp: Timestamp,
    pub key_ref: String,
    pub operation: KeyLifecycleOperation,
    pub operator: String,
}

/// Trait for logging key management audit events
///
/// Implementations should write to append-only storage for tamper-evidence.
pub trait KeyAuditLogger: Send + Sync {
    fn log_secret_access<'a>(
        &'a self,
        event: SecretAccessEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>>;

    fn log_signing_operation<'a>(
        &'a self,
        event: SigningEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>>;

    fn log_public_key_retrieval<'a>(
        &'a self,
        event: PublicKeyEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>>;

    fn log_key_lifecycle<'a>(
        &'a self,
        event: KeyLifecycleEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>>;
}

/// No-op audit logger for testing
pub struct NoopAuditLogger;

impl KeyAuditLogger for NoopAuditLogger {
    fn log_secret_access<'a>(
        &'a self,
        _event: SecretAccessEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn log_signing_operation<'a>(
        &'a self,
        _event: SigningEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn log_public_key_retrieval<'a>(
        &'a self,
        _event: PublicKeyEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn log_key_lifecycle<'a>(
        &'a self,
        _event: KeyLifecycleEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

/// File-based audit logger (append-only JSON lines)
pub struct FileAuditLogger {
    file: Arc<tokio::sync::Mutex<std::fs::File>>,
}

impl FileAuditLogger {
    pub fn new(path: impl AsRef<std::path::Path>) -> Result<Self, ThresholdError> {
        use std::fs::OpenOptions;

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .map_err(|e| ThresholdError::AuditLogError {
                details: format!("Failed to open audit log: {}", e),
                source: Some(Box::new(e)),
            })?;

        Ok(Self {
            file: Arc::new(tokio::sync::Mutex::new(file)),
        })
    }

    async fn write_event(&self, event: impl Serialize) -> Result<(), ThresholdError> {
        use std::io::Write;

        let json = serde_json::to_string(&event)
            .map_err(|e| ThresholdError::AuditLogError {
                details: format!("Failed to serialize audit event: {}", e),
                source: Some(Box::new(e)),
            })?;

        let mut file = self.file.lock().await;
        writeln!(file, "{}", json)
            .map_err(|e| ThresholdError::AuditLogError {
                details: format!("Failed to write audit event: {}", e),
                source: Some(Box::new(e)),
            })?;

        file.flush()
            .map_err(|e| ThresholdError::AuditLogError {
                details: format!("Failed to flush audit log: {}", e),
                source: Some(Box::new(e)),
            })?;

        Ok(())
    }
}

impl KeyAuditLogger for FileAuditLogger {
    fn log_secret_access<'a>(
        &'a self,
        event: SecretAccessEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(self.write_event(serde_json::json!({
            "event_type": "secret_access",
            "event": event,
        })))
    }

    fn log_signing_operation<'a>(
        &'a self,
        event: SigningEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(self.write_event(serde_json::json!({
            "event_type": "signing",
            "event": event,
        })))
    }

    fn log_public_key_retrieval<'a>(
        &'a self,
        event: PublicKeyEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(self.write_event(serde_json::json!({
            "event_type": "public_key",
            "event": event,
        })))
    }

    fn log_key_lifecycle<'a>(
        &'a self,
        event: KeyLifecycleEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(self.write_event(serde_json::json!({
            "event_type": "lifecycle",
            "event": event,
        })))
    }
}
```

---

This is getting very long. Let me continue in a structured way by creating the complete file with all remaining implementations. Should I:

1. Continue with the full detailed file content (will be very long, ~3000+ lines)
2. Create a comprehensive but slightly condensed version
3. Split into multiple documents

Which would you prefer?
### Step 3: Implement KeyManager Trait

#### File: `igra-core/src/infrastructure/keys/key_manager.rs`

```rust
//! KeyManager trait - high-level key operations

use crate::foundation::error::ThresholdError;
use crate::infrastructure::keys::{
    secret_store::SecretStore,
    types::{KeyRef, SignatureScheme, SigningPayload, KeyManagerCapabilities},
};
use std::future::Future;
use std::pin::Pin;

/// High-level key management interface
///
/// Provides signing and public key operations, abstracting over:
/// - Local in-process signing (Phase 1)
/// - Remote KMS signing (Phase 2+)
/// - HSM signing (Phase 2+)
///
/// All operations are async-capable to support remote backends.
pub trait KeyManager: Send + Sync {
    /// Get capabilities of this KeyManager implementation
    fn capabilities(&self) -> KeyManagerCapabilities;

    /// Get underlying SecretStore (if available)
    ///
    /// Returns None for "pure HSM" implementations that never export secrets.
    /// Local implementations should return Some.
    fn secret_store(&self) -> Option<&dyn SecretStore>;

    /// Get public key for a key reference
    ///
    /// Returns raw bytes (format depends on scheme):
    /// - Secp256k1Schnorr: 32-byte x-only pubkey
    /// - Secp256k1Ecdsa: 33-byte compressed pubkey
    /// - Ed25519: 32-byte pubkey
    fn public_key<'a>(
        &'a self,
        key: &'a KeyRef,
        scheme: SignatureScheme,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, ThresholdError>> + Send + 'a>>;

    /// Sign a payload with a key
    ///
    /// Returns raw signature bytes (format depends on scheme):
    /// - Secp256k1Schnorr: 64-byte signature
    /// - Secp256k1Ecdsa: 64-byte compact signature (r,s)
    /// - Ed25519: 64-byte signature
    fn sign<'a>(
        &'a self,
        key: &'a KeyRef,
        scheme: SignatureScheme,
        payload: SigningPayload<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, ThresholdError>> + Send + 'a>>;

    /// Verify that required keys exist (for startup validation)
    fn validate_required_keys<'a>(
        &'a self,
        keys: &'a [&'a KeyRef],
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(async move {
            for key in keys {
                // Try to get public key to verify key exists
                self.public_key(key, SignatureScheme::Secp256k1Schnorr)
                    .await
                    .map_err(|_| ThresholdError::key_not_found(key))?;
            }
            Ok(())
        })
    }
}
```

---

#### File: `igra-core/src/infrastructure/keys/context.rs`

```rust
//! KeyManagerContext - KeyManager with audit logging integration

use crate::foundation::error::ThresholdError;
use crate::infrastructure::keys::{
    audit::{
        KeyAuditLogger, OperationResult, PublicKeyEvent, SigningEvent,
        now_nanos,
    },
    key_manager::KeyManager,
    types::{KeyRef, RequestId, SignatureScheme, SigningPayload},
};
use std::sync::Arc;
use std::time::Instant;

/// KeyManager with automatic audit logging
///
/// This is the primary interface that application code should use.
/// It wraps a KeyManager and adds audit logging for all operations.
pub struct KeyManagerContext {
    key_manager: Arc<dyn KeyManager>,
    audit_log: Arc<dyn KeyAuditLogger>,
    request_id: RequestId,
}

impl KeyManagerContext {
    pub fn new(
        key_manager: Arc<dyn KeyManager>,
        audit_log: Arc<dyn KeyAuditLogger>,
        request_id: RequestId,
    ) -> Self {
        Self {
            key_manager,
            audit_log,
            request_id,
        }
    }

    /// Create context with new request ID
    pub fn with_new_request_id(
        key_manager: Arc<dyn KeyManager>,
        audit_log: Arc<dyn KeyAuditLogger>,
    ) -> Self {
        Self::new(key_manager, audit_log, RequestId::new())
    }

    /// Get request ID for this context
    pub fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Get underlying KeyManager
    pub fn key_manager(&self) -> &Arc<dyn KeyManager> {
        &self.key_manager
    }

    /// Sign with automatic audit logging
    pub async fn sign_with_audit(
        &self,
        key: &KeyRef,
        scheme: SignatureScheme,
        payload: SigningPayload<'_>,
    ) -> Result<Vec<u8>, ThresholdError> {
        let start = Instant::now();

        // Compute hash of payload for audit log (NOT the payload itself!)
        let payload_hash = {
            let hasher = blake3::Hasher::new();
            let mut hasher = hasher;
            hasher.update(payload.as_bytes());
            let hash = hasher.finalize();
            format!("{}", hash.to_hex())
        };

        let result = self.key_manager.sign(key, scheme, payload).await;
        let duration_micros = start.elapsed().as_micros() as u64;

        // Log signing event
        let event = SigningEvent {
            timestamp: now_nanos(),
            request_id: self.request_id,
            key_ref: key.to_string(),
            scheme,
            payload_hash,
            result: OperationResult::from_result(&result),
            duration_micros,
        };

        self.audit_log.log_signing_operation(event).await?;

        result
    }

    /// Get public key with automatic audit logging
    pub async fn public_key_with_audit(
        &self,
        key: &KeyRef,
        scheme: SignatureScheme,
    ) -> Result<Vec<u8>, ThresholdError> {
        let result = self.key_manager.public_key(key, scheme).await;

        // Log public key retrieval
        let event = PublicKeyEvent {
            timestamp: now_nanos(),
            request_id: self.request_id,
            key_ref: key.to_string(),
            scheme,
            result: OperationResult::from_result(&result),
        };

        self.audit_log.log_public_key_retrieval(event).await?;

        result
    }
}
```

---

### Step 4: Implement Storage Backends

#### File: `igra-core/src/infrastructure/keys/backends/env_secret_store.rs`

```rust
//! Environment variable based secret store (devnet/CI only)

use crate::foundation::error::ThresholdError;
use crate::infrastructure::keys::{
    secret_store::{SecretBytes, SecretStore},
    types::SecretName,
};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

/// SecretStore that reads from environment variables
///
/// **FOR DEVNET/CI ONLY - NOT FOR PRODUCTION**
///
/// Supports encoding prefixes:
/// - `hex:<data>` - hex-decode the data
/// - `b64:<data>` - base64-decode the data
/// - `<data>` - treat as UTF-8 bytes
///
/// Environment variable naming:
/// - `IGRA_SECRET__<namespace>__<key_id>` (double underscore separators)
/// - Example: `IGRA_SECRET__igra_hd__wallet_secret`
pub struct EnvSecretStore {
    /// Cached secrets (loaded once at startup)
    cache: HashMap<SecretName, SecretBytes>,
}

impl EnvSecretStore {
    pub fn new() -> Self {
        let mut cache = HashMap::new();

        // Load all IGRA_SECRET__* environment variables
        for (key, value) in std::env::vars() {
            if let Some(secret_name) = key.strip_prefix("IGRA_SECRET__") {
                // Convert env var name to SecretName
                // IGRA_SECRET__igra_hd__wallet_secret -> igra.hd.wallet_secret
                let secret_name = secret_name.replace("__", ".");
                let secret_name = SecretName::new(secret_name);

                match Self::decode_value(&value) {
                    Ok(bytes) => {
                        log::debug!("Loaded secret from env: {}", secret_name);
                        cache.insert(secret_name, bytes);
                    }
                    Err(e) => {
                        log::warn!("Failed to decode secret {}: {}", secret_name, e);
                    }
                }
            }
        }

        log::info!("EnvSecretStore loaded {} secrets", cache.len());

        Self { cache }
    }

    fn decode_value(value: &str) -> Result<SecretBytes, ThresholdError> {
        if let Some(hex_data) = value.strip_prefix("hex:") {
            // Hex decode
            let bytes = hex::decode(hex_data).map_err(|e| {
                ThresholdError::secret_decode_failed(
                    "env_var",
                    "hex",
                    format!("hex decode failed: {}", e),
                )
            })?;
            Ok(SecretBytes::new(bytes))
        } else if let Some(b64_data) = value.strip_prefix("b64:") {
            // Base64 decode
            use base64::{Engine, engine::general_purpose::STANDARD};
            let bytes = STANDARD.decode(b64_data).map_err(|e| {
                ThresholdError::secret_decode_failed(
                    "env_var",
                    "base64",
                    format!("base64 decode failed: {}", e),
                )
            })?;
            Ok(SecretBytes::new(bytes))
        } else {
            // UTF-8 bytes
            Ok(SecretBytes::new(value.as_bytes().to_vec()))
        }
    }
}

impl Default for EnvSecretStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStore for EnvSecretStore {
    fn get<'a>(
        &'a self,
        name: &'a SecretName,
    ) -> Pin<Box<dyn Future<Output = Result<SecretBytes, ThresholdError>> + Send + 'a>> {
        Box::pin(async move {
            self.cache
                .get(name)
                .cloned()
                .ok_or_else(|| ThresholdError::secret_not_found(name.as_str(), "env"))
        })
    }

    fn list_secrets<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SecretName>, ThresholdError>> + Send + 'a>> {
        Box::pin(async move {
            Ok(self.cache.keys().cloned().collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_decode_hex() {
        std::env::set_var("IGRA_SECRET__test__hex_key", "hex:deadbeef");
        let store = EnvSecretStore::new();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let secret = rt.block_on(store.get(&SecretName::new("test.hex_key"))).unwrap();

        assert_eq!(secret.expose_secret(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_decode_base64() {
        std::env::set_var("IGRA_SECRET__test__b64_key", "b64:aGVsbG8=");
        let store = EnvSecretStore::new();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let secret = rt.block_on(store.get(&SecretName::new("test.b64_key"))).unwrap();

        assert_eq!(secret.expose_secret(), b"hello");
    }

    #[test]
    fn test_decode_utf8() {
        std::env::set_var("IGRA_SECRET__test__utf8_key", "plain_secret");
        let store = EnvSecretStore::new();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let secret = rt.block_on(store.get(&SecretName::new("test.utf8_key"))).unwrap();

        assert_eq!(secret.expose_secret(), b"plain_secret");
    }
}
```

---

#### File: `igra-core/src/infrastructure/keys/backends/file_format.rs`

```rust
//! Encrypted secrets file format (Argon2id + XChaCha20-Poly1305)

use crate::foundation::error::ThresholdError;
use crate::infrastructure::keys::types::SecretName;
use argon2::{Argon2, ParamsBuilder, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAGIC: [u8; 4] = *b"ISEC"; // Igra SECrets
const VERSION: u8 = 1;

/// File header + encrypted payload
#[derive(Debug)]
pub struct SecretFile {
    pub version: u8,
    pub kdf_params: Argon2Params,
    pub salt: [u8; 32],
    pub nonce: [u8; 24],
    pub ciphertext_and_tag: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Params {
    pub m_cost: u32,      // Memory cost in KiB
    pub t_cost: u32,      // Time cost (iterations)
    pub p_cost: u32,      // Parallelism
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: 65536,    // 64 MiB
            t_cost: 3,        // 3 iterations
            p_cost: 4,        // 4 threads
        }
    }
}

/// Secret map (plaintext, gets encrypted)
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretMap {
    pub secrets: HashMap<SecretName, Vec<u8>>,
}

impl SecretFile {
    /// Create new encrypted file from secret map
    pub fn encrypt(
        secrets: &SecretMap,
        passphrase: &str,
        kdf_params: Argon2Params,
    ) -> Result<Self, ThresholdError> {
        // Generate random salt and nonce
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 24];

        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);

        // Derive encryption key from passphrase
        let key = Self::derive_key(passphrase, &salt, &kdf_params)?;

        // Serialize secret map
        let plaintext = bincode::serialize(&secrets).map_err(|e| {
            ThresholdError::secret_store_unavailable(
                "file",
                format!("Failed to serialize secrets: {}", e),
            )
        })?;

        // Encrypt with XChaCha20-Poly1305
        let cipher = XChaCha20Poly1305::new(&key.into());
        let ciphertext_and_tag = cipher
            .encrypt(&nonce.into(), plaintext.as_ref())
            .map_err(|e| {
                ThresholdError::SecretDecryptFailed {
                    backend: "file".to_string(),
                    details: format!("Encryption failed: {}", e),
                    source: None,
                }
            })?;

        Ok(Self {
            version: VERSION,
            kdf_params,
            salt,
            nonce,
            ciphertext_and_tag,
        })
    }

    /// Decrypt file and extract secret map
    pub fn decrypt(&self, passphrase: &str) -> Result<SecretMap, ThresholdError> {
        if self.version != VERSION {
            return Err(ThresholdError::secret_store_unavailable(
                "file",
                format!("Unsupported file version: {}", self.version),
            ));
        }

        // Derive encryption key from passphrase
        let key = Self::derive_key(passphrase, &self.salt, &self.kdf_params)?;

        // Decrypt with XChaCha20-Poly1305
        let cipher = XChaCha20Poly1305::new(&key.into());
        let plaintext = cipher
            .decrypt(&self.nonce.into(), self.ciphertext_and_tag.as_ref())
            .map_err(|e| {
                ThresholdError::SecretDecryptFailed {
                    backend: "file".to_string(),
                    details: format!("Decryption failed (wrong passphrase?): {}", e),
                    source: None,
                }
            })?;

        // Deserialize secret map
        let secrets: SecretMap = bincode::deserialize(&plaintext).map_err(|e| {
            ThresholdError::secret_store_unavailable(
                "file",
                format!("Failed to deserialize secrets: {}", e),
            )
        })?;

        Ok(secrets)
    }

    /// Serialize to bytes for writing to disk
    pub fn to_bytes(&self) -> Result<Vec<u8>, ThresholdError> {
        let mut buf = Vec::new();

        // Header
        buf.extend_from_slice(&MAGIC);
        buf.push(self.version);

        // KDF params (12 bytes: 3 x u32)
        buf.extend_from_slice(&self.kdf_params.m_cost.to_le_bytes());
        buf.extend_from_slice(&self.kdf_params.t_cost.to_le_bytes());
        buf.extend_from_slice(&self.kdf_params.p_cost.to_le_bytes());

        // Salt (32 bytes)
        buf.extend_from_slice(&self.salt);

        // Nonce (24 bytes)
        buf.extend_from_slice(&self.nonce);

        // Ciphertext + tag
        buf.extend_from_slice(&self.ciphertext_and_tag);

        Ok(buf)
    }

    /// Deserialize from bytes read from disk
    pub fn from_bytes(data: &[u8]) -> Result<Self, ThresholdError> {
        if data.len() < 73 {
            // 4 (magic) + 1 (version) + 12 (kdf) + 32 (salt) + 24 (nonce)
            return Err(ThresholdError::secret_store_unavailable(
                "file",
                "File too short to be valid secret file".to_string(),
            ));
        }

        // Verify magic
        if &data[0..4] != &MAGIC {
            return Err(ThresholdError::secret_store_unavailable(
                "file",
                "Invalid magic bytes (not an Igra secret file)".to_string(),
            ));
        }

        let version = data[4];
        if version != VERSION {
            return Err(ThresholdError::secret_store_unavailable(
                "file",
                format!("Unsupported file version: {}", version),
            ));
        }

        // Parse KDF params
        let m_cost = u32::from_le_bytes(data[5..9].try_into().unwrap());
        let t_cost = u32::from_le_bytes(data[9..13].try_into().unwrap());
        let p_cost = u32::from_le_bytes(data[13..17].try_into().unwrap());
        let kdf_params = Argon2Params { m_cost, t_cost, p_cost };

        // Parse salt and nonce
        let salt: [u8; 32] = data[17..49].try_into().unwrap();
        let nonce: [u8; 24] = data[49..73].try_into().unwrap();

        // Remaining bytes are ciphertext + tag
        let ciphertext_and_tag = data[73..].to_vec();

        Ok(Self {
            version,
            kdf_params,
            salt,
            nonce,
            ciphertext_and_tag,
        })
    }

    fn derive_key(
        passphrase: &str,
        salt: &[u8; 32],
        params: &Argon2Params,
    ) -> Result<[u8; 32], ThresholdError> {
        let mut key = [0u8; 32];

        let argon2_params = ParamsBuilder::new()
            .m_cost(params.m_cost)
            .t_cost(params.t_cost)
            .p_cost(params.p_cost)
            .build()
            .map_err(|e| {
                ThresholdError::secret_store_unavailable(
                    "file",
                    format!("Invalid Argon2 parameters: {}", e),
                )
            })?;

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            Version::V0x13,
            argon2_params,
        );

        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| {
                ThresholdError::secret_store_unavailable(
                    "file",
                    format!("Key derivation failed: {}", e),
                )
            })?;

        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut secrets = SecretMap {
            secrets: HashMap::new(),
        };
        secrets.secrets.insert(
            SecretName::new("test.key1"),
            b"secret_value_1".to_vec(),
        );
        secrets.secrets.insert(
            SecretName::new("test.key2"),
            b"secret_value_2".to_vec(),
        );

        let passphrase = "test_passphrase_123";
        let params = Argon2Params::default();

        // Encrypt
        let file = SecretFile::encrypt(&secrets, passphrase, params).unwrap();

        // Decrypt
        let decrypted = file.decrypt(passphrase).unwrap();

        assert_eq!(
            decrypted.secrets.get(&SecretName::new("test.key1")).unwrap(),
            b"secret_value_1"
        );
        assert_eq!(
            decrypted.secrets.get(&SecretName::new("test.key2")).unwrap(),
            b"secret_value_2"
        );
    }

    #[test]
    fn test_wrong_passphrase() {
        let mut secrets = SecretMap {
            secrets: HashMap::new(),
        };
        secrets.secrets.insert(
            SecretName::new("test.key"),
            b"secret".to_vec(),
        );

        let file = SecretFile::encrypt(&secrets, "correct", Argon2Params::default()).unwrap();

        // Try to decrypt with wrong passphrase
        let result = file.decrypt("wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_deserialize() {
        let mut secrets = SecretMap {
            secrets: HashMap::new(),
        };
        secrets.secrets.insert(
            SecretName::new("test.key"),
            b"secret".to_vec(),
        );

        let file = SecretFile::encrypt(&secrets, "pass", Argon2Params::default()).unwrap();

        // Serialize to bytes
        let bytes = file.to_bytes().unwrap();

        // Deserialize
        let file2 = SecretFile::from_bytes(&bytes).unwrap();

        // Decrypt with same passphrase
        let decrypted = file2.decrypt("pass").unwrap();
        assert_eq!(
            decrypted.secrets.get(&SecretName::new("test.key")).unwrap(),
            b"secret"
        );
    }
}
```


---

#### File: `igra-core/src/infrastructure/keys/backends/file_secret_store.rs`

```rust
//! Encrypted file-based secret store

use crate::foundation::error::ThresholdError;
use crate::infrastructure::keys::{
    backends::file_format::{Argon2Params, SecretFile, SecretMap},
    secret_store::{SecretBytes, SecretStore},
    types::SecretName,
};
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

/// SecretStore that reads/writes encrypted file
///
/// File format: Argon2id key derivation + XChaCha20-Poly1305 encryption
///
/// Thread-safe: Uses interior mutability for in-memory cache
pub struct FileSecretStore {
    file_path: PathBuf,
    cache: tokio::sync::RwLock<HashMap<SecretName, SecretBytes>>,
}

impl FileSecretStore {
    /// Open existing secrets file
    pub async fn open(
        path: impl AsRef<Path>,
        passphrase: &str,
    ) -> Result<Self, ThresholdError> {
        let path = path.as_ref();

        // Validate file permissions (Unix only)
        #[cfg(target_family = "unix")]
        Self::validate_file_permissions(path)?;

        // Read file
        let data = tokio::fs::read(path).await.map_err(|e| {
            ThresholdError::secret_store_unavailable(
                "file",
                format!("Failed to read secrets file: {}", e),
            )
        })?;

        // Decrypt
        let file = SecretFile::from_bytes(&data)?;
        let mut secret_map = file.decrypt(passphrase)?;

        // Load into cache
        let mut cache = HashMap::new();
        for (name, bytes) in secret_map.secrets.drain() {
            cache.insert(name, SecretBytes::new(bytes));
        }

        log::info!("Loaded {} secrets from {:?}", cache.len(), path);

        Ok(Self {
            file_path: path.to_path_buf(),
            cache: tokio::sync::RwLock::new(cache),
        })
    }

    /// Create new secrets file (fails if exists)
    pub async fn create(
        path: impl AsRef<Path>,
        passphrase: &str,
    ) -> Result<Self, ThresholdError> {
        let path = path.as_ref();

        if path.exists() {
            return Err(ThresholdError::secret_store_unavailable(
                "file",
                format!("Secrets file already exists: {:?}", path),
            ));
        }

        // Create empty secret map
        let secret_map = SecretMap {
            secrets: HashMap::new(),
        };

        // Encrypt and write
        let file = SecretFile::encrypt(&secret_map, passphrase, Argon2Params::default())?;
        let bytes = file.to_bytes()?;

        tokio::fs::write(path, &bytes).await.map_err(|e| {
            ThresholdError::secret_store_unavailable(
                "file",
                format!("Failed to write secrets file: {}", e),
            )
        })?;

        // Set restrictive permissions (Unix only)
        #[cfg(target_family = "unix")]
        Self::set_file_permissions(path)?;

        log::info!("Created new secrets file: {:?}", path);

        Ok(Self {
            file_path: path.to_path_buf(),
            cache: tokio::sync::RwLock::new(HashMap::new()),
        })
    }

    /// Open existing file or create if doesn't exist
    pub async fn open_or_create(
        path: impl AsRef<Path>,
        passphrase: &str,
    ) -> Result<Self, ThresholdError> {
        let path = path.as_ref();

        if path.exists() {
            Self::open(path, passphrase).await
        } else {
            Self::create(path, passphrase).await
        }
    }

    /// Add or update a secret in the store
    pub async fn set(
        &self,
        name: SecretName,
        secret: SecretBytes,
    ) -> Result<(), ThresholdError> {
        let mut cache = self.cache.write().await;
        cache.insert(name, secret);
        Ok(())
    }

    /// Remove a secret from the store
    pub async fn remove(&self, name: &SecretName) -> Result<(), ThresholdError> {
        let mut cache = self.cache.write().await;
        cache.remove(name);
        Ok(())
    }

    /// Save current cache to encrypted file
    pub async fn save(&self, passphrase: &str) -> Result<(), ThresholdError> {
        let cache = self.cache.read().await;

        // Build secret map
        let mut secret_map = SecretMap {
            secrets: HashMap::new(),
        };

        for (name, bytes) in cache.iter() {
            secret_map.secrets.insert(
                name.clone(),
                bytes.expose_secret().to_vec(),
            );
        }

        // Encrypt
        let file = SecretFile::encrypt(&secret_map, passphrase, Argon2Params::default())?;
        let bytes = file.to_bytes()?;

        // Write to temp file first, then rename (atomic on Unix)
        let temp_path = self.file_path.with_extension("tmp");

        tokio::fs::write(&temp_path, &bytes).await.map_err(|e| {
            ThresholdError::secret_store_unavailable(
                "file",
                format!("Failed to write secrets file: {}", e),
            )
        })?;

        tokio::fs::rename(&temp_path, &self.file_path).await.map_err(|e| {
            ThresholdError::secret_store_unavailable(
                "file",
                format!("Failed to rename secrets file: {}", e),
            )
        })?;

        // Set restrictive permissions (Unix only)
        #[cfg(target_family = "unix")]
        Self::set_file_permissions(&self.file_path)?;

        log::info!("Saved {} secrets to {:?}", cache.len(), self.file_path);

        Ok(())
    }

    #[cfg(target_family = "unix")]
    fn validate_file_permissions(path: &Path) -> Result<(), ThresholdError> {
        use std::os::unix::fs::PermissionsExt;

        let metadata = std::fs::metadata(path).map_err(|e| {
            ThresholdError::secret_store_unavailable(
                "file",
                format!("Failed to read file metadata: {}", e),
            )
        })?;

        let permissions = metadata.permissions();
        let mode = permissions.mode();

        // Check that file is not world-readable or group-readable
        if mode & 0o077 != 0 {
            return Err(ThresholdError::InsecureFilePermissions {
                path: path.display().to_string(),
                mode: mode & 0o777,
            });
        }

        Ok(())
    }

    #[cfg(target_family = "unix")]
    fn set_file_permissions(path: &Path) -> Result<(), ThresholdError> {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = std::fs::metadata(path)
            .map_err(|e| {
                ThresholdError::secret_store_unavailable(
                    "file",
                    format!("Failed to read file metadata: {}", e),
                )
            })?
            .permissions();

        permissions.set_mode(0o600); // Read/write for owner only

        std::fs::set_permissions(path, permissions).map_err(|e| {
            ThresholdError::secret_store_unavailable(
                "file",
                format!("Failed to set file permissions: {}", e),
            )
        })?;

        Ok(())
    }
}

impl SecretStore for FileSecretStore {
    fn get<'a>(
        &'a self,
        name: &'a SecretName,
    ) -> Pin<Box<dyn Future<Output = Result<SecretBytes, ThresholdError>> + Send + 'a>> {
        Box::pin(async move {
            let cache = self.cache.read().await;
            cache
                .get(name)
                .cloned()
                .ok_or_else(|| ThresholdError::secret_not_found(name.as_str(), "file"))
        })
    }

    fn list_secrets<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SecretName>, ThresholdError>> + Send + 'a>> {
        Box::pin(async move {
            let cache = self.cache.read().await;
            Ok(cache.keys().cloned().collect())
        })
    }
}
```

---

#### File: `igra-core/src/infrastructure/keys/backends/local_key_manager.rs`

```rust
//! Local KeyManager implementation (in-process signing)

use crate::foundation::error::ThresholdError;
use crate::infrastructure::keys::{
    audit::{KeyAuditLogger, OperationResult, SecretAccessEvent, SecretOperation, now_nanos},
    key_manager::KeyManager,
    panic_guard::SecretPanicGuard,
    secret_store::{SecretBytes, SecretStore},
    types::{
        KeyManagerCapabilities, KeyRef, RequestId, SignatureScheme, SigningPayload,
    },
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use zeroize::Zeroize;

/// LocalKeyManager performs all signing operations in-process
///
/// Supports:
/// - Secp256k1 Schnorr signatures (Kaspa transactions)
/// - Secp256k1 ECDSA signatures (Hyperlane compatibility)
/// - Ed25519 signatures (Iroh identity)
///
/// Secrets are loaded from SecretStore and held in memory only during operations.
pub struct LocalKeyManager {
    secret_store: Arc<dyn SecretStore>,
    audit_log: Arc<dyn KeyAuditLogger>,
}

impl LocalKeyManager {
    pub fn new(
        secret_store: Arc<dyn SecretStore>,
        audit_log: Arc<dyn KeyAuditLogger>,
    ) -> Self {
        Self {
            secret_store,
            audit_log,
        }
    }

    async fn get_secret_with_audit(
        &self,
        key_ref: &KeyRef,
    ) -> Result<SecretBytes, ThresholdError> {
        let request_id = RequestId::new();
        let secret_name = key_ref.qualified_name();

        let result = self.secret_store.get(&secret_name.into()).await;

        // Log secret access
        let event = SecretAccessEvent {
            timestamp: now_nanos(),
            request_id,
            secret_name: secret_name.clone(),
            backend: "local".to_string(),
            operation: SecretOperation::Get,
            result: OperationResult::from_result(&result),
            caller_module: Some(module_path!().to_string()),
        };

        self.audit_log.log_secret_access(event).await?;

        result
    }

    async fn sign_schnorr(
        &self,
        key_ref: &KeyRef,
        payload: SigningPayload<'_>,
    ) -> Result<Vec<u8>, ThresholdError> {
        // Load secret key
        let secret_bytes = self.get_secret_with_audit(key_ref).await?;

        // Parse into secp256k1 secret key
        let mut guard = SecretPanicGuard::new(secret_bytes.expose_secret().to_vec());

        let secret_key = secp256k1::SecretKey::from_slice(guard.get()).map_err(|e| {
            ThresholdError::key_operation_failed(
                "parse_secret_key",
                key_ref,
                format!("Invalid secp256k1 secret key: {}", e),
            )
        })?;

        // Compute message hash if needed
        let message_hash = match payload {
            SigningPayload::Digest(d) => d.to_vec(),
            SigningPayload::Message(m) => {
                // Hash message with SHA256 (Kaspa standard)
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(m);
                hasher.finalize().to_vec()
            }
        };

        // Sign with Schnorr
        let secp = secp256k1::Secp256k1::new();
        let message = secp256k1::Message::from_slice(&message_hash).map_err(|e| {
            ThresholdError::key_operation_failed(
                "parse_message",
                key_ref,
                format!("Invalid message hash: {}", e),
            )
        })?;

        let keypair = secp256k1::KeyPair::from_secret_key(&secp, &secret_key);
        let signature = secp.sign_schnorr(&message, &keypair);

        // Zeroize secret material
        guard.take().zeroize();

        Ok(signature.as_ref().to_vec())
    }

    async fn sign_ecdsa(
        &self,
        key_ref: &KeyRef,
        payload: SigningPayload<'_>,
    ) -> Result<Vec<u8>, ThresholdError> {
        // Load secret key
        let secret_bytes = self.get_secret_with_audit(key_ref).await?;

        // Parse into secp256k1 secret key
        let mut guard = SecretPanicGuard::new(secret_bytes.expose_secret().to_vec());

        let secret_key = secp256k1::SecretKey::from_slice(guard.get()).map_err(|e| {
            ThresholdError::key_operation_failed(
                "parse_secret_key",
                key_ref,
                format!("Invalid secp256k1 secret key: {}", e),
            )
        })?;

        // Compute message hash if needed
        let message_hash = match payload {
            SigningPayload::Digest(d) => d.to_vec(),
            SigningPayload::Message(m) => {
                // Hash message with SHA256
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(m);
                hasher.finalize().to_vec()
            }
        };

        // Sign with ECDSA
        let secp = secp256k1::Secp256k1::new();
        let message = secp256k1::Message::from_slice(&message_hash).map_err(|e| {
            ThresholdError::key_operation_failed(
                "parse_message",
                key_ref,
                format!("Invalid message hash: {}", e),
            )
        })?;

        let signature = secp.sign_ecdsa(&message, &secret_key);

        // Zeroize secret material
        guard.take().zeroize();

        // Return compact signature (64 bytes: r || s)
        Ok(signature.serialize_compact().to_vec())
    }

    async fn sign_ed25519(
        &self,
        key_ref: &KeyRef,
        payload: SigningPayload<'_>,
    ) -> Result<Vec<u8>, ThresholdError> {
        // Load secret seed (32 bytes)
        let secret_bytes = self.get_secret_with_audit(key_ref).await?;

        let mut guard = SecretPanicGuard::new(secret_bytes.expose_secret().to_vec());

        // Parse Ed25519 signing key
        let signing_key = ed25519_dalek::SigningKey::from_bytes(
            guard.get().try_into().map_err(|_| {
                ThresholdError::key_operation_failed(
                    "parse_ed25519_key",
                    key_ref,
                    "Ed25519 seed must be exactly 32 bytes".to_string(),
                )
            })?,
        );

        // Sign message
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(payload.as_bytes());

        // Zeroize secret material
        guard.take().zeroize();

        Ok(signature.to_bytes().to_vec())
    }

    async fn get_public_key_secp256k1(
        &self,
        key_ref: &KeyRef,
        scheme: SignatureScheme,
    ) -> Result<Vec<u8>, ThresholdError> {
        // Load secret key
        let secret_bytes = self.get_secret_with_audit(key_ref).await?;

        let mut guard = SecretPanicGuard::new(secret_bytes.expose_secret().to_vec());

        let secret_key = secp256k1::SecretKey::from_slice(guard.get()).map_err(|e| {
            ThresholdError::key_operation_failed(
                "parse_secret_key",
                key_ref,
                format!("Invalid secp256k1 secret key: {}", e),
            )
        })?;

        let secp = secp256k1::Secp256k1::new();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        // Zeroize secret
        guard.take().zeroize();

        match scheme {
            SignatureScheme::Secp256k1Schnorr => {
                // Return x-only pubkey (32 bytes)
                let (xonly, _parity) = public_key.x_only_public_key();
                Ok(xonly.serialize().to_vec())
            }
            SignatureScheme::Secp256k1Ecdsa => {
                // Return compressed pubkey (33 bytes)
                Ok(public_key.serialize().to_vec())
            }
            _ => Err(ThresholdError::unsupported_signature_scheme(
                scheme, "local",
            )),
        }
    }

    async fn get_public_key_ed25519(
        &self,
        key_ref: &KeyRef,
    ) -> Result<Vec<u8>, ThresholdError> {
        // Load secret seed
        let secret_bytes = self.get_secret_with_audit(key_ref).await?;

        let mut guard = SecretPanicGuard::new(secret_bytes.expose_secret().to_vec());

        let signing_key = ed25519_dalek::SigningKey::from_bytes(
            guard.get().try_into().map_err(|_| {
                ThresholdError::key_operation_failed(
                    "parse_ed25519_key",
                    key_ref,
                    "Ed25519 seed must be exactly 32 bytes".to_string(),
                )
            })?,
        );

        let verifying_key = signing_key.verifying_key();

        // Zeroize secret
        guard.take().zeroize();

        Ok(verifying_key.to_bytes().to_vec())
    }
}

impl KeyManager for LocalKeyManager {
    fn capabilities(&self) -> KeyManagerCapabilities {
        KeyManagerCapabilities {
            supports_secp256k1_schnorr: true,
            supports_secp256k1_ecdsa: true,
            supports_ed25519: true,
            supports_secret_export: true,
            supports_key_rotation: false, // Phase 2
        }
    }

    fn secret_store(&self) -> Option<&dyn SecretStore> {
        Some(self.secret_store.as_ref())
    }

    fn public_key<'a>(
        &'a self,
        key: &'a KeyRef,
        scheme: SignatureScheme,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, ThresholdError>> + Send + 'a>> {
        Box::pin(async move {
            match scheme {
                SignatureScheme::Secp256k1Schnorr | SignatureScheme::Secp256k1Ecdsa => {
                    self.get_public_key_secp256k1(key, scheme).await
                }
                SignatureScheme::Ed25519 => {
                    self.get_public_key_ed25519(key).await
                }
            }
        })
    }

    fn sign<'a>(
        &'a self,
        key: &'a KeyRef,
        scheme: SignatureScheme,
        payload: SigningPayload<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, ThresholdError>> + Send + 'a>> {
        Box::pin(async move {
            match scheme {
                SignatureScheme::Secp256k1Schnorr => {
                    self.sign_schnorr(key, payload).await
                }
                SignatureScheme::Secp256k1Ecdsa => {
                    self.sign_ecdsa(key, payload).await
                }
                SignatureScheme::Ed25519 => {
                    self.sign_ed25519(key, payload).await
                }
            }
        })
    }
}
```

---

### Step 5: Wire Into Application

#### File: `igra-core/src/foundation/error.rs` (UPDATE)

Add the new error variants to the `ThresholdError` enum:

```rust
// Add these variants to the existing ThresholdError enum:

    // === Key Management Errors ===

    #[error("Secret not found: {name} (backend: {backend})")]
    SecretNotFound {
        name: String,
        backend: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Secret decode failed: {name} (encoding: {encoding}, details: {details})")]
    SecretDecodeFailed {
        name: String,
        encoding: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Secret store unavailable: {backend} - {details}")]
    SecretStoreUnavailable {
        backend: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Secret decryption failed: {backend} - {details}")]
    SecretDecryptFailed {
        backend: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Unsupported signature scheme: {scheme} (backend: {backend})")]
    UnsupportedSignatureScheme {
        scheme: String,
        backend: String,
    },

    #[error("Key not found: {key_ref}")]
    KeyNotFound {
        key_ref: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Key operation failed: {operation} on {key_ref} - {details}")]
    KeyOperationFailed {
        operation: String,
        key_ref: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Invalid secret file permissions: {path} has mode {mode:o}, expected 0600")]
    InsecureFilePermissions {
        path: String,
        mode: u32,
    },

    #[error("Audit log error: {details}")]
    AuditLogError {
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
```

---

#### File: `igra-core/src/infrastructure/keys/mod.rs`

```rust
//! Key management infrastructure

pub mod audit;
pub mod backends;
pub mod context;
pub mod error;
pub mod key_manager;
pub mod panic_guard;
pub mod protected_memory;
pub mod secret_store;
pub mod types;

// Re-export commonly used types
pub use audit::{FileAuditLogger, KeyAuditLogger, NoopAuditLogger};
pub use backends::{EnvSecretStore, FileSecretStore, LocalKeyManager};
pub use context::KeyManagerContext;
pub use key_manager::KeyManager;
pub use secret_store::{SecretBytes, SecretStore};
pub use types::{
    KeyManagerCapabilities, KeyRef, RequestId, SecretName, SignatureScheme, SigningPayload,
};
```

---

#### File: `igra-core/src/infrastructure/mod.rs` (UPDATE)

```rust
// Add to existing infrastructure modules:
pub mod keys;
```


---

## Migration Guide

### Phase 1E: Convert Existing Secret Access

This section details **every location** that needs to be updated.

#### 1. Update `ServiceFlow` (Application Layer)

**File**: `igra-service/src/service/flow.rs`

```rust
// ADD this field to ServiceFlow struct:
pub struct ServiceFlow {
    pub key_manager: Arc<dyn KeyManager>,  // ADD THIS
    pub audit_log: Arc<dyn KeyAuditLogger>,  // ADD THIS

    // ... existing fields ...
    pub config: ServiceConfig,
    pub storage: Arc<dyn Storage>,
    // etc.
}

// UPDATE constructor to accept KeyManager:
impl ServiceFlow {
    pub fn new(
        key_manager: Arc<dyn KeyManager>,
        audit_log: Arc<dyn KeyAuditLogger>,
        config: ServiceConfig,
        storage: Arc<dyn Storage>,
        // ... other params ...
    ) -> Self {
        Self {
            key_manager,
            audit_log,
            config,
            storage,
            // ... other fields ...
        }
    }

    /// Create KeyManagerContext for a request
    pub fn key_context(&self) -> KeyManagerContext {
        KeyManagerContext::with_new_request_id(
            self.key_manager.clone(),
            self.audit_log.clone(),
        )
    }
}
```

---

#### 2. Update Service Startup

**File**: `igra-service/src/bin/kaspa-threshold-service/setup.rs`

```rust
use igra_core::infrastructure::keys::{
    EnvSecretStore, FileSecretStore, LocalKeyManager,
    FileAuditLogger, KeyManager, SecretStore,
};
use std::sync::Arc;

/// Build KeyManager based on configuration
pub async fn setup_key_manager(
    config: &ServiceConfig,
) -> Result<(Arc<dyn KeyManager>, Arc<dyn KeyAuditLogger>), ThresholdError> {
    // 1. Choose SecretStore backend
    let secret_store: Arc<dyn SecretStore> = if config.use_encrypted_secrets {
        // Production/local: use encrypted file
        let secrets_path = config.data_dir.join("secrets.bin");

        if !secrets_path.exists() {
            return Err(ThresholdError::secret_store_unavailable(
                "file",
                format!(
                    "Secrets file not found: {:?}. Run 'igra-keygen' to create it.",
                    secrets_path
                ),
            ));
        }

        let passphrase = prompt_passphrase()?;

        Arc::new(
            FileSecretStore::open(secrets_path, &passphrase)
                .await
                .map_err(|e| {
                    ThresholdError::secret_store_unavailable(
                        "file",
                        format!("Failed to open secrets file: {}", e),
                    )
                })?,
        )
    } else {
        // Devnet/CI: use environment variables
        log::warn!(
            "Using environment-based secrets (DEVNET ONLY - not for production)"
        );
        Arc::new(EnvSecretStore::new())
    };

    // 2. Set up audit logger
    let audit_path = config.data_dir.join("key-audit.log");
    let audit_log: Arc<dyn KeyAuditLogger> = Arc::new(
        FileAuditLogger::new(&audit_path)
            .map_err(|e| {
                ThresholdError::AuditLogError {
                    details: format!("Failed to create audit log: {}", e),
                    source: Some(Box::new(e)),
                }
            })?,
    );

    // 3. Build LocalKeyManager
    let key_manager: Arc<dyn KeyManager> = Arc::new(LocalKeyManager::new(
        secret_store,
        audit_log.clone(),
    ));

    // 4. Validate required keys exist
    let required_keys = vec![
        &KeyRef::new("igra.hd", "wallet_secret"),
        // Add other required keys here
    ];

    key_manager.validate_required_keys(&required_keys).await?;

    log::info!("KeyManager initialized successfully");

    Ok((key_manager, audit_log))
}

fn prompt_passphrase() -> Result<String, ThresholdError> {
    use std::io::{self, Write};

    // Check for passphrase in env var first (for automated deployments)
    if let Ok(pass) = std::env::var("IGRA_SECRETS_PASSPHRASE") {
        log::debug!("Using passphrase from IGRA_SECRETS_PASSPHRASE env var");
        return Ok(pass);
    }

    // Interactive prompt
    print!("Enter secrets file passphrase: ");
    io::stdout().flush().unwrap();

    let mut passphrase = String::new();
    io::stdin()
        .read_line(&mut passphrase)
        .map_err(|e| ThresholdError::secret_store_unavailable(
            "file",
            format!("Failed to read passphrase: {}", e),
        ))?;

    Ok(passphrase.trim().to_string())
}

// UPDATE main() to wire KeyManager:
pub async fn main() -> Result<(), ThresholdError> {
    // ... existing setup ...

    let config = load_config()?;

    // NEW: Set up key manager
    let (key_manager, audit_log) = setup_key_manager(&config).await?;

    // ... existing setup ...

    let service_flow = ServiceFlow::new(
        key_manager,      // ADD THIS
        audit_log,        // ADD THIS
        config,
        storage,
        // ... other params ...
    );

    // ... rest of main ...
}
```

---

#### 3. Update PSKT Signing

**File**: `igra-core/src/application/pskt_signing.rs`

**BEFORE** (old code):

```rust
pub async fn sign_pskt_with_app_config(
    config: &ServiceConfig,
    pskt_json: &str,
) -> Result<SignedPskt, ThresholdError> {
    // OLD: Direct secret loading
    let wallet_secret = load_wallet_secret()?;
    let hd_config = config.hd.clone();

    // Decrypt mnemonics
    let mnemonics = hd_config.decrypt_mnemonics(&wallet_secret)?;

    // Derive keypair
    let keypair = derive_keypair_from_key_data(/* ... */)?;

    // Sign
    let signature = sign_pskt(/* ... */)?;

    Ok(signature)
}
```

**AFTER** (new code):

```rust
use igra_core::infrastructure::keys::{KeyManagerContext, KeyRef, SignatureScheme, SigningPayload};

pub async fn sign_pskt_with_key_manager(
    key_context: &KeyManagerContext,
    pskt_json: &str,
    signer_index: usize,
) -> Result<SignedPskt, ThresholdError> {
    // Parse PSKT
    let pskt: Pskt = serde_json::from_str(pskt_json)?;

    // Get wallet secret to decrypt mnemonics
    let wallet_secret_key = KeyRef::new("igra.hd", "wallet_secret");
    let wallet_secret_bytes = key_context
        .key_manager()
        .secret_store()
        .ok_or_else(|| ThresholdError::secret_store_unavailable(
            "none",
            "KeyManager has no SecretStore".to_string(),
        ))?
        .get(&wallet_secret_key.qualified_name().into())
        .await?;

    // Decrypt mnemonics using wallet secret (existing logic)
    let wallet_secret = String::from_utf8(wallet_secret_bytes.expose_secret().to_vec())
        .map_err(|e| ThresholdError::secret_decode_failed(
            wallet_secret_key.qualified_name(),
            "utf8",
            format!("Invalid UTF-8: {}", e),
        ))?;

    // Load encrypted mnemonics from config and decrypt
    // (This part stays the same - we're still using config for encrypted mnemonics)
    let mnemonics = /* decrypt with wallet_secret */;

    // Derive keypair for this signer
    let keypair_data = derive_keypair_from_mnemonic(&mnemonics[signer_index])?;

    // Store derived private key temporarily with KeyManager namespace
    // (Alternative: sign directly here, but using KeyManager is more consistent)

    let mut partial_signatures = Vec::new();

    for (input_index, input) in pskt.inputs.iter().enumerate() {
        // Compute SIGHASH for this input
        let sighash = compute_sighash(&pskt, input_index)?;

        // Create signing payload
        let payload = SigningPayload::Digest(&sighash);

        // For now, we'll sign directly with the derived key
        // (Phase 2: Store HD-derived keys in KeyManager with dynamic KeyRefs)
        let signature = sign_schnorr_direct(&keypair_data, &sighash)?;

        partial_signatures.push(signature);
    }

    Ok(SignedPskt {
        pskt,
        partial_signatures,
        signer_pubkey: keypair_data.pubkey,
    })
}

// Helper to sign directly (transitional approach)
fn sign_schnorr_direct(
    keypair_data: &KeypairData,
    sighash: &[u8],
) -> Result<Vec<u8>, ThresholdError> {
    use secp256k1::{Secp256k1, Message, KeyPair};

    let secp = Secp256k1::new();
    let secret_key = secp256k1::SecretKey::from_slice(&keypair_data.secret_bytes)?;
    let keypair = KeyPair::from_secret_key(&secp, &secret_key);
    let message = Message::from_slice(sighash)?;

    let signature = secp.sign_schnorr(&message, &keypair);

    Ok(signature.as_ref().to_vec())
}
```

**Note**: For Phase 1, we keep HD derivation logic but load the wallet secret through KeyManager. For Phase 2, we can optionally store derived keys with dynamic KeyRefs.

---

#### 4. Update Config Loading

**File**: `igra-core/src/infrastructure/config/loader.rs`

**REMOVE** direct secret loading functions:

```rust
// DELETE or deprecate these functions:
// pub fn load_wallet_secret() -> Result<String, ThresholdError> { ... }
```

**UPDATE** config validation to NOT require secrets in config:

```rust
// REMOVE checks for hd.passphrase being present in config
// It should now come from KeyManager/SecretStore
```

---

#### 5. Update Config Types

**File**: `igra-core/src/infrastructure/config/types.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsktHdConfig {
    /// Encrypted mnemonics (still in config - encrypted at rest)
    #[serde(default)]
    pub encrypted_mnemonics: Vec<PrvKeyData>,

    /// Payment secret NOW REMOVED from config
    /// (Loaded from KeyManager instead)
    // DELETE THIS FIELD:
    // pub passphrase: Option<String>,

    /// Derivation path template
    #[serde(default)]
    pub derivation_path: String,

    /// Required signatures for multisig
    pub required_sigs: usize,
}

// Note: encrypted_mnemonics stay in config because they're encrypted
// The wallet_secret that decrypts them comes from KeyManager
```

---

#### 6. Update Iroh Identity Setup

**File**: `igra-service/src/bin/kaspa-threshold-service/setup.rs` (iroh section)

**BEFORE**:

```rust
// OLD: Read from config
let signer_seed_hex = config.iroh.signer_seed_hex.clone();
let signer_seed = hex::decode(signer_seed_hex)?;
let signer = Ed25519Signer::from_seed(&signer_seed)?;
```

**AFTER**:

```rust
use igra_core::infrastructure::keys::{KeyRef, SignatureScheme};

// NEW: Load from KeyManager
let iroh_seed_key = KeyRef::new("igra.iroh", "signer_seed");
let signer_seed_bytes = key_manager
    .secret_store()
    .ok_or_else(|| ThresholdError::secret_store_unavailable(
        "none",
        "No SecretStore available".to_string(),
    ))?
    .get(&iroh_seed_key.qualified_name().into())
    .await?;

let signer_seed: [u8; 32] = signer_seed_bytes
    .expose_secret()
    .try_into()
    .map_err(|_| ThresholdError::key_operation_failed(
        "parse_iroh_seed",
        &iroh_seed_key,
        "Seed must be exactly 32 bytes".to_string(),
    ))?;

let signer = Ed25519Signer::from_seed(&signer_seed)?;

// Zeroize seed after use
use zeroize::Zeroize;
let mut seed_copy = signer_seed;
seed_copy.zeroize();
```

---

## Devnet Scripts Update

### Update devnet-keygen

**File**: `igra-core/src/bin/devnet-keygen.rs`

Add functionality to generate secrets for both EnvSecretStore and FileSecretStore:

```rust
//! Devnet key generation tool
//!
//! Generates all required secrets for devnet/testing and outputs in two formats:
//! 1. Environment variables (for IGRA_SECRET__* pattern)
//! 2. Encrypted secrets file (for FileSecretStore)

use clap::Parser;
use igra_core::infrastructure::keys::{
    backends::file_format::{Argon2Params, SecretFile, SecretMap},
    types::SecretName,
};
use kaspa_bip32::{Mnemonic, WordCount, Language};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "devnet-keygen")]
#[command(about = "Generate devnet keys and secrets")]
struct Args {
    /// Output format: "env" (shell export), "file" (encrypted), or "both"
    #[arg(short, long, default_value = "both")]
    format: String,

    /// Output file path (for "file" or "both" formats)
    #[arg(short, long, default_value = "./devnet-secrets.bin")]
    output: PathBuf,

    /// Passphrase for encrypted file
    #[arg(short, long)]
    passphrase: Option<String>,

    /// Number of HD wallet mnemonics to generate
    #[arg(short, long, default_value = "3")]
    num_signers: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("🔐 Igra Devnet Key Generator");
    println!();

    // Generate all secrets
    let mut secrets = HashMap::new();

    // 1. Wallet secret (32 random bytes for encrypting HD mnemonics)
    let wallet_secret = generate_random_bytes(32);
    secrets.insert(
        SecretName::new("igra.hd.wallet_secret"),
        wallet_secret.clone(),
    );
    println!("✓ Generated wallet secret (32 bytes)");

    // 2. Payment secret (optional BIP39 passphrase)
    let payment_secret = generate_random_string(16);
    secrets.insert(
        SecretName::new("igra.hd.payment_secret"),
        payment_secret.as_bytes().to_vec(),
    );
    println!("✓ Generated payment secret");

    // 3. Iroh signer seed (32 bytes for Ed25519)
    let iroh_seed = generate_random_bytes(32);
    secrets.insert(
        SecretName::new("igra.iroh.signer_seed"),
        iroh_seed.clone(),
    );
    println!("✓ Generated Iroh signer seed (Ed25519)");

    // 4. Generate HD mnemonics
    println!();
    println!("📝 Generating {} HD wallet mnemonics:", args.num_signers);

    for i in 0..args.num_signers {
        let mnemonic = Mnemonic::random(WordCount::Words24, Language::English)?;
        let mnemonic_str = mnemonic.phrase();

        println!("  Signer {}: {} ...", i, &mnemonic_str[..50]);

        // Store mnemonic words as secret
        secrets.insert(
            SecretName::new(format!("igra.hd.mnemonic_{}", i)),
            mnemonic_str.as_bytes().to_vec(),
        );

        // Also derive and print the first key for reference
        let xprv = mnemonic.to_extended_key("")?;
        let path = "m/45'/111111'/0'/0/0";
        let derived = xprv.derive_path(path)?;
        let pubkey = derived.public_key();

        println!("    Pubkey (m/45'/111111'/0'/0/0): {}", hex::encode(pubkey.to_bytes()));
    }

    println!();

    // Output in requested format(s)
    match args.format.as_str() {
        "env" => {
            output_env_format(&secrets)?;
        }
        "file" => {
            let passphrase = args.passphrase.unwrap_or_else(|| {
                prompt_passphrase("Enter passphrase for secrets file: ")
            });
            output_file_format(&secrets, &args.output, &passphrase)?;
        }
        "both" => {
            output_env_format(&secrets)?;
            println!();
            let passphrase = args.passphrase.unwrap_or_else(|| {
                prompt_passphrase("Enter passphrase for secrets file: ")
            });
            output_file_format(&secrets, &args.output, &passphrase)?;
        }
        _ => {
            eprintln!("Invalid format: {}. Use 'env', 'file', or 'both'", args.format);
            std::process::exit(1);
        }
    }

    println!();
    println!("✅ Done!");

    Ok(())
}

fn generate_random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn generate_random_string(len: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();

    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn output_env_format(secrets: &HashMap<SecretName, Vec<u8>>) -> Result<(), Box<dyn std::error::Error>> {
    println!("📋 Environment Variables Format:");
    println!();
    println!("# Copy these to your shell or .env file:");
    println!();

    for (name, value) in secrets {
        // Convert SecretName format (igra.hd.wallet_secret) to env var (IGRA_SECRET__igra_hd__wallet_secret)
        let env_name = format!("IGRA_SECRET__{}", name.as_str().replace('.', "__"));

        // Encode as hex for binary data
        let encoded = format!("hex:{}", hex::encode(value));

        println!("export {}=\"{}\"", env_name, encoded);
    }

    Ok(())
}

fn output_file_format(
    secrets: &HashMap<SecretName, Vec<u8>>,
    path: &PathBuf,
    passphrase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("💾 Creating encrypted secrets file...");

    let secret_map = SecretMap {
        secrets: secrets.clone(),
    };

    let file = SecretFile::encrypt(&secret_map, passphrase, Argon2Params::default())?;
    let bytes = file.to_bytes()?;

    std::fs::write(path, &bytes)?;

    // Set restrictive permissions (Unix only)
    #[cfg(target_family = "unix")]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(path, permissions)?;
    }

    println!("✓ Wrote {} secrets to {:?}", secrets.len(), path);
    println!("  File size: {} bytes", bytes.len());
    println!("  Permissions: 0600 (owner read/write only)");

    Ok(())
}

fn prompt_passphrase(prompt: &str) -> String {
    use std::io::{self, Write};

    print!("{}", prompt);
    io::stdout().flush().unwrap();

    let mut passphrase = String::new();
    io::stdin().read_line(&mut passphrase).unwrap();

    passphrase.trim().to_string()
}
```

**Update devnet scripts to use generated secrets**:

```bash
#!/bin/bash
# scripts/start-devnet.sh

echo "Starting Igra devnet..."

# Generate secrets if they don't exist
if [ ! -f "./devnet-secrets.bin" ]; then
    echo "Generating devnet secrets..."
    cargo run --bin devnet-keygen -- \
        --format file \
        --output ./devnet-secrets.bin \
        --passphrase "devnet_test_passphrase"
fi

# Start service with encrypted secrets file
export IGRA_USE_ENCRYPTED_SECRETS=true
export IGRA_SECRETS_PASSPHRASE="devnet_test_passphrase"
export IGRA_DATA_DIR="./devnet-data"

cargo run --bin kaspa-threshold-service -- \
    --config ./devnet-config.toml \
    --devnet
```

**Alternative: Use environment variables (CI/testing)**:

```bash
#!/bin/bash
# scripts/ci-test.sh

# Generate secrets in env var format
cargo run --bin devnet-keygen -- --format env > /tmp/secrets.env

# Source the secrets
source /tmp/secrets.env

# Secrets are now available as IGRA_SECRET__* env vars
# EnvSecretStore will automatically load them

cargo test --all-features
```

---

## Testing Strategy

### Unit Tests

Each module has comprehensive tests (see `#[cfg(test)]` blocks in implementation files).

Run unit tests:

```bash
cargo test --package igra-core --lib infrastructure::keys
```

### Integration Tests

**File**: `igra-core/tests/key_manager_integration.rs`

```rust
//! Integration tests for KeyManager

use igra_core::infrastructure::keys::*;
use std::sync::Arc;

#[tokio::test]
async fn test_env_secret_store_workflow() {
    // Set up env vars
    std::env::set_var("IGRA_SECRET__test__key1", "hex:deadbeef");

    let store = EnvSecretStore::new();
    let secret = store.get(&SecretName::new("test.key1")).await.unwrap();

    assert_eq!(secret.expose_secret(), &[0xde, 0xad, 0xbe, 0xef]);
}

#[tokio::test]
async fn test_file_secret_store_workflow() {
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("secrets.bin");

    // Create and populate
    let store = FileSecretStore::create(&file_path, "testpass").await.unwrap();
    store
        .set(
            SecretName::new("test.key"),
            SecretBytes::new(b"secret_value".to_vec()),
        )
        .await
        .unwrap();

    store.save("testpass").await.unwrap();

    // Reopen
    let store2 = FileSecretStore::open(&file_path, "testpass").await.unwrap();
    let secret = store2.get(&SecretName::new("test.key")).await.unwrap();

    assert_eq!(secret.expose_secret(), b"secret_value");
}

#[tokio::test]
async fn test_local_key_manager_schnorr_signing() {
    // Set up KeyManager with test secret
    std::env::set_var(
        "IGRA_SECRET__test__schnorr_key",
        "hex:0000000000000000000000000000000000000000000000000000000000000001",
    );

    let secret_store = Arc::new(EnvSecretStore::new());
    let audit_log = Arc::new(NoopAuditLogger);
    let key_manager = Arc::new(LocalKeyManager::new(secret_store, audit_log));

    // Sign a message
    let key_ref = KeyRef::new("test", "schnorr_key");
    let message = b"hello world";
    let signature = key_manager
        .sign(
            &key_ref,
            SignatureScheme::Secp256k1Schnorr,
            SigningPayload::Message(message),
        )
        .await
        .unwrap();

    assert_eq!(signature.len(), 64);

    // Get public key
    let pubkey = key_manager
        .public_key(&key_ref, SignatureScheme::Secp256k1Schnorr)
        .await
        .unwrap();

    assert_eq!(pubkey.len(), 32); // x-only pubkey
}

#[tokio::test]
async fn test_key_manager_context_audit() {
    let temp_dir = tempfile::tempdir().unwrap();
    let audit_path = temp_dir.path().join("audit.log");

    // Set up KeyManager
    std::env::set_var(
        "IGRA_SECRET__test__key",
        "hex:0000000000000000000000000000000000000000000000000000000000000001",
    );

    let secret_store = Arc::new(EnvSecretStore::new());
    let audit_log = Arc::new(FileAuditLogger::new(&audit_path).unwrap());
    let key_manager = Arc::new(LocalKeyManager::new(secret_store, audit_log.clone()));

    let context = KeyManagerContext::with_new_request_id(key_manager, audit_log);

    // Sign with audit
    let key_ref = KeyRef::new("test", "key");
    let _signature = context
        .sign_with_audit(
            &key_ref,
            SignatureScheme::Secp256k1Schnorr,
            SigningPayload::Message(b"test"),
        )
        .await
        .unwrap();

    // Verify audit log was written
    let audit_content = std::fs::read_to_string(&audit_path).unwrap();
    assert!(audit_content.contains("signing"));
    assert!(audit_content.contains("test.key"));
}
```

Run integration tests:

```bash
cargo test --package igra-core --test key_manager_integration
```

### End-to-End Tests

Test complete PSKT signing flow with KeyManager:

```bash
cargo test --package igra-service --test e2e_pskt_signing
```

---

## Validation Checklist

Before marking Phase 1 complete, verify:

### Code Completion

- [ ] All files in `igra-core/src/infrastructure/keys/` implemented
- [ ] Error variants added to `foundation/error.rs`
- [ ] `ServiceFlow` updated with `KeyManager` field
- [ ] `setup_key_manager()` implemented in service startup
- [ ] PSKT signing converted to use KeyManager
- [ ] Iroh identity loading converted to use KeyManager
- [ ] Config types updated (removed plaintext passphrase)
- [ ] `devnet-keygen` updated with new output formats

### Testing

- [ ] All unit tests passing (`cargo test --lib infrastructure::keys`)
- [ ] Integration tests passing
- [ ] End-to-end PSKT signing test passing
- [ ] Devnet startup script works with FileSecretStore
- [ ] Devnet startup script works with EnvSecretStore
- [ ] CI tests work with EnvSecretStore

### Security

- [ ] No secrets logged (verify with `grep -r "expose_secret"`)
- [ ] All secret access goes through KeyManager
- [ ] No direct `std::env::var()` for secrets (except in EnvSecretStore)
- [ ] File permissions validated (0600 for secrets.bin)
- [ ] Audit log captures all signing operations
- [ ] Memory zeroization verified (unit tests)

### Documentation

- [ ] API documentation complete (`cargo doc`)
- [ ] Operator runbook written (how to manage secrets)
- [ ] Team training materials prepared
- [ ] Migration guide tested by team member

### Performance

- [ ] Signing latency < 10ms (benchmark)
- [ ] Secret loading latency < 100ms (benchmark)
- [ ] File decrypt/encrypt latency < 1s (benchmark)
- [ ] No memory leaks in long-running tests

### Deployment Readiness

- [ ] Secrets generation tool works (`devnet-keygen`)
- [ ] Passphrase prompt works in production setup
- [ ] Error messages are clear and actionable
- [ ] Audit log rotation strategy documented
- [ ] Backup/restore procedure for secrets.bin documented

---

## Dependencies to Add

Add to `igra-core/Cargo.toml`:

```toml
[dependencies]
# Key management
secrecy = { version = "0.8", features = ["serde"] }
argon2 = "0.5"
chacha20poly1305 = "0.10"
rand = "0.8"
hex = "0.4"
base64 = "0.22"
bincode = "1.3"
ed25519-dalek = { version = "2.1", features = ["rand_core"] }

# Already have these (verify versions):
# secp256k1 = { version = "0.28", features = ["rand", "recovery"] }
# zeroize = { version = "1.7", features = ["derive"] }
# serde = { version = "1.0", features = ["derive"] }
# serde_json = "1.0"
# tokio = { version = "1", features = ["full"] }
# thiserror = "1.0"
# log = "0.4"
```

For tests, add to `[dev-dependencies]`:

```toml
[dev-dependencies]
tempfile = "3.8"
```

---

## Timeline Estimate

Based on complexity and team size:

- **Week 1**: Foundation + EnvSecretStore (Steps 1-9)
- **Week 2**: FileSecretStore + LocalKeyManager (Steps 10-17)
- **Week 3**: Integration + Migration (Steps 18-29)
- **Week 4**: Testing + Validation + Documentation (Steps 30-34)

**Total**: ~4 weeks for complete Phase 1 implementation.

---

## Success Criteria

Phase 1 is complete when:

1. ✅ All secrets accessed exclusively through KeyManager
2. ✅ Zero direct env var reads for secrets (except in EnvSecretStore)
3. ✅ Devnet works with both EnvSecretStore and FileSecretStore
4. ✅ All existing tests pass
5. ✅ New integration tests pass
6. ✅ Audit log captures all key operations
7. ✅ Team can operate secrets file (create, backup, restore)
8. ✅ Documentation complete

**After Phase 1**, you have:

- Clean abstraction for future KMS/HSM integration (Phase 2)
- Audit-ready key operations
- Production-ready encrypted secrets storage
- Development-friendly environment variable fallback
- No secret leakage in logs
- Memory protection for sensitive data

---

## Next Steps (Phase 2 - Future)

After Phase 1 is validated, consider:

1. **Cosmian KMS integration**: Remote signing for ECDSA/Ed25519
2. **PKCS#11 HSM support**: Hardware-backed key storage
3. **Key rotation**: Version-based key management
4. **Distributed secrets**: Multi-party secret sharing (VSSS)
5. **Remote attestation**: TPM/SGX integration

But for now, **focus on Phase 1**: get the local implementation rock-solid.

---

## Questions & Support

If you encounter issues during implementation:

1. Check error messages - they include context (request_id, key_ref, backend)
2. Review audit logs - all operations are logged
3. Verify secrets.bin permissions (should be 0600)
4. Test with EnvSecretStore first (simpler debugging)
5. Use `RUST_LOG=debug` to see KeyManager operations

**Common issues**:

- "Secret not found": Check SecretName format (dots, not underscores)
- "Insecure file permissions": Run `chmod 600 secrets.bin`
- "Decryption failed": Wrong passphrase or corrupted file
- "Unsupported scheme": Check KeyManager capabilities

---

END OF GUIDE


---

## Ensuring Existing Devnet Scripts Work

### Scripts That Must Remain Compatible

Your team has three critical devnet scripts that MUST continue working:

1. **`run_local_devnet.sh`** - Main devnet runner
2. **`run_local_devnet_with_avail_and_hyperlane.sh`** - Devnet with Hyperlane integration
3. **`run_rothschild.sh`** - Transaction sending utility

### How They Currently Work

#### Current Secret Flow

```bash
# run_local_devnet.sh (line 251)
KASPA_IGRA_WALLET_SECRET="${KASPA_IGRA_WALLET_SECRET:-devnet-secret}"

# When starting igra service (lines 813-826):
start_process "igra-${profile}" \
  env \
    KASPA_CONFIG_PATH="${IGRA_CONFIG}" \
    KASPA_DATA_DIR="${profile_data_dir}" \
    KASPA_NODE_URL="grpc://127.0.0.1:16110" \
    KASPA_IGRA_WALLET_SECRET="${KASPA_IGRA_WALLET_SECRET}" \  # <-- SECRET PASSED HERE
    KASPA_IGRA_PROFILE="${profile}" \
    IGRA_RPC_URL="${rpc_url}" \
    HYPERLANE_KEYS_PATH="${HYPERLANE_KEYS}" \
    "${IGRA_BIN}" \
    --config "${IGRA_CONFIG}" \
    --data-dir "${profile_data_dir}" \
    --node-url "grpc://127.0.0.1:16110" \
    --log-level info
```

#### Scripts Use These Files

1. **devnet-keys.json** - Generated by devnet-keygen, contains:
   - `wallet.private_key_hex`
   - `multisig_address`
   - `source_addresses[]`
   - `member_pubkeys[]`
   - `redeem_script_hex`
   - `evm.private_key_hex` (for Hyperlane)
   - `group_id`

2. **hyperlane-keys.json** - Contains validator keys for Hyperlane

3. **igra-config.toml** - Generated from template, contains encrypted mnemonics

### Compatibility Strategy

**✅ ZERO CHANGES REQUIRED TO SCRIPTS**

The scripts will work **without modification** because:

1. **EnvSecretStore Automatically Maps Environment Variables**

   Current behavior:
   ```bash
   export KASPA_IGRA_WALLET_SECRET="devnet-secret"
   ```

   New KeyManager behavior (automatic):
   ```rust
   // EnvSecretStore automatically reads:
   // - KASPA_IGRA_WALLET_SECRET (legacy name - for backwards compatibility)
   // - IGRA_SECRET__igra_hd__wallet_secret (new standard name)
   
   // Both work! Scripts don't need to change.
   ```

2. **Service Startup Detects Devnet Mode**

   Update `kaspa-threshold-service/setup.rs` to detect devnet:

   ```rust
   pub async fn setup_key_manager(
       config: &ServiceConfig,
   ) -> Result<(Arc<dyn KeyManager>, Arc<dyn KeyAuditLogger>), ThresholdError> {
       // Check if running in devnet mode (environment-based secrets)
       let use_env_secrets = std::env::var("KASPA_IGRA_WALLET_SECRET").is_ok()
           || !config.use_encrypted_secrets;

       let secret_store: Arc<dyn SecretStore> = if use_env_secrets {
           log::info!("Using environment-based secrets (devnet mode)");
           Arc::new(EnvSecretStore::new())
       } else {
           // Production: use encrypted file
           let secrets_path = config.data_dir.join("secrets.bin");
           let passphrase = prompt_passphrase()?;
           Arc::new(FileSecretStore::open(secrets_path, &passphrase).await?)
       };

       // ... rest of setup ...
   }
   ```

3. **EnvSecretStore Enhancement for Legacy Compatibility**

   Update `EnvSecretStore` to support both naming conventions:

   ```rust
   impl EnvSecretStore {
       pub fn new() -> Self {
           let mut cache = HashMap::new();

           // Load new-style IGRA_SECRET__* variables
           for (key, value) in std::env::vars() {
               if let Some(secret_name) = key.strip_prefix("IGRA_SECRET__") {
                   let secret_name = secret_name.replace("__", ".");
                   let secret_name = SecretName::new(secret_name);
                   
                   match Self::decode_value(&value) {
                       Ok(bytes) => {
                           log::debug!("Loaded secret from env: {}", secret_name);
                           cache.insert(secret_name, bytes);
                       }
                       Err(e) => {
                           log::warn!("Failed to decode secret {}: {}", secret_name, e);
                       }
                   }
               }
           }

           // BACKWARDS COMPATIBILITY: Support legacy KASPA_IGRA_WALLET_SECRET
           if let Ok(legacy_secret) = std::env::var("KASPA_IGRA_WALLET_SECRET") {
               let secret_name = SecretName::new("igra.hd.wallet_secret");
               match Self::decode_value(&legacy_secret) {
                   Ok(bytes) => {
                       log::info!("Loaded wallet secret from legacy env var KASPA_IGRA_WALLET_SECRET");
                       cache.entry(secret_name).or_insert(bytes);
                   }
                   Err(e) => {
                       log::warn!("Failed to decode legacy wallet secret: {}", e);
                   }
               }
           }

           log::info!("EnvSecretStore loaded {} secrets", cache.len());

           Self { cache }
       }
   }
   ```

### Testing Existing Scripts

After implementing KeyManager, verify scripts work:

#### Test 1: run_local_devnet.sh

```bash
cd /path/to/rusty-kaspa/wallet/igra/orchestration/devnet/scripts

# Default devnet flow (should work exactly as before)
./run_local_devnet.sh default

# Start services
./run_local_devnet.sh start all

# Check status
./run_local_devnet.sh status

# Stop services
./run_local_devnet.sh stop all
```

**Expected behavior**: Everything works as before, KeyManager silently loads secrets from environment.

#### Test 2: run_local_devnet_with_avail_and_hyperlane.sh

```bash
# Full Hyperlane devnet (should work exactly as before)
./run_local_devnet_with_avail_and_hyperlane.sh default

# Check status
./run_local_devnet_with_avail_and_hyperlane.sh status

# Stop
./run_local_devnet_with_avail_and_hyperlane.sh stop
```

**Expected behavior**: Hyperlane integration works, KeyManager loads secrets for both Igra and Hyperlane components.

#### Test 3: run_rothschild.sh

```bash
# Send funds using devnet wallet
./run_rothschild.sh --to kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3 --amount 100000000
```

**Expected behavior**: Rothschild works as before (reads from devnet-keys.json, which is unchanged).

### What Changes in the Scripts (None!)

**Scripts require ZERO changes** because:

1. ✅ Environment variable `KASPA_IGRA_WALLET_SECRET` still works (EnvSecretStore reads it)
2. ✅ devnet-keygen output format unchanged (JSON structure stays the same)
3. ✅ Scripts pass secrets as env vars (EnvSecretStore picks them up automatically)
4. ✅ All binaries detect environment-based secrets and use EnvSecretStore

### devnet-keygen Output Compatibility

The updated `devnet-keygen` (from Step 29 in migration) must produce **identical JSON structure**:

```json
{
  "member_pubkeys": ["0x...", "0x...", "0x..."],
  "redeem_script_hex": "...",
  "multisig_address": "kaspadev:qr9ptqk4...",
  "source_addresses": ["kaspadev:qr9ptqk4..."],
  "change_address": "kaspadev:qr9ptqk4...",
  "wallet": {
    "private_key_hex": "...",
    "address": "kaspadev:...",
    "mining_address": "kaspadev:..."
  },
  "evm": {
    "private_key_hex": "...",
    "address_hex": "..."
  },
  "group_id": "..."
}
```

**Implementation note**: The new `devnet-keygen` (in Step 29) generates this JSON **plus** optionally creates secrets.bin file. The JSON output format is unchanged.

### Environment Variable Reference

For completeness, here are all environment variables the scripts use:

#### Secrets (picked up by EnvSecretStore)

```bash
# Legacy (still supported)
export KASPA_IGRA_WALLET_SECRET="devnet-secret"

# New style (also works)
export IGRA_SECRET__igra_hd__wallet_secret="devnet-secret"
```

#### Configuration (unchanged)

```bash
export KASPA_CONFIG_PATH="/path/to/igra-config.toml"
export KASPA_DATA_DIR="/path/to/data"
export KASPA_NODE_URL="grpc://127.0.0.1:16110"
export KASPA_IGRA_PROFILE="signer-1"
export IGRA_RPC_URL="http://127.0.0.1:8088/rpc"
export HYPERLANE_KEYS_PATH="/path/to/hyperlane-keys.json"
```

### Validation Checklist for Script Compatibility

Before merging Phase 1, verify:

- [ ] `run_local_devnet.sh default` completes successfully
- [ ] `run_local_devnet.sh start all` starts all services
- [ ] `run_local_devnet.sh status` shows all processes running
- [ ] `run_local_devnet.sh generate-keys` regenerates keys
- [ ] `run_local_devnet_with_avail_and_hyperlane.sh default` completes
- [ ] `run_local_devnet_with_avail_and_hyperlane.sh send` dispatches messages
- [ ] `run_rothschild.sh --to <addr>` sends transactions
- [ ] devnet-keys.json has correct structure
- [ ] hyperlane-keys.json is read correctly
- [ ] Audit log shows secret access from EnvSecretStore
- [ ] No errors in service logs about missing secrets

### Optional: Explicit New-Style Env Vars

If you want to **also** support new-style env vars in scripts (optional, for consistency):

```bash
# In run_local_devnet.sh, add alongside existing KASPA_IGRA_WALLET_SECRET:

# Export both legacy and new-style (for forward compatibility)
export KASPA_IGRA_WALLET_SECRET="${KASPA_IGRA_WALLET_SECRET:-devnet-secret}"
export IGRA_SECRET__igra_hd__wallet_secret="${KASPA_IGRA_WALLET_SECRET}"
```

But this is **NOT required** - the legacy env var works fine.

---

## Summary: Script Compatibility

### What Works Automatically

✅ **All three scripts work without changes**
✅ **Environment variable `KASPA_IGRA_WALLET_SECRET` still works**
✅ **devnet-keygen output format unchanged**
✅ **JSON files (devnet-keys.json, hyperlane-keys.json) unchanged**
✅ **EnvSecretStore automatically detects devnet mode**

### What You Need to Implement

1. **EnvSecretStore legacy compatibility** (read `KASPA_IGRA_WALLET_SECRET`)
2. **Service startup auto-detection** (use EnvSecretStore when env var present)
3. **devnet-keygen maintains JSON output** (while adding secrets.bin support)

### What Your Team Should Test

1. Run all three scripts through their full flows
2. Verify audit logs show EnvSecretStore usage
3. Confirm no secret leakage in logs
4. Check that services start successfully

**After these tests pass, you're done!** The scripts work exactly as before, with KeyManager silently managing secrets behind the scenes.

---


---

## Complete Inventory of Cryptographic Material

This section lists **every piece** of secret and public key material in the Igra system.

### SECRET MATERIAL (Stored in KeyManager)

These are **private** and must be protected by KeyManager's SecretStore.

#### 1. HD Wallet System

| Secret Name | Type | Size | Purpose | Current Location | New Location |
|-------------|------|------|---------|------------------|--------------|
| `igra.hd.wallet_secret` | AES-256 key | 32 bytes | Encrypts HD mnemonics at rest | env var `KASPA_IGRA_WALLET_SECRET` | KeyManager SecretStore |
| `igra.hd.payment_secret` | BIP39 passphrase | UTF-8 string | BIP39 passphrase for HD derivation | **plaintext in config** ⚠️ | KeyManager SecretStore |
| `igra.hd.mnemonic_signer_1` | BIP39 mnemonic | 24 words | Signer-1 HD wallet seed | Encrypted in config | KeyManager SecretStore |
| `igra.hd.mnemonic_signer_2` | BIP39 mnemonic | 24 words | Signer-2 HD wallet seed | Encrypted in config | KeyManager SecretStore |
| `igra.hd.mnemonic_signer_3` | BIP39 mnemonic | 24 words | Signer-3 HD wallet seed | Encrypted in config | KeyManager SecretStore |
| `igra.wallet.mnemonic` | BIP39 mnemonic | 24 words | Mining/funding wallet seed | devnet-keys.json (plaintext) | KeyManager SecretStore |

**Notes**:
- HD mnemonics are currently stored **encrypted** in `igra-config.toml` using `wallet_secret`
- After refactor, mnemonics will be stored **encrypted** in `secrets.bin` (FileSecretStore) or as env vars (EnvSecretStore)
- `payment_secret` is currently **plaintext in config** - **HIGH PRIORITY to fix**

#### 2. Network Identity (Iroh)

| Secret Name | Type | Size | Purpose | Current Location | New Location |
|-------------|------|------|---------|------------------|--------------|
| `igra.iroh.signer_seed_signer_1` | Ed25519 seed | 32 bytes | Signer-1 network identity | config `iroh.signer_seed_hex` | KeyManager SecretStore |
| `igra.iroh.signer_seed_signer_2` | Ed25519 seed | 32 bytes | Signer-2 network identity | config `iroh.signer_seed_hex` | KeyManager SecretStore |
| `igra.iroh.signer_seed_signer_3` | Ed25519 seed | 32 bytes | Signer-3 network identity | config `iroh.signer_seed_hex` | KeyManager SecretStore |

**Notes**:
- Currently stored as hex strings in config files (per profile)
- Used for peer-to-peer authentication in CRDT gossip network
- Each signer has unique Ed25519 identity

#### 3. Hyperlane Integration

| Secret Name | Type | Size | Purpose | Current Location | New Location |
|-------------|------|------|---------|------------------|--------------|
| `igra.hyperlane.validator_1_key` | secp256k1 ECDSA | 32 bytes | Validator-1 checkpoint signing | hyperlane-keys.json (plaintext) | KeyManager SecretStore |
| `igra.hyperlane.validator_2_key` | secp256k1 ECDSA | 32 bytes | Validator-2 checkpoint signing | hyperlane-keys.json (plaintext) | KeyManager SecretStore |
| `igra.hyperlane.evm_key` | secp256k1 ECDSA | 32 bytes | EVM transactions (Anvil) | devnet-keys.json (plaintext) | KeyManager SecretStore |

**Notes**:
- Hyperlane validators sign message checkpoints with ECDSA
- EVM key used for deploying contracts and funding on Anvil (devnet only)
- Currently stored as **plaintext hex** in JSON files

#### 4. Development/Testing Keys (Devnet Only)

| Secret Name | Type | Size | Purpose | Current Location | New Location |
|-------------|------|------|---------|------------------|--------------|
| `igra.devnet.wallet_private_key` | secp256k1 Schnorr | 32 bytes | Funding wallet for devnet | devnet-keys.json `wallet.private_key_hex` | EnvSecretStore only |
| `igra.devnet.rothschild_key` | secp256k1 Schnorr | 32 bytes | Transaction load testing | Same as wallet key | EnvSecretStore only |

**Notes**:
- **Devnet/testing ONLY** - not for production
- Used by rothschild for load testing
- Can remain in devnet-keys.json for convenience (devnet only)

---

### PUBLIC KEYS (NOT in KeyManager)

These are **public** and stored in configuration files. KeyManager does NOT store these.

#### Multisig Public Keys

| Public Key | Type | Size | Purpose | Stored In |
|------------|------|------|---------|-----------|
| `member_pubkeys[0]` | secp256k1 compressed | 33 bytes | Signer-1 multisig pubkey | igra-config.toml |
| `member_pubkeys[1]` | secp256k1 compressed | 33 bytes | Signer-2 multisig pubkey | igra-config.toml |
| `member_pubkeys[2]` | secp256k1 compressed | 33 bytes | Signer-3 multisig pubkey | igra-config.toml |

**Notes**:
- These are **x-only (32-byte)** Schnorr pubkeys in current implementation
- Stored in `group.member_pubkeys` array in config
- Used for multisig address construction and PSKT validation

#### Hyperlane Validator Public Keys

| Public Key | Type | Size | Purpose | Stored In |
|------------|------|------|---------|-----------|
| `hyperlane.validators[0]` | secp256k1 compressed | 33 bytes | Validator-1 checkpoint verification | igra-config.toml |
| `hyperlane.validators[1]` | secp256k1 compressed | 33 bytes | Validator-2 checkpoint verification | igra-config.toml |

**Notes**:
- Stored as hex strings in config `hyperlane.validators` array
- Used for verifying incoming Hyperlane message signatures
- NOT secret material - safe to store in plaintext config

#### Addresses & Scripts (Derived Public Data)

| Item | Type | Purpose | Stored In |
|------|------|---------|-----------|
| `multisig_address` | Kaspa address | Multisig P2SH address | igra-config.toml |
| `redeem_script_hex` | Script | Multisig redeem script | igra-config.toml |
| `source_addresses[]` | Kaspa addresses | Individual signer addresses | devnet-keys.json (devnet) |
| `mining_address` | Kaspa address | Coinbase rewards destination | devnet-keys.json (devnet) |

---

### EPHEMERAL KEYS (Not Persisted)

These are generated on-demand and **never stored** on disk.

#### HD Derived Keys

| Key | Type | Lifetime | Purpose |
|-----|------|----------|---------|
| HD-derived keypair | secp256k1 | Single signing operation | PSKT signing (from mnemonic + derivation path) |
| Change addresses | Kaspa addresses | Session/transaction | Derived during transaction building |

**Notes**:
- Derived from mnemonic + derivation path (e.g., `m/45'/111111'/0'/0/0`)
- Created in memory, used for signing, immediately zeroized
- Protected by `SecretPanicGuard` during operations

#### Session/Temporary Keys

| Key | Type | Lifetime | Purpose |
|-----|------|----------|---------|
| Signing keypair temp | secp256k1 | Milliseconds | Converted to secp256k1 types for signing |
| SIGHASH buffers | [u8; 32] | Microseconds | Transaction hash for signing |

---

### SECRET MATERIAL SUMMARY BY ENVIRONMENT

#### Production Deployment

Stored in **FileSecretStore** (`secrets.bin` encrypted with Argon2id + XChaCha20-Poly1305):

```
secrets.bin contains:
├── igra.hd.wallet_secret (32 bytes)
├── igra.hd.payment_secret (string)
├── igra.hd.mnemonic_signer_1 (24 words)
├── igra.hd.mnemonic_signer_2 (24 words)
├── igra.hd.mnemonic_signer_3 (24 words)
├── igra.iroh.signer_seed_signer_1 (32 bytes)
├── igra.iroh.signer_seed_signer_2 (32 bytes)
├── igra.iroh.signer_seed_signer_3 (32 bytes)
├── igra.hyperlane.validator_1_key (32 bytes)
└── igra.hyperlane.validator_2_key (32 bytes)
```

**Total**: 10 secrets per deployment

#### Devnet Deployment

Stored in **EnvSecretStore** (environment variables):

```bash
# HD Wallet
export IGRA_SECRET__igra_hd__wallet_secret="devnet-secret"
export IGRA_SECRET__igra_hd__payment_secret="optional_passphrase"
export IGRA_SECRET__igra_hd__mnemonic_signer_1="word1 word2 ..."
export IGRA_SECRET__igra_hd__mnemonic_signer_2="word1 word2 ..."
export IGRA_SECRET__igra_hd__mnemonic_signer_3="word1 word2 ..."

# Iroh Identity
export IGRA_SECRET__igra_iroh__signer_seed_signer_1="hex:65a408b4..."
export IGRA_SECRET__igra_iroh__signer_seed_signer_2="hex:c34061c0..."
export IGRA_SECRET__igra_iroh__signer_seed_signer_3="hex:a951310c..."

# Hyperlane (devnet only)
export IGRA_SECRET__igra_hyperlane__validator_1_key="hex:3ce2c6ad..."
export IGRA_SECRET__igra_hyperlane__validator_2_key="hex:31211525..."
export IGRA_SECRET__igra_hyperlane__evm_key="hex:..."

# Devnet funding wallet
export IGRA_SECRET__igra_devnet__wallet_private_key="hex:..."
```

**Or legacy format** (backwards compatible):

```bash
export KASPA_IGRA_WALLET_SECRET="devnet-secret"
# (other secrets in devnet-keys.json for convenience)
```

---

### SECRET NAMING CONVENTION

All secret names follow this pattern:

```
igra.<namespace>.<key_id>[_<profile>]
```

Examples:
- `igra.hd.wallet_secret` - Global HD wallet encryption key
- `igra.hd.mnemonic_signer_1` - Profile-specific mnemonic
- `igra.iroh.signer_seed_signer_2` - Profile-specific Iroh seed
- `igra.hyperlane.validator_1_key` - Validator key (numbered)

**Environment variable format**:
```
IGRA_SECRET__<namespace>__<key_id>[__<profile>]
```

Examples:
- `IGRA_SECRET__igra_hd__wallet_secret`
- `IGRA_SECRET__igra_hd__mnemonic_signer_1`
- `IGRA_SECRET__igra_iroh__signer_seed_signer_2`

---

### MIGRATION CHECKLIST: Secrets to Move

#### Phase 1A: Critical Secrets (Week 3)

- [ ] Move `KASPA_IGRA_WALLET_SECRET` to KeyManager (with backwards compat)
- [ ] Move `hd.passphrase` from config to KeyManager (**security fix**)
- [ ] Keep encrypted mnemonics in config (already encrypted)
- [ ] Add wallet_secret loading via KeyManager

#### Phase 1B: Network Identity (Week 3)

- [ ] Move `iroh.signer_seed_hex` to KeyManager (per profile)
- [ ] Update Iroh identity setup to load from KeyManager

#### Phase 1C: Hyperlane Keys (Week 3)

- [ ] Move validator keys from hyperlane-keys.json to KeyManager
- [ ] Update validator private key loading in fake binaries

#### Phase 1D: Devnet Keys (Week 4)

- [ ] Keep devnet-keys.json for convenience (devnet only)
- [ ] Update devnet-keygen to output both JSON and secrets.bin

---

### SECURITY NOTES

#### Sensitive Material (NEVER log, NEVER commit)

⚠️ **CRITICAL - These must NEVER appear in logs or git history**:

1. HD mnemonics (24 words)
2. Private keys (any format: hex, bytes, WIF)
3. Seeds (Ed25519, secp256k1)
4. Payment secrets / passphrases
5. Wallet secret (encryption key)

#### Safe to Log/Commit

✅ **Safe for logs and version control**:

1. Public keys (all formats)
2. Addresses (Kaspa, EVM)
3. Redeem scripts
4. Group IDs
5. Configuration (without secrets)

#### Current Security Issues (Fixed by KeyManager)

1. ❌ Payment secret in plaintext config → ✅ Encrypted in secrets.bin
2. ❌ Iroh seed in plaintext config → ✅ Encrypted in secrets.bin
3. ❌ Hyperlane validator keys in plaintext JSON → ✅ Encrypted in secrets.bin
4. ❌ No audit trail for secret access → ✅ Full audit logging
5. ❌ No memory protection → ✅ mlock + zeroization

---

### KEY LIFECYCLE

#### Creation (Initial Setup)

1. **Production**:
   ```bash
   # Generate all secrets
   cargo run --bin igra-keygen -- \
     --format file \
     --output ./secrets.bin \
     --passphrase "<strong-passphrase>"
   
   # secrets.bin now contains all 10 secrets
   chmod 600 secrets.bin
   ```

2. **Devnet**:
   ```bash
   # Generate devnet keys (JSON + optional secrets.bin)
   cargo run --bin devnet-keygen
   
   # Sets environment variables OR creates secrets.bin
   ```

#### Usage (Runtime)

1. **Service starts** → Loads KeyManager
2. **KeyManager opens SecretStore** (file or env)
3. **Secrets loaded into memory** (protected by Secrecy + mlock)
4. **Operations request keys** via KeyRef
5. **Signing occurs** → secret material used briefly
6. **Immediate zeroization** after use

#### Rotation (Future - Phase 2)

1. Generate new secret with version
2. Re-encrypt data with new secret
3. Update KeyManager to recognize both versions
4. Deprecate old version after transition period

---

### TOTAL SECRET INVENTORY

| Environment | Secrets Count | Storage | Encryption |
|-------------|---------------|---------|------------|
| **Production (single signer)** | 5 | secrets.bin | Argon2id + XChaCha20 |
| **Production (3 signers)** | 10 | secrets.bin | Argon2id + XChaCha20 |
| **Devnet (3 signers + Hyperlane)** | 13 | env vars | None (ephemeral) |

**Production breakdown** (3 signers):
- 1 wallet secret
- 1 payment secret (optional, can be empty)
- 3 HD mnemonics
- 3 Iroh seeds
- 2 Hyperlane validator keys

**Devnet adds**:
- 1 EVM private key
- 1 funding wallet key
- 1 rothschild key (same as funding)

---

