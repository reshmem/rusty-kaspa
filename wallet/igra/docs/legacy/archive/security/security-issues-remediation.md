# IGRA KEY MANAGEMENT - SECURITY ISSUES REMEDIATION GUIDE

**Document:** Resolution guide for all PARTIAL and VIOLATION findings
**Source Audit:** docs/security/key-management-extended-audit.md
**Date:** 2026-01-24
**Status:** Implementation roadmap

---

## EXECUTIVE SUMMARY

This document provides **actionable fixes** for all security issues identified in the key management audit. Issues are prioritized by severity and deployment timeline.

### Quick Status:
- 🔴 **1 CRITICAL** violation (must fix before mainnet)
- 🟠 **4 MEDIUM** issues (3 before mainnet, 1 for v1.1)
- 🟡 **2 LOW** issues (document now, fix in v2.0+)

---

## PRIORITY MATRIX

| Issue | Severity | Effort | Fix By | Blocker? |
|-------|----------|--------|--------|----------|
| EnvSecretStore unrestricted | 🔴 CRITICAL | 1 day | **BEFORE MAINNET** | YES |
| payment_secret optional | 🟠 HIGH | 1 day | **BEFORE MAINNET** | YES |
| Password strength validation | 🟡 MEDIUM | 2-3 days | **BEFORE MAINNET** | Recommended |
| Audit log permissions | 🟠 MEDIUM | 1 day | v1.1 | No |
| Cache TTL | 🟠 MEDIUM | 3-4 days | v1.1 | No |
| Key rotation | 🟡 MEDIUM | 2-3 weeks | v2.0 | No |
| OWASP MASVS features | 🟡 LOW | Months | Future | No |

---

## 🔴 CRITICAL FIXES (MUST DO BEFORE MAINNET)

### 1. Restrict EnvSecretStore to DevNet Only

**File:** `igra-core/src/infrastructure/keys/backends/env_secret_store.rs`

**Issue:** CWE-311 - Plaintext secrets via environment variables visible to all processes

**Current Code:**
```rust
// PROBLEM: Always available in all builds
pub struct EnvSecretStore { ... }
impl EnvSecretStore {
    pub fn new() -> Self { ... }
}
```

**Fix (Option A - Compile-Time, Recommended):**
```rust
// Only compile in test/devnet builds
#[cfg(any(test, feature = "devnet-env-secrets"))]
pub struct EnvSecretStore {
    cache: HashMap<SecretName, SecretBytes>,
}

#[cfg(any(test, feature = "devnet-env-secrets"))]
impl EnvSecretStore {
    pub fn new() -> Self {
        // ... existing implementation
    }
}

#[cfg(any(test, feature = "devnet-env-secrets"))]
impl Default for EnvSecretStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "devnet-env-secrets"))]
impl SecretStore for EnvSecretStore {
    // ... existing implementation
}
```

**Fix (Option B - Runtime Validation, Alternative):**
```rust
impl EnvSecretStore {
    pub fn new(network_mode: NetworkMode) -> Result<Self, ThresholdError> {
        match network_mode {
            NetworkMode::Mainnet => {
                return Err(ThresholdError::ConfigError(
                    "EnvSecretStore is forbidden in mainnet mode. \
                     Use FileSecretStore with encrypted secrets.bin file.".to_string()
                ));
            }
            NetworkMode::Testnet => {
                log::warn!(
                    "⚠️  SECURITY WARNING: Using EnvSecretStore in testnet. \
                     Secrets visible in process environment. \
                     Not recommended for staging/production-like environments."
                );
            }
            NetworkMode::Devnet => {
                log::info!("EnvSecretStore enabled for devnet (development only)");
            }
        }

        // ... existing implementation
        Ok(Self { cache })
    }
}
```

**Integration Point:**
```rust
// In service initialization (igra-service/src/main.rs or similar)
let secret_store: Arc<dyn SecretStore> = match config.network_mode {
    NetworkMode::Mainnet => {
        // ENFORCE FileSecretStore only
        if env::var("IGRA_SECRET__").is_ok() {
            return Err("Mainnet detected environment variable secrets. \
                        Use encrypted secrets.bin file only.");
        }
        Arc::new(FileSecretStore::open(&config.secrets_path, &passphrase).await?)
    }
    NetworkMode::Testnet => {
        if config.use_env_secrets {
            log::warn!("⚠️  Testnet using environment secrets");
            Arc::new(EnvSecretStore::new())
        } else {
            Arc::new(FileSecretStore::open(&config.secrets_path, &passphrase).await?)
        }
    }
    NetworkMode::Devnet => {
        if config.use_env_secrets {
            Arc::new(EnvSecretStore::new())
        } else {
            Arc::new(FileSecretStore::open(&config.secrets_path, &passphrase).await?)
        }
    }
};
```

**Testing:**
```bash
# Should fail with error
IGRA_SECRET__test__key="value" cargo run --release -- --mainnet

# Should succeed
cargo run --release -- --devnet
```

**Estimated Effort:** 1 day (implementation + testing)
**Status:** BLOCKING for mainnet deployment

---

### 2. Require payment_secret for Mainnet

**File:** `igra-core/src/application/pskt_signing.rs`

**Issue:** Optional BIP39 passphrase = single layer of protection

**Current Code (Line 59, 125-138):**
```rust
let payment_secret = load_payment_secret_optional(key_context).await?;
// payment_secret may be None - only wallet_secret protects mnemonics

pub async fn load_payment_secret_optional(key_context: &KeyManagerContext)
    -> Result<Option<Secret>, ThresholdError>
{
    let name = SecretName::new("igra.hd.payment_secret");
    let secret_bytes = match key_context.get_secret_with_audit(&name).await {
        Ok(bytes) => bytes,
        Err(ThresholdError::SecretNotFound { .. }) => return Ok(None),  // PROBLEM
        Err(err) => return Err(err),
    };
    // ...
}
```

**Fix:**
```rust
pub async fn load_payment_secret_optional(
    key_context: &KeyManagerContext,
    network_mode: NetworkMode,
) -> Result<Option<Secret>, ThresholdError> {
    let name = SecretName::new("igra.hd.payment_secret");

    match key_context.get_secret_with_audit(&name).await {
        Ok(bytes) if !bytes.expose_secret().is_empty() => {
            let value = String::from_utf8(bytes.expose_owned())
                .map_err(|err| ThresholdError::secret_decode_failed(
                    name.to_string(),
                    "utf8",
                    format!("invalid UTF-8: {}", err)
                ))?;
            Ok(Some(Secret::from(value)))
        }
        Ok(_) | Err(ThresholdError::SecretNotFound { .. }) => {
            // Empty or missing payment_secret
            match network_mode {
                NetworkMode::Mainnet => {
                    // ENFORCE: payment_secret is REQUIRED
                    return Err(ThresholdError::ConfigError(
                        "Mainnet requires payment_secret for mnemonic encryption. \n\
                         \n\
                         This provides two-layer protection:\n\
                         1. wallet_secret encrypts mnemonic storage\n\
                         2. payment_secret protects seed derivation\n\
                         \n\
                         Set igra.hd.payment_secret in your secrets file:\n\
                         secrets-admin set secrets.bin <passphrase> igra.hd.payment_secret <your-bip39-passphrase>".to_string()
                    ));
                }
                NetworkMode::Testnet => {
                    log::warn!(
                        "⚠️  SECURITY WARNING: payment_secret not configured for testnet.\n\
                         Mnemonics are protected by wallet_secret only (single layer).\n\
                         For staging/production-like environments, set igra.hd.payment_secret."
                    );
                }
                NetworkMode::Devnet => {
                    log::debug!("payment_secret not set (devnet mode - single layer protection)");
                }
            }
            Ok(None)
        }
        Err(err) => Err(err),
    }
}
```

**Update Call Sites:**
```rust
// In sign_pskt_with_hd_config (line 59)
let payment_secret = load_payment_secret_optional(
    key_context,
    network_mode  // ADD THIS PARAMETER
).await?;
```

**Pass network_mode through call chain:**
```rust
pub async fn sign_pskt_with_service_config(
    service: &ServiceConfig,
    key_context: &KeyManagerContext,
    pskt: PSKT<Signer>,
    ctx: PsktSigningContext<'_>,
    network_mode: NetworkMode,  // ADD
) -> Result<SignPsktResult, ThresholdError> {
    let hd = service.hd.as_ref().ok_or_else(||
        ThresholdError::ConfigError("missing HD config".to_string())
    )?;
    sign_pskt_with_hd_config(hd, key_context, pskt, ctx, network_mode).await  // PASS
}
```

**Documentation Update:**

Create: `docs/MAINNET-SECRETS-REQUIREMENTS.md`
```markdown
# Mainnet Secret Requirements

## Required Secrets

### 1. igra.hd.wallet_secret (Layer 1)
- **Purpose:** Encrypts mnemonic storage in config
- **Type:** UTF-8 password
- **Minimum Strength:** zxcvbn score 4/4
- **Storage:** secrets.bin (FileSecretStore)

### 2. igra.hd.payment_secret (Layer 2)
- **Purpose:** BIP39 passphrase for seed derivation
- **Type:** UTF-8 string (any characters)
- **Minimum Length:** 12 characters recommended
- **Storage:** secrets.bin (FileSecretStore)

## Defense-in-Depth Rationale

Two-layer protection ensures:
- Compromise of wallet_secret alone → Cannot derive keys (needs payment_secret)
- Compromise of payment_secret alone → Cannot decrypt mnemonics (needs wallet_secret)
- Both secrets required for complete key recovery

## Setup Instructions

```bash
# Create encrypted secrets file
secrets-admin init secrets.bin

# Set wallet secret (Layer 1)
secrets-admin set secrets.bin <file-passphrase> \
    igra.hd.wallet_secret <strong-password>

# Set payment secret (Layer 2)
secrets-admin set secrets.bin <file-passphrase> \
    igra.hd.payment_secret <bip39-passphrase>

# Verify
secrets-admin list secrets.bin <file-passphrase>
```
```

**Estimated Effort:** 1 day
**Status:** BLOCKING for mainnet deployment

---

## 🟡 HIGH-PRIORITY FIXES (RECOMMENDED BEFORE MAINNET)

### 3. Password Strength Validation

**File:** `igra-core/src/infrastructure/keys/backends/file_secret_store.rs`

**Issue:** CWE-522, NIST SP 800-63B - No password complexity enforcement

**Add Dependency:**
```toml
# In igra-core/Cargo.toml
[dependencies]
zxcvbn = "2.2"
```

**Implementation:**
```rust
// Add to file_secret_store.rs
use zxcvbn::zxcvbn;

fn validate_passphrase_strength(
    passphrase: &str,
    network_mode: NetworkMode
) -> Result<(), ThresholdError> {
    let (min_length, min_score) = match network_mode {
        NetworkMode::Mainnet => (16, 4),  // Very strong, 16+ chars
        NetworkMode::Testnet => (12, 3),  // Strong, 12+ chars
        NetworkMode::Devnet => return Ok(()),  // No requirement
    };

    if passphrase.len() < min_length {
        return Err(ThresholdError::ConfigError(
            format!(
                "{} passphrase must be at least {} characters (got {})",
                network_mode, min_length, passphrase.len()
            )
        ));
    }

    let entropy = zxcvbn(passphrase, &[])
        .map_err(|e| ThresholdError::ConfigError(
            format!("Password strength check failed: {}", e)
        ))?;

    if entropy.score() < min_score {
        let feedback = entropy.feedback()
            .and_then(|f| f.warning())
            .unwrap_or("Use a longer, more complex passphrase");

        let message = format!(
            "Passphrase too weak for {} (score: {}/4).\n\
             \n\
             Feedback: {}\n\
             \n\
             Requirements:\n\
             - Minimum {} characters\n\
             - Mix of uppercase, lowercase, numbers, symbols\n\
             - Avoid common words and patterns\n\
             - Consider using a passphrase (4+ random words)",
            network_mode,
            entropy.score(),
            feedback,
            min_length
        );

        match network_mode {
            NetworkMode::Mainnet => {
                return Err(ThresholdError::ConfigError(message));
            }
            NetworkMode::Testnet => {
                log::warn!("⚠️  {}", message);
            }
            NetworkMode::Devnet => {}
        }
    }

    Ok(())
}

// Update FileSecretStore::create()
pub async fn create(
    path: impl AsRef<Path>,
    passphrase: &str,
    network_mode: NetworkMode,
) -> Result<Self, ThresholdError> {
    let path = path.as_ref();

    // Validate passphrase strength
    validate_passphrase_strength(passphrase, network_mode)?;

    if path.exists() {
        return Err(ThresholdError::secret_store_unavailable(
            "file",
            format!("Secrets file already exists: {}", path.display())
        ));
    }

    // ... rest of existing implementation
}

// Also validate in open() for additional safety
pub async fn open(
    path: impl AsRef<Path>,
    passphrase: &str,
    network_mode: NetworkMode,
) -> Result<Self, ThresholdError> {
    let path = path.as_ref();

    // Validate on open (for existing files created with weak passwords)
    if network_mode == NetworkMode::Mainnet {
        validate_passphrase_strength(passphrase, network_mode)?;
    }

    // ... rest of existing implementation
}
```

**Update secrets-admin:**
```rust
// In src/bin/secrets-admin.rs
match command.as_str() {
    "init" => {
        // ... existing arg parsing ...

        // Add network mode detection or flag
        let network_mode = NetworkMode::from_env_or_default();

        println!("Creating secrets file: {}", file_path);
        if network_mode == NetworkMode::Mainnet {
            println!("Mainnet mode: Passphrase must be 16+ characters, score 4/4");
        }

        FileSecretStore::create(file_path, &passphrase, network_mode).await?;
        println!("✓ Secrets file created successfully");
    }
    // ...
}
```

**User Experience:**
```bash
$ secrets-admin init secrets.bin
Creating secrets file: secrets.bin
Mainnet mode: Passphrase must be 16+ characters, score 4/4
Enter passphrase: password123
Error: Passphrase too weak for Mainnet (score: 1/4).

Feedback: This is a common password

Requirements:
- Minimum 16 characters
- Mix of uppercase, lowercase, numbers, symbols
- Avoid common words and patterns
- Consider using a passphrase (4+ random words)

$ secrets-admin init secrets.bin
Enter passphrase: CorrectHorseBatteryStaple2024!
✓ Secrets file created successfully
```

**Estimated Effort:** 2-3 days
**Status:** RECOMMENDED before mainnet (improves security posture)

---

## 🟠 MEDIUM-PRIORITY FIXES (Version 1.1)

### 4. Audit Log File Permissions

**File:** `igra-core/src/infrastructure/keys/audit.rs`

**Issue:** Audit logs may be world-readable, leaking metadata

**Implementation:**
```rust
pub struct FileAuditLogger {
    file: Arc<Mutex<File>>,
    log_path: PathBuf,
}

impl FileAuditLogger {
    pub async fn new(log_path: impl AsRef<Path>) -> Result<Self, ThresholdError> {
        let log_path = log_path.as_ref();

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .map_err(|e| ThresholdError::secret_store_unavailable(
                "audit_log",
                format!("Failed to open audit log: {}", e)
            ))?;

        // Enforce secure permissions (Unix only)
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()
                .map_err(|e| ThresholdError::secret_store_unavailable(
                    "audit_log",
                    format!("Failed to stat audit log: {}", e)
                ))?
                .permissions();

            perms.set_mode(0o600);
            std::fs::set_permissions(log_path, perms)
                .map_err(|e| ThresholdError::InsecureFilePermissions {
                    path: log_path.display().to_string(),
                    mode: perms.mode() & 0o777,
                })?;

            log::info!("✓ Audit log permissions set to 0600: {}", log_path.display());
        }

        #[cfg(not(target_family = "unix"))]
        {
            log::warn!("⚠️  Audit log permission enforcement not available on this platform");
        }

        let logger = Self {
            file: Arc::new(Mutex::new(file)),
            log_path: log_path.to_path_buf(),
        };

        // Start periodic validation
        logger.spawn_permission_validator();

        Ok(logger)
    }

    fn spawn_permission_validator(&self) {
        let path = self.log_path.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Every hour

            loop {
                interval.tick().await;

                #[cfg(target_family = "unix")]
                {
                    use std::os::unix::fs::PermissionsExt;

                    match std::fs::metadata(&path) {
                        Ok(metadata) => {
                            let mode = metadata.permissions().mode() & 0o777;
                            if mode != 0o600 {
                                log::error!(
                                    "🔴 SECURITY ALERT: Audit log permissions changed!\n\
                                     Expected: 0600 (owner read/write only)\n\
                                     Actual:   {:o}\n\
                                     Path:     {}\n\
                                     \n\
                                     This may indicate tampering or misconfiguration.",
                                    mode,
                                    path.display()
                                );
                            }
                        }
                        Err(e) => {
                            log::error!(
                                "Failed to validate audit log permissions: {} (path: {})",
                                e,
                                path.display()
                            );
                        }
                    }
                }
            }
        });
    }
}
```

**Estimated Effort:** 1 day
**Status:** Target for v1.1 release

---

### 5. Secret Cache TTL

**File:** `igra-core/src/infrastructure/keys/backends/file_secret_store.rs`

**Issue:** Secrets persist in RAM indefinitely

**Implementation:**
```rust
use std::time::{Duration, Instant};

struct CachedSecret {
    value: SecretBytes,
    loaded_at: Instant,
}

pub struct FileSecretStore {
    file_path: PathBuf,
    passphrase: SecretBytes,  // Store encrypted passphrase for reload
    cache: Arc<RwLock<HashMap<SecretName, CachedSecret>>>,
    cache_ttl: Duration,
    kdf_params: Argon2Params,
}

impl FileSecretStore {
    pub async fn open(
        path: impl AsRef<Path>,
        passphrase: &str,
        cache_ttl: Option<Duration>,
    ) -> Result<Self, ThresholdError> {
        let cache_ttl = cache_ttl.unwrap_or(Duration::from_secs(300)); // 5 min default
        let path = path.as_ref();

        #[cfg(target_family = "unix")]
        Self::validate_file_permissions(path)?;

        let data = tokio::fs::read(path)
            .await
            .map_err(|e| ThresholdError::secret_store_unavailable(
                "file",
                format!("Failed to read secrets file: {}", e)
            ))?;

        let file = SecretFile::from_bytes(&data)?;
        let mut secret_map = file.decrypt(passphrase)?;

        let mut cache = HashMap::new();
        let now = Instant::now();
        for (name, bytes) in secret_map.secrets.drain() {
            cache.insert(name, CachedSecret {
                value: SecretBytes::new(bytes),
                loaded_at: now,
            });
        }

        log::info!("Loaded {} secrets from {} (TTL: {:?})", cache.len(), path.display(), cache_ttl);

        let store = Self {
            file_path: path.to_path_buf(),
            passphrase: SecretBytes::new(passphrase.as_bytes().to_vec()),
            cache: Arc::new(RwLock::new(cache)),
            cache_ttl,
            kdf_params: file.kdf_params,
        };

        // Start background cleanup task
        store.spawn_cleanup_task();

        Ok(store)
    }

    fn spawn_cleanup_task(&self) {
        let cache = self.cache.clone();
        let ttl = self.cache_ttl;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                let mut cache = cache.write().await;
                let now = Instant::now();
                let initial_count = cache.len();

                cache.retain(|name, cached| {
                    let age = now.duration_since(cached.loaded_at);
                    let expired = age > ttl;

                    if expired {
                        log::debug!("Evicting expired secret from cache: {} (age: {:?})", name, age);
                    }

                    !expired
                });

                let evicted = initial_count - cache.len();
                if evicted > 0 {
                    log::info!("Cache cleanup: evicted {} expired secrets", evicted);
                }
            }
        });
    }

    async fn reload_secret(&self, name: &SecretName) -> Result<SecretBytes, ThresholdError> {
        log::debug!("Reloading secret from encrypted file: {}", name);

        // Read entire file again
        let data = tokio::fs::read(&self.file_path).await
            .map_err(|e| ThresholdError::secret_store_unavailable(
                "file",
                format!("Failed to reload secrets: {}", e)
            ))?;

        let file = SecretFile::from_bytes(&data)?;
        let passphrase = std::str::from_utf8(self.passphrase.expose_secret())
            .map_err(|_| ThresholdError::secret_decode_failed(
                "passphrase", "utf8", "Invalid UTF-8"
            ))?;
        let secret_map = file.decrypt(passphrase)?;

        // Update cache with fresh value
        if let Some(bytes) = secret_map.secrets.get(name) {
            let secret = SecretBytes::new(bytes.clone());
            let mut cache = self.cache.write().await;
            cache.insert(name.clone(), CachedSecret {
                value: secret.clone(),
                loaded_at: Instant::now(),
            });
            Ok(secret)
        } else {
            Err(ThresholdError::secret_not_found(name.as_str(), "file"))
        }
    }
}

impl SecretStore for FileSecretStore {
    fn backend(&self) -> &'static str {
        "file"
    }

    fn get<'a>(&'a self, name: &'a SecretName)
        -> Pin<Box<dyn Future<Output = Result<SecretBytes, ThresholdError>> + Send + 'a>>
    {
        Box::pin(async move {
            // Check cache first
            {
                let cache = self.cache.read().await;
                if let Some(cached) = cache.get(name) {
                    let age = Instant::now().duration_since(cached.loaded_at);
                    if age < self.cache_ttl {
                        log::trace!("Cache hit for {} (age: {:?})", name, age);
                        return Ok(cached.value.clone());
                    }
                    log::debug!("Cache expired for {} (age: {:?} > TTL: {:?})", name, age, self.cache_ttl);
                }
            }

            // Cache miss or expired - reload
            self.reload_secret(name).await
        })
    }

    fn list_secrets<'a>(&'a self)
        -> Pin<Box<dyn Future<Output = Result<Vec<SecretName>, ThresholdError>> + Send + 'a>>
    {
        Box::pin(async move {
            let cache = self.cache.read().await;
            Ok(cache.keys().cloned().collect())
        })
    }
}
```

**Configuration:**
```toml
# In config.toml
[security]
# Secret cache TTL in seconds (default: 300 = 5 minutes)
# Set to 0 to disable caching (most secure, higher I/O)
secret_cache_ttl = 300
```

**Estimated Effort:** 3-4 days
**Status:** Target for v1.1 release

---

## 🟡 LOW-PRIORITY ISSUES (Future Versions)

### 6. Key Rotation Support

**Issue:** No automated key rotation mechanism

**Resolution Strategy:**

**Phase 1 (v1.0): Document Manual Process**

Create: `docs/KEY_ROTATION_MANUAL.md`
```markdown
# Manual Key Rotation Procedure

## When to Rotate
- Suspected key compromise
- Scheduled rotation policy (e.g., annually)
- Personnel changes (signer leaves organization)
- Security incident response

## Procedure

### Step 1: Generate New Keys
```bash
devnet-keygen \
    --threshold-m 2 \
    --threshold-n 3 \
    --kaspa-network mainnet \
    --output-format file \
    --output-file new-secrets.bin \
    --passphrase <strong-passphrase>
```

### Step 2: Create Migration Multisig
- Use 2M-of-(N+N) threshold with old + new keys
- Example: 2-of-3 becomes 4-of-6 during migration
- This allows either old OR new signers to approve

### Step 3: Coordinate Fund Migration
1. Deploy new coordinator configs with migration address
2. Sweep funds from old multisig to migration address
3. Verify all funds transferred
4. Update configs to new multisig only
5. Sweep from migration to new address

### Step 4: Decommission Old Keys
1. Backup old secrets.bin (encrypted, offline)
2. Update all signers with new secrets files
3. Restart all services
4. Monitor for 48 hours
5. Archive old keys securely

## Coordination Checklist
- [ ] All N signers notified of rotation
- [ ] Migration schedule agreed upon
- [ ] New secrets files generated and distributed securely
- [ ] Configs updated on all nodes
- [ ] Old multisig address has zero balance
- [ ] New multisig address operational
- [ ] Old secrets archived/destroyed per policy
```

**Phase 2 (v1.5): Implement Key Versioning**
```rust
// Already exists in types.rs:
pub struct KeyRef {
    pub namespace: &'static str,
    pub key_id: String,
    pub version: Option<u32>,  // USE THIS!
}

// Add versioning support to KeyManager
impl LocalKeyManager {
    pub async fn rotate_key(&self, old_ref: &KeyRef) -> Result<KeyRef, ThresholdError> {
        // 1. Generate new key (same namespace/id, version N+1)
        // 2. Store new key alongside old
        // 3. Return new KeyRef with incremented version
        todo!("Implement in v1.5")
    }

    pub async fn list_key_versions(&self, namespace: &str, key_id: &str)
        -> Result<Vec<u32>, ThresholdError>
    {
        // List all versions of a key
        todo!("Implement in v1.5")
    }
}
```

**Phase 3 (v2.0): Automated Rotation**
- API endpoints for rotation initiation
- Coordinator orchestration of multi-signer rotation
- Automatic migration multisig creation
- Fund sweeping automation

**Estimated Effort:** 2-3 weeks (full automation)
**Status:** v1.0 = document, v1.5 = versioning, v2.0 = automation

---

### 7. OWASP MASVS Features

**Issue:** Missing biometric protection, key attestation, secure enclave

**Resolution Strategy:**

These are **advanced security features** that require platform-specific APIs and significant engineering effort.

**For v1.0:**
```markdown
# In docs/security/key-management-extended-audit.md

## Known Limitations

The following OWASP MASVS features are not currently implemented:

1. **Biometric Protection**: No TouchID/FaceID/fingerprint integration
   - **Mitigation**: Use strong passphrases (16+ characters, score 4/4)
   - **Roadmap**: Not planned for v1.0-v2.0

2. **Hardware Key Attestation**: No TPM/SGX attestation
   - **Mitigation**: Rely on file permissions + encryption
   - **Roadmap**: v3.0 (if user demand exists)

3. **Secure Enclave Integration**:
   - macOS: No Keychain/Secure Enclave support
   - Linux: No TPM 2.0 integration
   - **Mitigation**: FileSecretStore with strong encryption
   - **Roadmap**: v3.0+ (platform-specific implementations)

These features would provide marginal security improvements over current
XChaCha20-Poly1305 + Argon2id implementation, and are not critical for
production deployments. Priority is low unless regulatory requirements demand them.
```

**For v3.0+ (if needed):**
```rust
// Create platform-specific backends

#[cfg(target_os = "macos")]
pub struct KeychainSecretStore {
    // Use Security.framework APIs
    // Store secrets in macOS Keychain (encrypted by OS)
}

#[cfg(target_os = "linux")]
pub struct TpmSecretStore {
    // Use tpm2-tss libraries
    // Seal secrets to TPM 2.0
}

#[cfg(windows)]
pub struct DpapiSecretStore {
    // Use Windows DPAPI
    // CryptProtectData / CryptUnprotectData
}
```

**Estimated Effort:** 2-3 months per platform
**Status:** Document limitation for v1.0, implement only if required

---

## TESTING CHECKLIST

### Before Mainnet Deployment

**Critical Fixes:**
- [ ] EnvSecretStore disabled in mainnet builds
  - [ ] Unit test: `#[cfg(test)]` only compiles EnvSecretStore
  - [ ] Integration test: Mainnet config rejects env secrets

- [ ] payment_secret required for mainnet
  - [ ] Unit test: Mainnet without payment_secret returns error
  - [ ] Integration test: Full signing flow with payment_secret

- [ ] Password strength validation
  - [ ] Unit test: Weak passwords rejected for mainnet
  - [ ] Unit test: Strong passwords accepted
  - [ ] Manual test: secrets-admin with various passwords

**Security Validation:**
- [ ] File permissions enforced (0o600)
  - [ ] Test: secrets.bin created with correct permissions
  - [ ] Test: Audit log created with correct permissions

- [ ] Encryption roundtrip
  - [ ] Test: Encrypt → decrypt → verify secrets intact
  - [ ] Test: Wrong passphrase fails decryption

- [ ] Network mode enforcement
  - [ ] Test: Mainnet config with devnet address rejected
  - [ ] Test: payment_secret optional in devnet, required in mainnet

**Stress Testing:**
- [ ] Long-running process (24 hours+)
- [ ] Cache expiration behavior (if TTL implemented)
- [ ] Memory leak detection (valgrind/heaptrack)
- [ ] Zeroization verification (memory dumps)

---

## DEPLOYMENT GUIDE

### Pre-Deployment

1. **Code Changes:**
   ```bash
   # Apply critical fixes
   git checkout -b security-fixes-mainnet

   # Implement fixes #1, #2, #3 from this document
   # Run tests
   cargo test --release

   # Create PR
   git push origin security-fixes-mainnet
   ```

2. **Configuration Validation:**
   ```bash
   # Run network mode validator
   igra-service validate-config --config config.toml --network mainnet

   # Expected output:
   # ✓ Network mode: mainnet
   # ✓ Encrypted secrets: enabled
   # ✓ payment_secret: configured
   # ✓ Audit logging: enabled
   # ✓ RPC endpoint: localhost
   ```

3. **Secrets Preparation:**
   ```bash
   # Create mainnet secrets file
   secrets-admin init mainnet-secrets.bin
   # (Enter strong passphrase: 16+ chars, score 4/4)

   # Set required secrets
   secrets-admin set mainnet-secrets.bin <passphrase> \
       igra.hd.wallet_secret <layer1-password>

   secrets-admin set mainnet-secrets.bin <passphrase> \
       igra.hd.payment_secret <layer2-password>

   # Verify
   secrets-admin list mainnet-secrets.bin <passphrase>
   # Expected:
   # - igra.hd.wallet_secret
   # - igra.hd.payment_secret
   ```

4. **File Permissions:**
   ```bash
   chmod 600 mainnet-secrets.bin
   chmod 600 /var/log/igra/key-audit.log

   # Verify
   ls -l mainnet-secrets.bin
   # Expected: -rw------- (600)
   ```

### Post-Deployment Monitoring

1. **Audit Log Review:**
   ```bash
   # Check for unusual activity
   tail -f /var/log/igra/key-audit.log | jq '
     select(.event_type == "SecretAccess" or .event_type == "Signing")
   '
   ```

2. **Security Alerts:**
   ```bash
   # Monitor for security warnings
   journalctl -u igra -f | grep -E "SECURITY|WARNING"
   ```

3. **Performance Metrics:**
   ```bash
   # Monitor signing latency
   cat key-audit.log | jq '
     select(.event_type == "Signing") | .duration_ms
   ' | jq -s 'add/length'
   ```

---

## REFERENCE

### Related Documents
- `docs/security/key-management-extended-audit.md` - Full security audit
- `docs/config/network-modes.md` - Network mode security model
- `docs/security/key-management-audit.md` - General Kaspa wallet audit

### Code Locations
- Secrets: `igra-core/src/infrastructure/keys/`
- Signing: `igra-core/src/application/pskt_signing.rs`
- Config: `igra-core/src/infrastructure/config/`

### Contact
- Security issues: security@igra.local
- Questions: #igra-dev channel

---

**Document Version:** 1.0
**Last Updated:** 2026-01-24
**Next Review:** After mainnet deployment
