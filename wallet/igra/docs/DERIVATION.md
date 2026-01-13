# DERIVATION.md

HD key derivation design and required refactoring.

---

## Policy

**Default behavior: NO derivation paths. Use root keys directly.**

Derivation paths are an optional feature for advanced use cases, not the default.

---

## Current State (WRONG)

### Problem 1: Validation forces derivation path

`infrastructure/config/validation.rs:131-134`:
```rust
if self.signing.backend == "threshold" {
    let derivation_path = hd.derivation_path.as_deref().unwrap_or("").trim();
    if derivation_path.is_empty() {
        errors.push("service.hd.derivation_path is required for threshold signing".to_string());
    }
}
```

**This is wrong.** Empty/missing `derivation_path` should mean "use root key", not "config error".

### Problem 2: Code assumes derivation path exists

`application/event_processor.rs:249-252`:
```rust
let derivation_path = hd
    .derivation_path
    .as_deref()
    .ok_or_else(|| ThresholdError::ConfigError("missing hd.derivation_path".to_string()))?;
```

`application/event_processor.rs:290-292`:
```rust
hd.derivation_path
    .as_deref()
    .ok_or_else(|| ThresholdError::ConfigError("missing hd.derivation_path".to_string()))?
```

**This is wrong.** Should handle `None` as "use root key".

### Problem 3: Unused `derivation_index` field

`infrastructure/config/types.rs:44`:
```rust
pub derivation_index: Option<u32>,
```

This field exists but is never used anywhere. Either use it or delete it.

### Problem 4: `derivation_path_from_index()` is unused in production

`foundation/hd.rs:104-106`:
```rust
pub fn derivation_path_from_index(index: u32) -> String {
    format!("m/45'/111111'/0'/0/{}", index)
}
```

Only used in `devnet-keygen.rs` binary, never in actual signing flow.

---

## Required Changes

### 1. Fix `derive_pubkeys()` to handle no derivation

`foundation/hd.rs:51-73`

**Current:**
```rust
pub fn derive_pubkeys(inputs: HdInputs<'_>) -> Result<Vec<PublicKey>, ThresholdError> {
    let path = DerivationPath::from_str(inputs.derivation_path)  // FAILS if empty
        .map_err(|err| ThresholdError::Message(err.to_string()))?;
    // ... derives using path
}
```

**Should be:**
```rust
pub fn derive_pubkeys(inputs: HdInputs<'_>) -> Result<Vec<PublicKey>, ThresholdError> {
    let path: Option<DerivationPath> = match inputs.derivation_path {
        "" | "m" => None,  // No derivation, use root
        p => Some(DerivationPath::from_str(p)
            .map_err(|err| ThresholdError::InvalidDerivationPath(err.to_string()))?),
    };

    for key_data in inputs.key_data {
        let xprv = key_data.get_xprv(inputs.payment_secret)?;
        let derived = match &path {
            Some(p) => xprv.derive_path(p)?,
            None => xprv,  // Use root directly
        };
        pubkeys.push(derived.private_key().get_public_key());
    }
    // ... same for xpubs
}
```

### 2. Fix `derive_keypair_from_key_data()` to handle no derivation

`foundation/hd.rs:75-91`

**Current:**
```rust
pub fn derive_keypair_from_key_data(
    key_data: &PrvKeyData,
    derivation_path: &str,  // Required
    payment_secret: Option<&Secret>,
) -> Result<SigningKeypair, ThresholdError>
```

**Should be:**
```rust
pub fn derive_keypair_from_key_data(
    key_data: &PrvKeyData,
    derivation_path: Option<&str>,  // Optional
    payment_secret: Option<&Secret>,
) -> Result<SigningKeypair, ThresholdError> {
    let xprv = key_data.get_xprv(payment_secret)?;
    let derived = match derivation_path {
        Some(p) if !p.is_empty() && p != "m" => xprv.derive_path(&DerivationPath::from_str(p)?)?,
        _ => xprv,  // Use root
    };
    // ... rest
}
```

### 3. Fix `HdInputs` struct

`foundation/hd.rs:10-15`

**Current:**
```rust
pub struct HdInputs<'a> {
    pub key_data: &'a [PrvKeyData],
    pub xpubs: &'a [String],
    pub derivation_path: &'a str,  // Required
    pub payment_secret: Option<&'a Secret>,
}
```

**Should be:**
```rust
pub struct HdInputs<'a> {
    pub key_data: &'a [PrvKeyData],
    pub xpubs: &'a [String],
    pub derivation_path: Option<&'a str>,  // Optional
    pub payment_secret: Option<&'a Secret>,
}
```

### 4. Remove validation error for missing derivation path

`infrastructure/config/validation.rs:131-134`

**Delete these lines:**
```rust
let derivation_path = hd.derivation_path.as_deref().unwrap_or("").trim();
if derivation_path.is_empty() {
    errors.push("service.hd.derivation_path is required for threshold signing".to_string());
}
```

### 5. Fix callers in event_processor.rs

`application/event_processor.rs:249-253`

**Current:**
```rust
let derivation_path = hd
    .derivation_path
    .as_deref()
    .ok_or_else(|| ThresholdError::ConfigError("missing hd.derivation_path".to_string()))?;
pskt.redeem_script_hex = derive_redeem_script_hex(hd, derivation_path)?;
```

**Should be:**
```rust
pskt.redeem_script_hex = derive_redeem_script_hex(hd, hd.derivation_path.as_deref())?;
```

`application/event_processor.rs:288-294`

**Current:**
```rust
let signing_keypair = crate::foundation::hd::derive_keypair_from_key_data(
    signing_key_data,
    hd.derivation_path
        .as_deref()
        .ok_or_else(|| ThresholdError::ConfigError("missing hd.derivation_path".to_string()))?,
    payment_secret.as_ref(),
)?;
```

**Should be:**
```rust
let signing_keypair = crate::foundation::hd::derive_keypair_from_key_data(
    signing_key_data,
    hd.derivation_path.as_deref(),
    payment_secret.as_ref(),
)?;
```

### 6. Fix `derive_redeem_script_hex()` signature

`infrastructure/config/mod.rs:22`

**Current:**
```rust
pub fn derive_redeem_script_hex(hd: &PsktHdConfig, derivation_path: &str) -> Result<String, ThresholdError>
```

**Should be:**
```rust
pub fn derive_redeem_script_hex(hd: &PsktHdConfig, derivation_path: Option<&str>) -> Result<String, ThresholdError>
```

### 7. Decide on `derivation_index`

`infrastructure/config/types.rs:44`

**Option A: Delete it**
```rust
// DELETE:
pub derivation_index: Option<u32>,
```

**Option B: Use it as shorthand**
```rust
// In derive functions, if derivation_path is None but derivation_index is Some:
let path = derivation_index.map(derivation_path_from_index);
```

**Recommendation:** Delete it. One way to specify derivation is enough.

---

## Files to Modify

| File | Change |
|------|--------|
| `foundation/hd.rs` | Make `derivation_path` optional in structs and functions |
| `infrastructure/config/validation.rs` | Remove derivation_path requirement |
| `infrastructure/config/mod.rs` | Update `derive_redeem_script_hex()` signature |
| `infrastructure/config/types.rs` | Delete `derivation_index` field |
| `application/event_processor.rs` | Remove `.ok_or_else()` error on missing path |

---

## Test Cases

After refactoring, these must work:

```toml
# Case 1: No derivation (DEFAULT) - use root keys
[service.hd]
mnemonics_encrypted = ["..."]
required_sigs = 2
# derivation_path NOT specified

# Case 2: Explicit root
[service.hd]
mnemonics_encrypted = ["..."]
required_sigs = 2
derivation_path = "m"

# Case 3: With derivation (advanced)
[service.hd]
mnemonics_encrypted = ["..."]
required_sigs = 2
derivation_path = "m/45'/111111'/0'/0/0"
```

---

## Summary

| What | Current | Should Be |
|------|---------|-----------|
| `derivation_path` | Required | Optional (None = root key) |
| `derivation_index` | Exists, unused | Delete |
| Empty path handling | Error | Use root key |
| Default behavior | Must specify path | No derivation |

---

*Generated: 2025-01-13*
