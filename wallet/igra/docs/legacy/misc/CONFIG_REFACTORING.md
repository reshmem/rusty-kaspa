# Configuration System Refactoring Guide

This document provides a comprehensive guide for migrating the igra configuration system from INI to TOML format.

---

## Table of Contents

1. [Overview](#overview)
2. [Current State](#current-state)
3. [Target State](#target-state)
4. [Migration Plan](#migration-plan)
5. [Code Changes](#code-changes)
6. [Config File Conversion](#config-file-conversion)
7. [Profile Handling](#profile-handling)
8. [Devnet Config Generator](#devnet-config-generator)
9. [Testing Strategy](#testing-strategy)
10. [Rollback Plan](#rollback-plan)
11. [Checklist](#checklist)

---

## Overview

### Why Migrate?

| Aspect | INI (Current) | TOML + Figment (Target) |
|--------|---------------|-------------------------|
| Parsing | ~500 lines manual code | ~30 lines via figment |
| Nested structures | Manual handling | Native support |
| Arrays | Comma-separated strings | Native `["a", "b"]` |
| Type safety | Manual parsing | Automatic via serde |
| Maintenance | High (every field change needs code) | Low (structs only) |
| Comments | `;` (non-standard) | `#` (standard) |
| Env overrides | 2 hardcoded fields | All fields via `IGRA_*` |
| Config merging | Manual `merge_from` impls | Automatic layering |
| Profile support | Manual section parsing | Built-in profiles |

### Estimated Effort

| Task | Effort |
|------|--------|
| Code changes (loader, types) | 2-3 hours |
| Config file conversion | 1-2 hours |
| Devnet generator script migration | 2-3 hours |
| Test updates | 1-2 hours |
| Documentation | 1 hour |
| Testing & validation | 2-3 hours |
| **Total** | **9-14 hours** |

---

## Current State

### Config Files

```
artifacts/igra-config.ini          # Dev/test config with 3 signer profiles
artifacts/igra-prod.ini            # Production template
orchestration/devnet/igra-devnet.ini  # Docker devnet config
```

### Devnet Config Generator Script

```
orchestration/devnet/scripts/update_devnet_config.py  # Generates config from keygen output
```

This script takes an INI template and fills in generated keys/addresses from `devnet-keygen`. It performs line-by-line INI processing and needs to be migrated to output TOML.

### Code Files (~1,500 lines total)

```
igra-core/src/infrastructure/config/
├── mod.rs              # Module exports (~50 lines)
├── types.rs            # Structs + merge_from (~409 lines)
├── loader.rs           # INI/TOML parsing (~602 lines)  <- REMOVE MOST
├── loader_unified.rs   # Layered loading (~100 lines)
├── validation.rs       # Config validation (~92 lines)
├── encryption.rs       # Mnemonic encryption (~54 lines)
├── persistence.rs      # RocksDB storage (~79 lines)
└── env.rs              # Environment vars (~89 lines)
```

### INI Features Currently Used

1. **Standard sections**: `[service]`, `[pskt]`, `[runtime]`, etc.
2. **Profile sections**: `[signer-1.service]`, `[signer-2.hd]`, etc.
3. **Dynamic sections**: `[hyperlane.domain.42]` for per-domain ISM config
4. **CSV values**: `source_addresses = addr1,addr2,addr3`
5. **Comments**: `; comment`

---

## Target State

### TOML + Figment Advantages

```toml
# Native arrays (no parsing needed)
source_addresses = ["addr1", "addr2", "addr3"]

# Native nested tables
[service.pskt]
sig_op_count = 2

# Array of tables for dynamic configs
[[hyperlane.domains]]
domain = 42
validators = ["0xabc", "0xdef"]
threshold = 2
```

**Figment provides:**
- **Layered config**: defaults → file → environment (automatic merging)
- **Environment overrides**: `IGRA_SERVICE__NODE_RPC_URL` → `service.node_rpc_url`
- **Profile support**: `Figment::from(Profile::new("signer-1"))`
- **Type-safe extraction**: validates against struct definitions

### Code After Refactoring (~500 lines removed)

```
igra-core/src/infrastructure/config/
├── mod.rs              # Module exports (~30 lines)   <- SIMPLIFIED
├── types.rs            # Structs only (~200 lines)    <- NO merge_from
├── loader.rs           # Figment loader (~50 lines)   <- DRASTICALLY SIMPLIFIED
├── validation.rs       # Config validation (~92 lines)
├── encryption.rs       # Mnemonic encryption (~54 lines)
└── persistence.rs      # RocksDB storage (~79 lines)
```

**Removed files:**
- `loader_unified.rs` - figment handles layering
- `env.rs` - figment handles env vars automatically

---

## Migration Plan

### Phase 1: Add TOML Configs (Non-Breaking)

Create TOML equivalents alongside existing INI files. Both formats work during this phase.

**Duration**: 1-2 hours

1. Create `artifacts/igra-config.toml`
2. Create `artifacts/igra-prod.toml`
3. Create `orchestration/devnet/igra-devnet.toml`
4. Verify both formats load correctly

### Phase 2: Simplify Code

Remove INI-specific code while keeping TOML support.

**Duration**: 2-3 hours

1. Remove manual INI parsing functions from `loader.rs`
2. Remove `merge_from` implementations from `types.rs`
3. Update `loader_unified.rs` to use TOML-only path
4. Update `env.rs` default config filename

### Phase 3: Update Tests & Documentation

**Duration**: 2-3 hours

1. Update `igra-core/tests/integration/config_loading.rs`
2. Update integration tests in `igra-service/tests/`
3. Update `docs/service/README.md`
4. Update orchestration scripts

### Phase 4: Remove INI Files

**Duration**: 30 minutes

1. Delete old INI files
2. Update `.gitignore` if needed
3. Final verification

---

## Code Changes

### 5.1 Simplify `types.rs`

**Remove all `merge_from` implementations** (~160 lines).

TOML with serde handles merging via `#[serde(default)]` - no manual merge needed.

```rust
// BEFORE: types.rs had 9 merge_from implementations
impl ServiceConfig {
    fn merge_from(&mut self, other: &ServiceConfig) {
        if !other.node_rpc_url.trim().is_empty() {
            self.node_rpc_url = other.node_rpc_url.clone();
        }
        // ... 20+ more lines per struct
    }
}

// AFTER: Just the struct definitions with serde attributes
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServiceConfig {
    #[serde(default)]
    pub node_rpc_url: String,
    #[serde(default)]
    pub data_dir: String,
    #[serde(default)]
    pub pskt: PsktBuildConfig,
    #[serde(default)]
    pub hd: Option<PsktHdConfig>,
}
```

**File**: `igra-core/src/infrastructure/config/types.rs`

**Lines to remove**: 195-380 (all `impl ... { fn merge_from }` blocks)

---

### 5.2 Add Figment Dependency

**File**: `igra-core/Cargo.toml`

```toml
[dependencies]
figment = { version = "0.10", features = ["toml", "env"] }
```

---

### 5.3 Rewrite `loader.rs` with Figment

Replace ~600 lines with ~60 lines.

**File**: `igra-core/src/infrastructure/config/loader.rs`

```rust
//! Configuration loader using Figment for layered config management.
//!
//! Precedence (lowest to highest):
//! 1. Compiled defaults
//! 2. TOML config file
//! 3. Environment variables (IGRA_* prefix)

use crate::foundation::ThresholdError;
use crate::infrastructure::config::types::AppConfig;
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment, Profile,
};
use std::path::Path;
use tracing::{debug, info};

/// Environment variable prefix for config overrides.
/// Example: IGRA_SERVICE__NODE_RPC_URL -> service.node_rpc_url
const ENV_PREFIX: &str = "IGRA_";

/// Load configuration with full layering: defaults -> file -> env.
pub fn load_config(data_dir: &Path) -> Result<AppConfig, ThresholdError> {
    let config_path = data_dir.join("igra-config.toml");

    info!(
        config_path = %config_path.display(),
        data_dir = %data_dir.display(),
        "loading configuration"
    );

    let figment = Figment::new()
        // Layer 1: Compiled defaults
        .merge(Serialized::defaults(AppConfig::default()))
        // Layer 2: TOML config file (if exists)
        .merge(Toml::file(&config_path).nested())
        // Layer 3: Environment variables with IGRA_ prefix
        // IGRA_SERVICE__NODE_RPC_URL -> service.node_rpc_url
        .merge(Env::prefixed(ENV_PREFIX).split("__"));

    let mut config: AppConfig = figment.extract().map_err(|e| {
        ThresholdError::ConfigError(format!("config extraction failed: {}", e))
    })?;

    // Apply data_dir if not set
    if config.service.data_dir.is_empty() {
        config.service.data_dir = data_dir.to_string_lossy().to_string();
    }

    // Cascade node_rpc_url to pskt if not set
    if config.service.pskt.node_rpc_url.is_empty() {
        config.service.pskt.node_rpc_url = config.service.node_rpc_url.clone();
    }

    debug!(
        node_rpc_url = %redact_url(&config.service.node_rpc_url),
        rpc_addr = %config.rpc.addr,
        rpc_enabled = config.rpc.enabled,
        "configuration loaded"
    );

    Ok(config)
}

/// Load configuration with a specific profile (e.g., "signer-1").
///
/// Profile sections in TOML override base config:
/// ```toml
/// [service]
/// data_dir = "/base"
///
/// [profiles.signer-1.service]
/// data_dir = "/signer-1"  # This wins when profile="signer-1"
/// ```
pub fn load_config_with_profile(data_dir: &Path, profile: &str) -> Result<AppConfig, ThresholdError> {
    let config_path = data_dir.join("igra-config.toml");

    info!(
        config_path = %config_path.display(),
        profile = %profile,
        "loading configuration with profile"
    );

    let figment = Figment::new()
        // Layer 1: Compiled defaults
        .merge(Serialized::defaults(AppConfig::default()))
        // Layer 2: TOML config file
        .merge(Toml::file(&config_path).nested())
        // Layer 3: Profile-specific overrides from [profiles.<name>] section
        .select(Profile::new(profile))
        // Layer 4: Environment variables (highest priority)
        .merge(Env::prefixed(ENV_PREFIX).split("__"));

    let mut config: AppConfig = figment.extract().map_err(|e| {
        ThresholdError::ConfigError(format!("config extraction failed for profile '{}': {}", profile, e))
    })?;

    // Apply data_dir if not set
    if config.service.data_dir.is_empty() {
        config.service.data_dir = data_dir.to_string_lossy().to_string();
    }

    // Cascade node_rpc_url to pskt if not set
    if config.service.pskt.node_rpc_url.is_empty() {
        config.service.pskt.node_rpc_url = config.service.node_rpc_url.clone();
    }

    debug!(
        profile = %profile,
        node_rpc_url = %redact_url(&config.service.node_rpc_url),
        rpc_addr = %config.rpc.addr,
        "configuration loaded with profile"
    );

    Ok(config)
}

/// Load configuration from a specific file path.
pub fn load_config_from_file(path: &Path, data_dir: &Path) -> Result<AppConfig, ThresholdError> {
    info!(path = %path.display(), "loading configuration from file");

    let figment = Figment::new()
        .merge(Serialized::defaults(AppConfig::default()))
        .merge(Toml::file(path).nested())
        .merge(Env::prefixed(ENV_PREFIX).split("__"));

    let mut config: AppConfig = figment.extract().map_err(|e| {
        ThresholdError::ConfigError(format!("config extraction failed: {}", e))
    })?;

    if config.service.data_dir.is_empty() {
        config.service.data_dir = data_dir.to_string_lossy().to_string();
    }

    Ok(config)
}

fn redact_url(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let (scheme, rest) = url.split_at(scheme_end + 3);
        if let Some(at) = rest.find('@') {
            return format!("{scheme}<redacted>@{}", &rest[at + 1..]);
        }
    }
    url.to_string()
}
```

---

### 5.4 Update `types.rs` for Figment

Add figment's `Provider` derive for profile support.

**File**: `igra-core/src/infrastructure/config/types.rs`

```rust
// Add to imports
use figment::value::{Dict, Map};

// Update AppConfig to support figment profiles
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub service: ServiceConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub signing: SigningConfig,
    #[serde(default)]
    pub rpc: RpcConfig,
    #[serde(default)]
    pub policy: GroupPolicy,
    #[serde(default)]
    pub group: Option<GroupConfig>,
    #[serde(default)]
    pub hyperlane: HyperlaneConfig,
    #[serde(default)]
    pub layerzero: LayerZeroConfig,
    #[serde(default)]
    pub iroh: IrohRuntimeConfig,

    /// Profile overrides - not used directly, processed by figment
    #[serde(default, skip_serializing)]
    pub profiles: Option<Map<String, Dict>>,
}
```

**Remove all `merge_from` implementations** - figment handles merging automatically.

---

### 5.5 Update `mod.rs`

Simplify exports - remove env.rs and loader_unified.rs.

**File**: `igra-core/src/infrastructure/config/mod.rs`

```rust
mod encryption;
mod loader;
mod persistence;
mod types;
mod validation;

pub use loader::{load_config, load_config_from_file, load_config_with_profile};
pub use types::*;

use crate::foundation::ThresholdError;
use std::path::Path;

/// Environment variable for wallet secret (still needed for HD encryption).
pub const HD_WALLET_SECRET_ENV: &str = "KASPA_IGRA_WALLET_SECRET";

/// Load app config from default location.
pub fn load_app_config() -> Result<AppConfig, ThresholdError> {
    let data_dir = resolve_data_dir()?;
    let config = load_config(&data_dir)?;
    config.validate().map_err(|errors| {
        ThresholdError::ConfigError(format!("validation failed: {:?}", errors))
    })?;
    Ok(config)
}

/// Load app config with a specific profile.
pub fn load_app_config_with_profile(profile: &str) -> Result<AppConfig, ThresholdError> {
    let data_dir = resolve_data_dir()?;
    let config = load_config_with_profile(&data_dir, profile)?;
    config.validate().map_err(|errors| {
        ThresholdError::ConfigError(format!("validation failed: {:?}", errors))
    })?;
    Ok(config)
}

fn resolve_data_dir() -> Result<std::path::PathBuf, ThresholdError> {
    // Check KASPA_DATA_DIR env var first
    if let Ok(dir) = std::env::var("KASPA_DATA_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return Ok(std::path::PathBuf::from(trimmed));
        }
    }
    // Default to .igra in current directory
    let cwd = std::env::current_dir()
        .map_err(|e| ThresholdError::Message(e.to_string()))?;
    Ok(cwd.join(".igra"))
}
```

---

### 5.6 Delete Obsolete Files

Remove these files (figment replaces their functionality):

```bash
rm igra-core/src/infrastructure/config/env.rs
rm igra-core/src/infrastructure/config/loader_unified.rs
```

---

### 5.7 Environment Variable Reference

With figment, ALL config fields can be overridden via environment variables:

| Config Field | Environment Variable |
|--------------|---------------------|
| `service.node_rpc_url` | `IGRA_SERVICE__NODE_RPC_URL` |
| `service.data_dir` | `IGRA_SERVICE__DATA_DIR` |
| `service.pskt.sig_op_count` | `IGRA_SERVICE__PSKT__SIG_OP_COUNT` |
| `rpc.addr` | `IGRA_RPC__ADDR` |
| `rpc.enabled` | `IGRA_RPC__ENABLED` |
| `runtime.test_mode` | `IGRA_RUNTIME__TEST_MODE` |
| `hyperlane.threshold` | `IGRA_HYPERLANE__THRESHOLD` |
| `iroh.peer_id` | `IGRA_IROH__PEER_ID` |
| `iroh.network_id` | `IGRA_IROH__NETWORK_ID` |

**Pattern**: `IGRA_<SECTION>__<FIELD>` (double underscore for nesting)

---

## Config File Conversion

### 6.1 Syntax Changes

| INI | TOML |
|-----|------|
| `; comment` | `# comment` |
| `key = value` | `key = "value"` (strings need quotes) |
| `key = a,b,c` | `key = ["a", "b", "c"]` |
| `[section]` | `[section]` (same) |
| `[profile.section]` | `[profiles.profile.section]` |

### 6.2 Conversion Script

Create `scripts/convert-ini-to-toml.py`:

```python
#!/usr/bin/env python3
"""
Convert igra INI config files to TOML format.

Usage:
    python scripts/convert-ini-to-toml.py artifacts/igra-config.ini

Outputs:
    artifacts/igra-config.toml
"""

import sys
import re
from pathlib import Path
from configparser import ConfigParser
from collections import defaultdict

def parse_ini_with_profiles(ini_path: Path) -> tuple[dict, dict]:
    """Parse INI file, separating base config from profiles."""
    config = ConfigParser(allow_no_value=True, interpolation=None)
    config.read(ini_path)

    base = defaultdict(dict)
    profiles = defaultdict(lambda: defaultdict(dict))

    for section in config.sections():
        # Check if this is a profile section (e.g., signer-1.service)
        match = re.match(r'^([^.]+)\.(.+)$', section)
        if match and match.group(1) not in ['hyperlane', 'service']:
            profile_name = match.group(1)
            subsection = match.group(2)
            for key, value in config.items(section):
                profiles[profile_name][subsection][key] = value
        else:
            for key, value in config.items(section):
                base[section][key] = value

    return dict(base), dict(profiles)

def convert_value(key: str, value: str) -> str:
    """Convert INI value to TOML value."""
    if value is None:
        return '""'

    value = value.strip()

    # Boolean conversion
    if value.lower() in ('true', 'yes', 'on', '1'):
        return 'true'
    if value.lower() in ('false', 'no', 'off', '0'):
        return 'false'

    # Numeric conversion
    try:
        int(value)
        return value
    except ValueError:
        pass

    # Array fields (comma-separated)
    array_fields = [
        'source_addresses', 'validators', 'member_pubkeys', 'verifier_keys',
        'endpoint_pubkeys', 'xpubs', 'mnemonics', 'allowed_destinations',
        'bootstrap', 'bootstrap_addrs', 'outputs'
    ]

    if key in array_fields and ',' in value:
        items = [item.strip() for item in value.split(',') if item.strip()]
        quoted = [f'"{item}"' for item in items]
        return f'[{", ".join(quoted)}]'

    # String (needs quotes)
    # Escape any internal quotes
    escaped = value.replace('\\', '\\\\').replace('"', '\\"')
    return f'"{escaped}"'

def section_to_toml(section_name: str, items: dict, indent: int = 0) -> list[str]:
    """Convert a section to TOML lines."""
    lines = []
    prefix = "    " * indent

    # Handle nested sections
    if '.' in section_name:
        parts = section_name.split('.')
        lines.append(f'{prefix}[{".".join(parts)}]')
    else:
        lines.append(f'{prefix}[{section_name}]')

    for key, value in items.items():
        toml_value = convert_value(key, value)
        lines.append(f'{prefix}{key} = {toml_value}')

    lines.append('')
    return lines

def convert_hyperlane_domains(base: dict) -> list[str]:
    """Convert hyperlane.domain.N sections to [[hyperlane.domains]] array."""
    lines = []
    domains = []

    for section_name in list(base.keys()):
        match = re.match(r'^hyperlane\.domain\.(\d+)$', section_name)
        if match:
            domain_id = match.group(1)
            domain_config = base.pop(section_name)
            domains.append((int(domain_id), domain_config))

    for domain_id, config in sorted(domains):
        lines.append('[[hyperlane.domains]]')
        lines.append(f'domain = {domain_id}')
        for key, value in config.items():
            toml_value = convert_value(key, value)
            lines.append(f'{key} = {toml_value}')
        lines.append('')

    return lines

def generate_toml(base: dict, profiles: dict) -> str:
    """Generate TOML content from parsed config."""
    lines = [
        '# Igra Configuration',
        '# Converted from INI format',
        '# See CONFIG_REFACTORING.md for migration details',
        '',
    ]

    # Define section order
    section_order = [
        'service', 'service.pskt', 'service.hd',
        'runtime', 'signing', 'rpc', 'policy', 'group',
        'hyperlane', 'layerzero', 'iroh'
    ]

    # Write base sections in order
    written = set()
    for section in section_order:
        if section in base:
            lines.extend(section_to_toml(section, base[section]))
            written.add(section)

    # Write hyperlane domains
    lines.extend(convert_hyperlane_domains(base))

    # Write remaining sections
    for section in base:
        if section not in written and not section.startswith('hyperlane.domain.'):
            lines.extend(section_to_toml(section, base[section]))

    # Write profiles
    if profiles:
        lines.append('# =============================================================================')
        lines.append('# Signer Profiles')
        lines.append('# Use --profile <name> to load a specific profile')
        lines.append('# =============================================================================')
        lines.append('')

        for profile_name in sorted(profiles.keys()):
            profile_sections = profiles[profile_name]
            lines.append(f'[profiles.{profile_name}]')
            lines.append('')

            for subsection, items in profile_sections.items():
                lines.append(f'[profiles.{profile_name}.{subsection}]')
                for key, value in items.items():
                    toml_value = convert_value(key, value)
                    lines.append(f'{key} = {toml_value}')
                lines.append('')

    return '\n'.join(lines)

def main():
    if len(sys.argv) < 2:
        print("Usage: python convert-ini-to-toml.py <input.ini> [output.toml]")
        sys.exit(1)

    ini_path = Path(sys.argv[1])
    if not ini_path.exists():
        print(f"Error: {ini_path} not found")
        sys.exit(1)

    toml_path = Path(sys.argv[2]) if len(sys.argv) > 2 else ini_path.with_suffix('.toml')

    print(f"Converting {ini_path} -> {toml_path}")

    base, profiles = parse_ini_with_profiles(ini_path)
    toml_content = generate_toml(base, profiles)

    toml_path.write_text(toml_content)
    print(f"Written {toml_path}")
    print(f"  Base sections: {len(base)}")
    print(f"  Profiles: {list(profiles.keys())}")

if __name__ == '__main__':
    main()
```

Make executable:
```bash
chmod +x scripts/convert-ini-to-toml.py
```

### 6.3 Manual Conversion Examples

#### Basic Section

```ini
; INI
[service]
node_rpc_url = grpc://127.0.0.1:16110
data_dir = ./.igra
```

```toml
# TOML
[service]
node_rpc_url = "grpc://127.0.0.1:16110"
data_dir = "./.igra"
```

#### Arrays

```ini
; INI
[pskt]
source_addresses = kaspadev:qzjw...,kaspadev:qpjf...
```

```toml
# TOML
[service.pskt]
source_addresses = [
    "kaspadev:qzjw...",
    "kaspadev:qpjf..."
]
```

#### Hyperlane Domains

```ini
; INI - Dynamic sections
[hyperlane.domain.42]
validators = 0xabc,0xdef
threshold = 2
mode = message_id_multisig

[hyperlane.domain.137]
validators = 0x123
threshold = 1
```

```toml
# TOML - Array of tables
[[hyperlane.domains]]
domain = 42
validators = ["0xabc", "0xdef"]
threshold = 2
mode = "message_id_multisig"

[[hyperlane.domains]]
domain = 137
validators = ["0x123"]
threshold = 1
```

---

## Profile Handling

### 7.1 INI Profile Structure (Current)

```ini
[service]
node_rpc_url = grpc://127.0.0.1:16110

[signer-1.service]
data_dir = ./.igra/signer-1

[signer-1.hd]
mnemonics = abandon abandon ...

[signer-1.iroh]
peer_id = signer-1
```

### 7.2 TOML Profile Structure (Target)

```toml
[service]
node_rpc_url = "grpc://127.0.0.1:16110"

# Profiles section contains per-signer overrides
[profiles.signer-1]

[profiles.signer-1.service]
data_dir = "./.igra/signer-1"

[profiles.signer-1.hd]
mnemonics = ["abandon", "abandon", "..."]

[profiles.signer-1.iroh]
peer_id = "signer-1"
signer_seed_hex = "000102..."
```

### 7.3 Loading Profiles with Figment

```rust
// Load config with profile overlay using figment
let config = load_config_with_profile(&data_dir, "signer-1")?;
```

Figment handles profile merging automatically:
1. Loads compiled defaults
2. Merges TOML file values
3. Applies `profiles.{name}` overrides via `figment.select(Profile::new(name))`
4. Applies environment variable overrides (highest priority)

The profile selection in figment works by looking for a `[profiles.{name}]` section in the TOML and merging those values over the base config. This eliminates manual merging code.

---

## Devnet Config Generator

The devnet orchestration includes a Python script that generates config files from keygen output. This script must be migrated to output TOML.

### 8.1 Current Script

**File**: `orchestration/devnet/scripts/update_devnet_config.py`

The script:
1. Reads keygen JSON output (mnemonics, keys, addresses)
2. Takes an INI template file
3. Processes line-by-line, replacing placeholders with generated values
4. Outputs a filled INI config file

**Current INI-specific code** (~200 lines):
```python
def rewrite_ini(ini_template, ini_out, config_dir, data, generated_ts, igra_data, run_root):
    text = ini_template.read_text()
    lines = text.splitlines()
    out_lines = []
    section = None

    for line in lines:
        if line.strip().startswith("[") and line.strip().endswith("]"):
            section = line.strip()[1:-1]
        # ... line-by-line processing
```

### 8.2 Migration Strategy

**Option A: Full Rewrite (Recommended)**

Replace line-by-line INI processing with TOML dict manipulation:

```python
import toml

def rewrite_toml(toml_template, toml_out, data, generated_ts, igra_data, run_root):
    """Generate TOML config from template and keygen data."""
    config = toml.load(toml_template)

    # Update service section
    config["service"]["data_dir"] = str(igra_data)

    # Update pskt section
    config["service"]["pskt"]["source_addresses"] = data["source_addresses"]
    config["service"]["pskt"]["redeem_script_hex"] = data["redeem_script_hex"]
    config["service"]["pskt"]["change_address"] = data["change_address"]

    # Update hd section with all mnemonics
    config["service"]["hd"] = {
        "mnemonics": [s["mnemonic"] for s in data["signers"]],
        "required_sigs": 2,
    }

    # Update group section
    config["group"]["member_pubkeys"] = data["member_pubkeys"]

    # Update hyperlane section
    config["hyperlane"]["validators"] = [k["public_key_hex"] for k in data["hyperlane_keys"]]

    # Update iroh section
    config["iroh"]["group_id"] = data["group_id"]
    config["iroh"]["verifier_keys"] = [
        f"{s['profile']}:{s['iroh_pubkey_hex']}" for s in data["signers"]
    ]

    # Bootstrap configuration
    endpoint_map = {s["profile"]: s["iroh_pubkey_hex"] for s in data["signers"]}
    port_map = {"signer-1": 9101, "signer-2": 9102, "signer-3": 9103}
    config["iroh"]["bootstrap"] = list(endpoint_map.values())
    config["iroh"]["bootstrap_addrs"] = [
        f"{endpoint_map[p]}@127.0.0.1:{port_map[p]}" for p in endpoint_map
    ]

    # Generate profile sections
    if "profiles" not in config:
        config["profiles"] = {}

    for signer in data["signers"]:
        profile = signer["profile"]
        config["profiles"][profile] = {
            "service": {
                "data_dir": str(igra_data / profile),
            },
            "hd": {
                "mnemonics": [signer["mnemonic"]],
            },
            "rpc": {
                "addr": f"0.0.0.0:{8088 + int(profile.split('-')[1]) - 1}",
            },
            "iroh": {
                "peer_id": signer["iroh_peer_id"],
                "signer_seed_hex": signer["iroh_seed_hex"],
                "group_id": data["group_id"],
                "network_id": 0,
                "verifier_keys": [
                    f"{s['profile']}:{s['iroh_pubkey_hex']}" for s in data["signers"]
                ],
                "bootstrap": [
                    endpoint_map[p] for p in endpoint_map if p != profile
                ],
                "bootstrap_addrs": [
                    f"{endpoint_map[p]}@127.0.0.1:{port_map[p]}"
                    for p in endpoint_map if p != profile
                ],
                "bind_port": port_map[profile],
            },
        }

    # Add generation metadata as comments (TOML doesn't support inline comments,
    # so we add a metadata section)
    config["_metadata"] = {
        "generated_at": generated_ts,
        "generator": "update_devnet_config.py",
    }

    # Write output
    with open(toml_out, "w") as f:
        toml.dump(config, f)
```

**Option B: Gradual Migration**

Keep the existing script but add TOML output:

```python
def main(argv):
    # ... existing argument parsing ...

    # Detect output format from extension
    if str(ini_out).endswith('.toml'):
        rewrite_toml(toml_template, ini_out, config_dir, data, generated_ts, igra_data, run_root)
    else:
        rewrite_ini(ini_template, ini_out, config_dir, data, generated_ts, igra_data, run_root)
```

### 8.3 Template File Changes

Create a TOML template alongside the INI template:

**File**: `orchestration/devnet/igra-devnet-template.toml`

```toml
# Devnet config template - values filled by update_devnet_config.py

[service]
node_rpc_url = "grpc://kaspad:16110"
data_dir = ""  # Filled by generator

[service.pskt]
source_addresses = []  # Filled by generator
redeem_script_hex = ""  # Filled by generator
sig_op_count = 2
fee_payment_mode = "recipient_pays"
fee_sompi = 0
change_address = ""  # Filled by generator

[service.hd]
mnemonics = []  # Filled by generator
required_sigs = 2

[runtime]
test_mode = false
session_timeout_seconds = 60

[signing]
backend = "threshold"

[rpc]
addr = "0.0.0.0:8088"
enabled = true

[policy]
allowed_destinations = []
min_amount_sompi = 1000000
max_amount_sompi = 100000000000
max_daily_volume_sompi = 500000000000
require_reason = false

[group]
threshold_m = 2
threshold_n = 3
member_pubkeys = []  # Filled by generator
fee_rate_sompi_per_gram = 0
finality_blue_score_threshold = 0
dust_threshold_sompi = 0
min_recipient_amount_sompi = 0
session_timeout_seconds = 60

[hyperlane]
validators = []  # Filled by generator
threshold = 2
poll_secs = 10

[layerzero]
endpoint_pubkeys = []

[iroh]
group_id = ""  # Filled by generator
verifier_keys = []  # Filled by generator
bootstrap = []  # Filled by generator
bootstrap_addrs = []  # Filled by generator

# Profile sections will be added by generator
```

### 8.4 Script Arguments Update

Update the script to accept TOML paths:

```python
"""
Update devnet configuration files with generated keys.

Args:
  1) env file path
  2) TOML template path (was: INI template path)
  3) config dir
  4) TOML output path (was: INI output path)
  5) hyperlane output path
  6) keygen json path
  7) igra data dir
  8) run root
  9) keyset output path
"""
```

### 8.5 Calling Scripts Update

Update any scripts that call `update_devnet_config.py`:

**File**: `orchestration/devnet/scripts/run_local_devnet.sh` (or similar)

```bash
# BEFORE
python3 scripts/update_devnet_config.py \
    "$ENV_FILE" \
    "$INI_TEMPLATE" \
    "$CONFIG_DIR" \
    "$INI_OUTPUT" \
    ...

# AFTER
python3 scripts/update_devnet_config.py \
    "$ENV_FILE" \
    "$TOML_TEMPLATE" \
    "$CONFIG_DIR" \
    "$TOML_OUTPUT" \
    ...
```

### 8.6 Full Migrated Script

Here's the complete migrated script:

```python
#!/usr/bin/env python3
"""
Update devnet configuration files with generated keys (TOML version).

Args:
  1) env file path
  2) TOML template path
  3) config dir
  4) TOML output path
  5) hyperlane output path
  6) keygen json path
  7) igra data dir
  8) run root
  9) keyset output path
"""

import datetime
import json
import pathlib
import sys

try:
    import tomli
    import tomli_w
except ImportError:
    print("ERROR: Install tomli and tomli-w: pip install tomli tomli-w", file=sys.stderr)
    sys.exit(1)


def read_keygen(path: pathlib.Path) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        print(f"ERROR: failed to read keygen {path}: {exc}", file=sys.stderr)
        sys.exit(1)


def write_env(env_path: pathlib.Path, config_dir: pathlib.Path, data: dict) -> None:
    env_vars = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if not line.strip() or line.strip().startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env_vars[k.strip()] = v.strip()

    env_vars["KASPA_DEVNET_WALLET_MNEMONIC"] = data["wallet"]["mnemonic"]
    env_vars["KASPA_DEVNET_WALLET_PASSWORD"] = data["wallet"]["password"]
    env_vars["KASPA_DEVNET_WALLET_NAME"] = data["wallet"]["name"]
    env_vars["KASPA_MINING_ADDRESS"] = data["wallet"]["mining_address"]

    output_env = config_dir / ".env"
    output_env.write_text("\n".join(f"{k}={v}" for k, v in env_vars.items()) + "\n")


def rewrite_toml(
    toml_template: pathlib.Path,
    toml_out: pathlib.Path,
    data: dict,
    generated_ts: str,
    igra_data: pathlib.Path,
    run_root: pathlib.Path,
) -> None:
    # Load template
    with open(toml_template, "rb") as f:
        config = tomli.load(f)

    # Ensure nested sections exist
    if "service" not in config:
        config["service"] = {}
    if "pskt" not in config["service"]:
        config["service"]["pskt"] = {}
    if "hd" not in config["service"]:
        config["service"]["hd"] = {}

    # Update service section
    config["service"]["data_dir"] = str(igra_data)

    # Update pskt section
    config["service"]["pskt"]["source_addresses"] = data["source_addresses"]
    config["service"]["pskt"]["redeem_script_hex"] = data["redeem_script_hex"]
    config["service"]["pskt"]["change_address"] = data["change_address"]

    # Update hd section
    config["service"]["hd"]["mnemonics"] = [s["mnemonic"] for s in data["signers"]]
    config["service"]["hd"]["required_sigs"] = 2

    # Update group section
    if "group" not in config:
        config["group"] = {}
    config["group"]["member_pubkeys"] = data["member_pubkeys"]

    # Update hyperlane section
    if "hyperlane" not in config:
        config["hyperlane"] = {}
    config["hyperlane"]["validators"] = [k["public_key_hex"] for k in data["hyperlane_keys"]]

    # Update iroh section
    if "iroh" not in config:
        config["iroh"] = {}

    group_id = data.get("group_id", "")
    config["iroh"]["group_id"] = group_id

    # Build verifier keys and bootstrap info
    endpoint_map = {s["profile"]: s["iroh_pubkey_hex"] for s in data["signers"]}
    peer_map = {s["profile"]: s["iroh_peer_id"] for s in data["signers"]}
    port_map = {"signer-1": 9101, "signer-2": 9102, "signer-3": 9103}

    verifier_keys = [f"{s['profile']}:{s['iroh_pubkey_hex']}" for s in data["signers"]]
    config["iroh"]["verifier_keys"] = verifier_keys
    config["iroh"]["bootstrap"] = list(endpoint_map.values())
    config["iroh"]["bootstrap_addrs"] = [
        f"{endpoint_map[p]}@127.0.0.1:{port_map[p]}" for p in endpoint_map
    ]

    # Generate profile sections
    if "profiles" not in config:
        config["profiles"] = {}

    signer_map = {s["profile"]: s for s in data["signers"]}

    for signer in data["signers"]:
        profile = signer["profile"]
        profile_num = int(profile.split("-")[1])

        other_bootstrap = [endpoint_map[p] for p in endpoint_map if p != profile]
        other_bootstrap_addrs = [
            f"{endpoint_map[p]}@127.0.0.1:{port_map[p]}"
            for p in endpoint_map if p != profile
        ]

        config["profiles"][profile] = {
            "service": {
                "data_dir": str(igra_data / profile),
            },
            "hd": {
                "mnemonics": [signer["mnemonic"]],
            },
            "rpc": {
                "addr": f"0.0.0.0:{8087 + profile_num}",
            },
            "iroh": {
                "peer_id": peer_map[profile],
                "signer_seed_hex": signer["iroh_seed_hex"],
                "group_id": group_id,
                "network_id": 0,
                "verifier_keys": verifier_keys,
                "bootstrap": other_bootstrap,
                "bootstrap_addrs": other_bootstrap_addrs,
                "bind_port": port_map[profile],
            },
        }

    # Write output with tomli_w
    with open(toml_out, "wb") as f:
        tomli_w.dump(config, f)

    print(f"Written: {toml_out}")


def write_hyperlane_keys(hyperlane_out: pathlib.Path, data: dict) -> None:
    validators = [
        {
            "name": key["name"],
            "private_key_hex": key["private_key_hex"],
            "public_key_hex": key["public_key_hex"],
        }
        for key in data["hyperlane_keys"]
    ]
    hyperlane_out.write_text(json.dumps({"validators": validators}, indent=2) + "\n")


def write_keyset(keyset_out: pathlib.Path, data: dict, generated_ts: str) -> None:
    payload = {
        "generated_at": generated_ts,
        "wallet": data["wallet"],
        "signers": data["signers"],
        "signer_addresses": data.get("signer_addresses", []),
        "member_pubkeys": data["member_pubkeys"],
        "redeem_script_hex": data["redeem_script_hex"],
        "source_addresses": data["source_addresses"],
        "change_address": data["change_address"],
        "hyperlane_keys": data["hyperlane_keys"],
        "group_id": data.get("group_id", ""),
    }
    keyset_out.write_text(json.dumps(payload, indent=2) + "\n")


def write_identities(igra_data: pathlib.Path, data: dict) -> None:
    for signer in data["signers"]:
        profile = signer["profile"]
        identity_dir = igra_data / profile / "iroh"
        identity_dir.mkdir(parents=True, exist_ok=True)
        identity_path = identity_dir / "identity.json"
        identity = {
            "peer_id": signer["iroh_peer_id"],
            "seed_hex": signer["iroh_seed_hex"],
        }
        identity_path.write_text(json.dumps(identity, indent=2) + "\n")


def main(argv: list[str]) -> int:
    if len(argv) != 9:
        print(__doc__, file=sys.stderr)
        return 1

    env_path = pathlib.Path(argv[0])
    toml_template = pathlib.Path(argv[1])
    config_dir = pathlib.Path(argv[2])
    toml_out = pathlib.Path(argv[3])
    hyperlane_out = pathlib.Path(argv[4])
    keygen_path = pathlib.Path(argv[5])
    igra_data = pathlib.Path(argv[6])
    run_root = pathlib.Path(argv[7])
    keyset_out = pathlib.Path(argv[8])

    config_dir.mkdir(parents=True, exist_ok=True)
    data = read_keygen(keygen_path)
    generated_ts = datetime.datetime.utcnow().isoformat() + "Z"

    write_identities(igra_data, data)
    write_env(env_path, config_dir, data)
    rewrite_toml(toml_template, toml_out, data, generated_ts, igra_data, run_root)
    write_hyperlane_keys(hyperlane_out, data)
    write_keyset(keyset_out, data, generated_ts)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

### 8.7 Dependencies

Add TOML libraries to devnet requirements:

```bash
pip install tomli tomli-w
```

Or add to `orchestration/devnet/requirements.txt`:

```
tomli>=2.0.0
tomli-w>=1.0.0
```

---

## Testing Strategy

### 9.1 Unit Tests

Add to `igra-core/src/infrastructure/config/loader.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_load_minimal_toml() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("igra-config.toml");
        std::fs::write(&config_path, r#"
            [service]
            node_rpc_url = "grpc://127.0.0.1:16110"
        "#).unwrap();

        let config = load_config(dir.path()).unwrap();
        assert_eq!(config.service.node_rpc_url, "grpc://127.0.0.1:16110");
    }

    #[test]
    fn test_load_with_arrays() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("igra-config.toml");
        std::fs::write(&config_path, r#"
            [service.pskt]
            source_addresses = ["addr1", "addr2"]
        "#).unwrap();

        let config = load_config(dir.path()).unwrap();
        assert_eq!(config.service.pskt.source_addresses, vec!["addr1", "addr2"]);
    }

    #[test]
    fn test_load_hyperlane_domains() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("igra-config.toml");
        std::fs::write(&config_path, r#"
            [[hyperlane.domains]]
            domain = 42
            validators = ["0xabc"]
            threshold = 1
        "#).unwrap();

        let config = load_config(dir.path()).unwrap();
        assert_eq!(config.hyperlane.domains.len(), 1);
        assert_eq!(config.hyperlane.domains[0].domain, 42);
    }

    #[test]
    fn test_load_with_profile() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("igra-config.toml");
        std::fs::write(&config_path, r#"
            [service]
            data_dir = "/base"

            [profiles.signer-1.service]
            data_dir = "/signer-1"
        "#).unwrap();

        let config = load_config_with_profile(dir.path(), "signer-1").unwrap();
        assert_eq!(config.service.data_dir, "/signer-1");
    }

    #[test]
    fn test_load_from_specific_file() {
        let dir = tempdir().unwrap();
        let custom_path = dir.path().join("custom-config.toml");
        std::fs::write(&custom_path, r#"
            [service]
            node_rpc_url = "grpc://custom:16110"
        "#).unwrap();

        let config = load_config_from_file(&custom_path, dir.path()).unwrap();
        assert_eq!(config.service.node_rpc_url, "grpc://custom:16110");
    }
}
```

### 9.2 Integration Tests

Update `igra-core/tests/integration/config_loading.rs`:

```rust
#[test]
fn test_toml_config_loading_with_profile() {
    let _guard = lock_env();
    let data_dir = tempfile::tempdir().expect("temp data dir");

    env::set_var("KASPA_IGRA_WALLET_SECRET", "test-secret");
    env::set_var("KASPA_DATA_DIR", data_dir.path());

    // Copy test config to temp dir
    let root = config_root();
    let src_config = root.join("artifacts/igra-config.toml");
    let dest_config = data_dir.path().join("igra-config.toml");
    std::fs::copy(&src_config, &dest_config).expect("copy config");

    // Load with profile using figment-based loader
    let config = load_config_with_profile(data_dir.path(), "signer-1")
        .expect("load config");

    assert_eq!(config.iroh.peer_id, Some("signer-1".to_string()));

    env::remove_var("KASPA_DATA_DIR");
    env::remove_var("KASPA_IGRA_WALLET_SECRET");
}

#[test]
fn test_env_overrides_with_figment() {
    let _guard = lock_env();
    let data_dir = tempfile::tempdir().expect("temp data dir");

    // Create minimal config
    let config_path = data_dir.path().join("igra-config.toml");
    std::fs::write(&config_path, r#"
        [service]
        node_rpc_url = "grpc://127.0.0.1:16110"

        [rpc]
        addr = "127.0.0.1:8088"
    "#).unwrap();

    // Set env override (should take precedence)
    env::set_var("IGRA_RPC__ADDR", "0.0.0.0:9999");

    let config = load_config(data_dir.path()).expect("load config");

    // Env var should override file value
    assert_eq!(config.rpc.addr, "0.0.0.0:9999");

    env::remove_var("IGRA_RPC__ADDR");
}
```

### 9.3 Validation Checklist

Run after conversion:

```bash
# 1. Run architecture tests
cargo test --test architecture -p igra-core

# 2. Run config unit tests
cargo test -p igra-core config

# 3. Run config integration tests
cargo test -p igra-core --test config_loading

# 4. Run full integration tests
cargo test -p igra-service --test '*'

# 5. Manual smoke test with each profile
KASPA_CONFIG_PATH=artifacts/igra-config.toml cargo run -p igra-service -- --profile signer-1
KASPA_CONFIG_PATH=artifacts/igra-config.toml cargo run -p igra-service -- --profile signer-2
KASPA_CONFIG_PATH=artifacts/igra-config.toml cargo run -p igra-service -- --profile signer-3
```

---

## Rollback Plan

If issues are discovered after deployment:

### 10.1 Keep INI Parser (Temporary)

During Phase 2, the INI parser is still in the codebase behind a deprecation warning. To rollback:

1. Revert `env.rs` changes (default filename)
2. Remove deprecation warning from `loader_unified.rs`
3. Keep using `.ini` files

### 10.2 Full Rollback

```bash
# Revert the refactoring commits
git revert <commit-hash>

# Or restore specific files
git checkout HEAD~1 -- igra-core/src/infrastructure/config/loader.rs
git checkout HEAD~1 -- igra-core/src/infrastructure/config/types.rs
```

### 10.3 Dual Format Support

If needed long-term, keep both parsers:

```rust
fn load_from_path(path: &Path, data_dir: &Path) -> Result<AppConfig, ThresholdError> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("toml") => loader::load_from_toml(path, data_dir),
        Some("ini") => loader::load_from_ini(path, data_dir),
        _ => loader::load_from_toml(path, data_dir),  // Default to TOML
    }
}
```

---

## Checklist

### Pre-Migration

- [ ] Read and understand this document
- [ ] Backup existing config files
- [ ] Ensure all tests pass with current INI configs
- [ ] Create feature branch: `git checkout -b feature/toml-config`

### Phase 1: Create TOML Configs

- [ ] Run conversion script on `artifacts/igra-config.ini`
- [ ] Run conversion script on `artifacts/igra-prod.ini`
- [ ] Run conversion script on `orchestration/devnet/igra-devnet.ini`
- [ ] Manually verify each converted file
- [ ] Test loading both INI and TOML versions
- [ ] Commit: `"Add TOML config files alongside INI"`

### Phase 2: Code Changes

- [ ] Update `loader.rs` (remove INI parsing, keep TOML)
- [ ] Remove `merge_from` implementations from `types.rs`
- [ ] Update `env.rs` default filename
- [ ] Update `loader_unified.rs`
- [ ] Add deprecation warning for INI files
- [ ] Run `cargo check` - fix any compilation errors
- [ ] Commit: `"Simplify config loader to TOML-only"`

### Phase 3: Devnet Script Migration

- [ ] Install Python TOML dependencies: `pip install tomli tomli-w`
- [ ] Create TOML template: `orchestration/devnet/igra-devnet-template.toml`
- [ ] Update `update_devnet_config.py` to use `rewrite_toml()` function
- [ ] Update calling scripts (`run_local_devnet.sh`, etc.) to pass TOML paths
- [ ] Test devnet config generation with new TOML output
- [ ] Verify generated TOML loads correctly with igra-service
- [ ] Run full devnet smoke test
- [ ] Commit: `"Migrate devnet config generator to TOML"`

### Phase 4: Tests & Documentation

- [ ] Update `igra-core/tests/integration/config_loading.rs`
- [ ] Update integration tests in `igra-service/tests/`
- [ ] Add new unit tests for TOML loader
- [ ] Run full test suite: `cargo test --workspace`
- [ ] Update `docs/service/README.md`
- [ ] Commit: `"Update tests and docs for TOML config"`

### Phase 5: Cleanup

- [ ] Delete `artifacts/igra-config.ini`
- [ ] Delete `artifacts/igra-prod.ini`
- [ ] Delete `orchestration/devnet/igra-devnet.ini`
- [ ] Delete INI template if exists
- [ ] Remove INI parsing code from `loader.rs`
- [ ] Remove `configparser` from `Cargo.toml` if no longer needed
- [ ] Final test run
- [ ] Commit: `"Remove deprecated INI config support"`

### Post-Migration

- [ ] Create PR with all commits
- [ ] Get code review
- [ ] Merge to devel
- [ ] Monitor for issues
- [ ] Update any external documentation/wikis

---

## Appendix: Full TOML Config Example

```toml
# =============================================================================
# Igra Configuration (TOML)
# =============================================================================
# Environment: export KASPA_IGRA_WALLET_SECRET=<your-secret>

[service]
node_rpc_url = "grpc://127.0.0.1:16110"
data_dir = "./.igra"

[service.pskt]
source_addresses = [
    "kaspadev:qzjwhmuwx4fmmxleyykgcekr2m2tamseskqvl859mss2jvz7tk46j2qyvpukx",
    "kaspadev:qpjfl8wzj94zc6wtdy6fh8yy7apywvnpqdfnvay8s460gd56yx5rwegde7cxa"
]
redeem_script_hex = "5220a4ebef..."
sig_op_count = 2
fee_payment_mode = "recipient_pays"
fee_sompi = 0
change_address = "kaspadev:qrz9yajzk65v0wyrk0s54drcauzd8rlgaagrl74cjmj042w4crqkust5wycfq"

[service.hd]
# Mnemonics are encrypted; provide via KASPA_IGRA_WALLET_SECRET
xpubs = []
required_sigs = 2

[runtime]
test_mode = true
test_recipient = "kaspadev:qzunluwzc0yfk55yulnzczgqx23a43n6v2utqde0jst7uhh93dkhkp80l2wca"
test_amount_sompi = 123456
session_timeout_seconds = 60

[signing]
backend = "threshold"

[rpc]
addr = "127.0.0.1:8088"
enabled = true

[policy]
allowed_destinations = ["kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3"]
min_amount_sompi = 1000000
max_amount_sompi = 100000000000
max_daily_volume_sompi = 500000000000
require_reason = false

[group]
threshold_m = 2
threshold_n = 3
member_pubkeys = [
    "02a4ebef8e3553bd9bf9212c8c66c356d4beee198580cf9e85dc20a9305e5daba9",
    "02b93ff1c2c3c89b5284e7e62c090032a3dac67a62b8b0372f9417ee5ee58b6d7b",
    "02ca1582d546037ff74ebc280c84a40d7118c0959b7885b94eba69a578b273deec"
]
fee_rate_sompi_per_gram = 0
finality_blue_score_threshold = 0
dust_threshold_sompi = 0
min_recipient_amount_sompi = 0
session_timeout_seconds = 60

[hyperlane]
validators = [
    "039a8d46063004a62914db7eb40e445e2500331c7f1263d4596e3e3cc6bc7bc82c",
    "02f5c3507cd1dc83a1e890a830bcfd452ea12ee93537e76bc30a3130ac7138203c"
]
threshold = 2
poll_secs = 10

# Per-domain ISM configuration (optional, preferred over flat validators)
[[hyperlane.domains]]
domain = 42
validators = ["0xabc", "0xdef"]
threshold = 2
mode = "message_id_multisig"

[layerzero]
endpoint_pubkeys = []

[iroh]
group_id = "d44bf35c6f6f52b1c245fb85ef1ae2178e4f621c9e6d53f6a36acd03aa25b81c"
verifier_keys = [
    "coordinator-1:02a4ebef8e3553bd9bf9212c8c66c356d4beee198580cf9e85dc20a9305e5daba9"
]

# =============================================================================
# Signer Profiles
# =============================================================================

[profiles.signer-1]

[profiles.signer-1.service]
data_dir = "./.igra/signer-1"

[profiles.signer-1.hd]
# Single mnemonic for this signer (will be encrypted on load)
mnemonics = ["abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"]

[profiles.signer-1.rpc]
addr = "127.0.0.1:8088"

[profiles.signer-1.iroh]
peer_id = "signer-1"
signer_seed_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
group_id = "d44bf35c6f6f52b1c245fb85ef1ae2178e4f621c9e6d53f6a36acd03aa25b81c"
network_id = 0
verifier_keys = [
    "signer-1:03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
    "signer-2:29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7",
    "signer-3:2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d"
]

[profiles.signer-2]

[profiles.signer-2.service]
data_dir = "./.igra/signer-2"

[profiles.signer-2.hd]
mnemonics = ["legal winner thank year wave sausage worth useful legal winner thank yellow"]

[profiles.signer-2.rpc]
addr = "127.0.0.1:8089"

[profiles.signer-2.iroh]
peer_id = "signer-2"
signer_seed_hex = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
group_id = "d44bf35c6f6f52b1c245fb85ef1ae2178e4f621c9e6d53f6a36acd03aa25b81c"
network_id = 0
verifier_keys = [
    "signer-1:03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
    "signer-2:29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7",
    "signer-3:2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d"
]

[profiles.signer-3]

[profiles.signer-3.service]
data_dir = "./.igra/signer-3"

[profiles.signer-3.hd]
mnemonics = ["letter advice cage absurd amount doctor acoustic avoid letter advice cage above"]

[profiles.signer-3.rpc]
addr = "127.0.0.1:8090"

[profiles.signer-3.iroh]
peer_id = "signer-3"
signer_seed_hex = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
group_id = "d44bf35c6f6f52b1c245fb85ef1ae2178e4f621c9e6d53f6a36acd03aa25b81c"
network_id = 0
verifier_keys = [
    "signer-1:03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
    "signer-2:29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7",
    "signer-3:2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d"
]
```

---

## Questions?

If you encounter issues during migration:

1. Check the [TOML specification](https://toml.io/en/v1.0.0)
2. Review existing TOML tests in the codebase
3. Use `toml::from_str` in a test to validate your config syntax
4. Open an issue with the specific error message
