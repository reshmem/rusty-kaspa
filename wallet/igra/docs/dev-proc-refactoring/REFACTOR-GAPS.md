# Igra Refactoring Gaps Analysis

**Document ID**: REFACTOR-GAPS-001
**Related**: ARCHITECTURE-DOMAIN-INFRASTRUCTURE.md
**Status**: Action Required
**Created**: 2026-01-10

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [What Was Done Well](#what-was-done-well)
3. [Critical Issues: Domain Layer Violations](#critical-issues-domain-layer-violations)
4. [What To Do With igra-service](#what-to-do-with-igra-service)
5. [What To Do With infrastructure/observability](#what-to-do-with-infrastructureobservability)
6. [Action Items](#action-items)
7. [Implementation Guide](#implementation-guide)

---

## Executive Summary

The refactoring to the 4-layer architecture (foundation, domain, infrastructure, application) is **mostly complete**. The directory structure is correct and most modules are in the right places.

However, there are **critical violations** where the domain layer imports from infrastructure, breaking the core architectural constraint:

```
Domain → Infrastructure ❌ (FORBIDDEN)
```

These must be fixed to achieve the benefits of the layered architecture (testability, maintainability, clear boundaries).

---

## What Was Done Well

### Layer Structure ✅

The 4-layer structure is correctly in place:

```
igra-core/src/
├── foundation/          ✅ Shared primitives
│   ├── constants.rs
│   ├── error.rs
│   ├── hd.rs
│   ├── types.rs
│   └── util/
│
├── domain/              ✅ Business logic
│   ├── audit/
│   ├── coordination/
│   ├── event/
│   ├── group_id.rs
│   ├── hashes.rs
│   ├── model.rs
│   ├── policy/
│   ├── pskt/
│   ├── request/
│   ├── signing/
│   └── validation/
│
├── infrastructure/      ✅ I/O and external systems
│   ├── audit/
│   ├── config/
│   ├── hyperlane/
│   ├── observability/
│   ├── rpc/
│   ├── storage/
│   └── transport/
│
├── application/         ✅ Orchestration
│   ├── coordinator.rs
│   ├── event_processor.rs
│   ├── lifecycle.rs
│   ├── monitoring.rs
│   └── signer.rs
│
└── lib.rs               ✅ Clean exports
```

### Clean Public API ✅

`lib.rs` correctly exports only the 4 layers:

```rust
pub mod application;
pub mod foundation;
pub mod domain;
pub mod infrastructure;
pub use foundation::{Result, ThresholdError};
```

### Correct Module Placement ✅

- **Foundation**: Types, errors, utilities, constants - no business logic, no I/O
- **Application**: `Coordinator`, `Signer`, `EventProcessor` - orchestrates domain + infrastructure
- **Infrastructure**: Storage (RocksDB), Transport (Iroh), RPC (gRPC), Config, Hyperlane

---

## Critical Issues: Domain Layer Violations

### Issue 1: `domain/pskt/builder.rs` Imports Infrastructure

**File**: `igra-core/src/domain/pskt/builder.rs`

**Problematic Imports** (lines 1-6):
```rust
use crate::infrastructure::config::{PsktBuildConfig, PsktOutput};
use crate::foundation::ThresholdError;
use crate::domain::FeePaymentMode;
use crate::domain::pskt::multisig::{build_pskt, MultisigInput, MultisigOutput};
use crate::infrastructure::rpc::GrpcNodeRpc;
use crate::infrastructure::rpc::NodeRpc;
```

**Violation**: Domain layer directly depends on:
- `infrastructure::config::PsktBuildConfig`
- `infrastructure::config::PsktOutput`
- `infrastructure::rpc::GrpcNodeRpc`
- `infrastructure::rpc::NodeRpc`

**Problematic Functions**:
- `build_pskt_via_rpc()` - Creates RPC connection and fetches UTXOs
- `build_pskt_with_client()` - Takes `NodeRpc` trait and fetches UTXOs

**Why This Is Wrong**:
- Domain logic cannot be tested without mocking RPC
- Domain depends on infrastructure configuration types
- Violates dependency inversion principle

**Fix Required**:
1. Move `build_pskt_via_rpc` and `build_pskt_with_client` to `infrastructure/rpc/kaspa_integration/`
2. Keep only pure PSKT building logic in domain (fee calculations, transaction construction)
3. Create domain-level parameter types or move `PsktBuildConfig` to foundation

---

### Issue 2: `domain/signing/mod.rs` Imports Infrastructure

**File**: `igra-core/src/domain/signing/mod.rs`

**Problematic Imports** (lines 1-2):
```rust
use crate::foundation::ThresholdError;
use crate::infrastructure::transport::messages::PartialSigSubmit;
```

**Problematic Function** (line 27):
```rust
pub fn backend_kind_from_config(config: &crate::infrastructure::config::SigningConfig) -> Result<SigningBackendKind, ThresholdError>
```

**Violation**: Domain layer directly depends on:
- `infrastructure::transport::messages::PartialSigSubmit`
- `infrastructure::config::SigningConfig`

**Why This Is Wrong**:
- `SignerBackend` trait returns infrastructure types
- Config parsing belongs in infrastructure or application layer

**Fix Required**:
1. Move `PartialSigSubmit` struct to `domain/signing/types.rs` (it's just data)
2. Move `backend_kind_from_config` to `application/` or `infrastructure/config/`
3. Keep only `SigningBackendKind::from_str()` in domain (already exists)

---

### Issue 3: Transport Messages Are Infrastructure But Used By Domain

**File**: `igra-core/src/infrastructure/transport/iroh/messages.rs`

**Current Location**: Infrastructure (correct for protocol-specific messages)

**Problem**: `PartialSigSubmit` is used by domain signing trait:

```rust
// domain/signing/mod.rs
pub trait SignerBackend: Send + Sync {
    fn kind(&self) -> SigningBackendKind;
    fn sign(&self, kpsbt_blob: &[u8]) -> Result<Vec<PartialSigSubmit>, ThresholdError>;
}
```

**Fix Required**:
1. Create `domain/signing/types.rs` with a domain-level `PartialSignature` struct
2. Infrastructure transport can convert to/from the domain type
3. Or move `PartialSigSubmit` definition to domain (it has no Iroh-specific dependencies)

---

## What To Do With igra-service

### Current Structure

```
igra-service/src/
├── api/
│   ├── mod.rs
│   └── json_rpc.rs        # JSON-RPC API endpoints
├── service/
│   ├── mod.rs
│   ├── coordination.rs    # Main coordination loop (474 lines)
│   ├── flow.rs            # ServiceFlow orchestration
│   └── metrics.rs         # Prometheus metrics
├── transport/
│   └── iroh.rs            # Re-export: pub use igra_core::infrastructure::transport::iroh::*;
├── bin/
│   ├── kaspa-threshold-service.rs
│   └── kaspa-threshold-service/
│       ├── cli.rs
│       ├── setup.rs
│       └── modes/
└── lib.rs
```

### Role of igra-service

`igra-service` is the **deployment-specific application layer**. This is the correct architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                      igra-service                           │
│  (Deployment: binaries, API endpoints, service config)      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                       igra-core                             │
│  (Library: domain, infrastructure, application layers)      │
└─────────────────────────────────────────────────────────────┘
```

### What Should Stay in igra-service

| Module | Reason |
|--------|--------|
| `service/coordination.rs` | Service-specific event loop, spawns tasks, manages timeouts |
| `service/flow.rs` | Wires up `Coordinator` with Iroh transport and RocksDB |
| `service/metrics.rs` | Prometheus metrics (deployment-specific) |
| `api/json_rpc.rs` | JSON-RPC API (deployment-specific) |
| `bin/*` | Binary entry points |

### What Should NOT Move to igra-core

The `coordination.rs` loop is deployment-specific because it:
- Uses `tokio::spawn` for task management
- Handles Iroh-specific subscription patterns
- Manages session timeouts with service configuration
- Integrates with service-level metrics

This is **correct placement** - it's orchestration at the service level.

### Recommended Cleanup

1. **Document the architecture** in `igra-service/README.md`:
   ```markdown
   igra-service is the deployment layer for the Igra threshold signing service.
   It wires together igra-core components and provides:
   - Binary entry points
   - JSON-RPC API
   - Prometheus metrics
   - Service configuration
   ```

2. **Keep transport re-export** but add documentation:
   ```rust
   //! Re-exports Iroh transport from igra-core for convenience.
   //! This allows igra-service to use transport types without deep imports.
   pub use igra_core::infrastructure::transport::iroh::*;
   ```

---

## What To Do With infrastructure/observability

### Current State

The observability module contains placeholder stubs:

```rust
// infrastructure/observability/metrics.rs
pub struct MetricsStub;

// infrastructure/observability/tracing.rs
pub struct TracingStub;

// infrastructure/observability/health.rs
pub struct HealthStub;
```

Meanwhile, **real metrics exist** in `igra-service/src/service/metrics.rs` with actual Prometheus implementation.

### Options

#### Option A: Delete Stubs (Recommended for Now)

The stubs provide no value. Delete them:

```
igra-core/src/infrastructure/observability/
├── mod.rs      # Keep as empty or minimal
├── metrics.rs  # DELETE
├── tracing.rs  # DELETE
└── health.rs   # DELETE
```

Metrics stay in `igra-service` where they belong (deployment-specific).

#### Option B: Define Traits in igra-core

If you want `igra-core` to be observability-aware without depending on Prometheus:

**metrics.rs**:
```rust
//! Metrics recording trait for observability.
//! Implementations provided by deployment layer (igra-service).

pub trait MetricsRecorder: Send + Sync {
    fn inc_session_stage(&self, stage: &str);
    fn inc_signer_ack(&self, accepted: bool);
    fn inc_partial_sig(&self);
    fn inc_rpc_request(&self, method: &str, status: &str);
}

/// No-op implementation for testing or when metrics are disabled.
pub struct NoopMetrics;

impl MetricsRecorder for NoopMetrics {
    fn inc_session_stage(&self, _: &str) {}
    fn inc_signer_ack(&self, _: bool) {}
    fn inc_partial_sig(&self) {}
    fn inc_rpc_request(&self, _: &str, _: &str) {}
}
```

**health.rs**:
```rust
//! Health check trait for service readiness.

pub trait HealthCheck: Send + Sync {
    fn check(&self) -> HealthStatus;
}

#[derive(Debug, Clone)]
pub enum HealthStatus {
    Healthy,
    Degraded(String),
    Unhealthy(String),
}

impl HealthStatus {
    pub fn is_healthy(&self) -> bool {
        matches!(self, HealthStatus::Healthy)
    }
}
```

**tracing.rs**:
```rust
//! Tracing configuration.
//!
//! Use the `tracing` crate directly - no wrapper needed.
//! This module can provide helper functions for span creation if desired.

// Consider deleting this file entirely.
// The `tracing` crate is used directly throughout the codebase.
```

### Recommendation

**For immediate cleanup**: Option A (delete stubs)

**For future extensibility**: Option B (define traits) - but only if you need `igra-core` components to record metrics without depending on Prometheus directly.

---

## Action Items

### Priority: 🚨 Critical (Domain Violations)

| # | Task | File | Effort |
|---|------|------|--------|
| 1 | Move `build_pskt_via_rpc` and `build_pskt_with_client` to infrastructure | `domain/pskt/builder.rs` → `infrastructure/rpc/kaspa_integration/` | Medium |
| 2 | Move `PartialSigSubmit` to domain or create domain equivalent | `infrastructure/transport/iroh/messages.rs` → `domain/signing/types.rs` | Low |
| 3 | Move `backend_kind_from_config` out of domain | `domain/signing/mod.rs` → `infrastructure/config/` or `application/` | Low |
| 4 | Remove infrastructure imports from domain pskt builder | `domain/pskt/builder.rs` | Low |

### Priority: 🔶 Medium (Cleanup)

| # | Task | File | Effort |
|---|------|------|--------|
| 5 | Delete observability stubs OR replace with traits | `infrastructure/observability/*.rs` | Low |
| 6 | Move `PsktBuildConfig` to foundation or create domain params | `infrastructure/config/` | Medium |
| 7 | Update re-exports after moves | Various `mod.rs` files | Low |

### Priority: 🟢 Low (Documentation)

| # | Task | Location | Effort |
|---|------|----------|--------|
| 8 | Document igra-service as deployment layer | `igra-service/README.md` | Low |
| 9 | Add module-level documentation | All `mod.rs` files | Low |
| 10 | Update ARCHITECTURE-DOMAIN-INFRASTRUCTURE.md with actual state | Root | Low |

---

## Implementation Guide

### Step 1: Fix domain/pskt/builder.rs

**Current** (WRONG):
```rust
// domain/pskt/builder.rs
use crate::infrastructure::config::{PsktBuildConfig, PsktOutput};
use crate::infrastructure::rpc::GrpcNodeRpc;
use crate::infrastructure::rpc::NodeRpc;

pub async fn build_pskt_via_rpc(config: &PsktBuildConfig) -> Result<...> {
    let rpc = GrpcNodeRpc::connect(config.node_rpc_url.clone()).await?;
    build_pskt_with_client(&rpc, config).await
}
```

**After** (CORRECT):

Move to `infrastructure/rpc/kaspa_integration/pskt_builder.rs`:
```rust
// infrastructure/rpc/kaspa_integration/pskt_builder.rs
use crate::infrastructure::config::{PsktBuildConfig, PsktOutput};
use crate::infrastructure::rpc::{GrpcNodeRpc, NodeRpc};
use crate::domain::pskt::multisig::{build_pskt, MultisigInput, MultisigOutput};

pub async fn build_pskt_via_rpc(config: &PsktBuildConfig) -> Result<...> {
    let rpc = GrpcNodeRpc::connect(config.node_rpc_url.clone()).await?;
    build_pskt_from_rpc(&rpc, config).await
}

pub async fn build_pskt_from_rpc(rpc: &dyn NodeRpc, config: &PsktBuildConfig) -> Result<...> {
    // Fetch UTXOs via RPC
    let utxos = rpc.get_utxos_by_addresses(&addresses).await?;

    // Call domain logic
    let inputs = convert_utxos_to_inputs(utxos, &redeem_script);
    let outputs = convert_config_to_outputs(config);

    domain::pskt::multisig::build_pskt(&inputs, &outputs)
}
```

Keep in `domain/pskt/builder.rs` only pure functions:
```rust
// domain/pskt/builder.rs
use crate::foundation::ThresholdError;
use crate::domain::FeePaymentMode;

/// Pure fee calculation - no I/O
pub fn calculate_fee_split(
    fee: u64,
    mode: &FeePaymentMode,
) -> Result<(u64, u64), ThresholdError> {
    // Pure logic only
}

/// Pure fee application - no I/O
pub fn apply_fee_to_outputs(
    total_input: u64,
    outputs: &mut Vec<MultisigOutput>,
    fee: u64,
    mode: &FeePaymentMode,
    change_address: Option<&str>,
) -> Result<(), ThresholdError> {
    // Pure logic only
}
```

---

### Step 2: Fix domain/signing/mod.rs

**Current** (WRONG):
```rust
// domain/signing/mod.rs
use crate::infrastructure::transport::messages::PartialSigSubmit;

pub fn backend_kind_from_config(config: &crate::infrastructure::config::SigningConfig) -> Result<...>
```

**After** (CORRECT):

Create `domain/signing/types.rs`:
```rust
// domain/signing/types.rs
use crate::foundation::RequestId;
use serde::{Deserialize, Serialize};

/// Partial signature from a signer for a specific input.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PartialSignature {
    pub request_id: RequestId,
    pub input_index: u32,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}
```

Update `domain/signing/mod.rs`:
```rust
// domain/signing/mod.rs
use crate::foundation::ThresholdError;

pub mod types;
pub mod mpc;
pub mod musig2;
pub mod threshold;
pub mod aggregation;

pub use types::PartialSignature;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningBackendKind {
    Threshold,
    MuSig2,
    Mpc,
}

impl SigningBackendKind {
    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "threshold" | "multisig" => Some(Self::Threshold),
            "musig2" => Some(Self::MuSig2),
            "mpc" | "frost" => Some(Self::Mpc),
            _ => None,
        }
    }
}

pub trait SignerBackend: Send + Sync {
    fn kind(&self) -> SigningBackendKind;
    fn sign(&self, kpsbt_blob: &[u8]) -> Result<Vec<PartialSignature>, ThresholdError>;
}
```

Move config helper to `infrastructure/config/signing.rs`:
```rust
// infrastructure/config/signing.rs
use crate::domain::signing::SigningBackendKind;
use crate::foundation::ThresholdError;

pub fn backend_kind_from_config(config: &SigningConfig) -> Result<SigningBackendKind, ThresholdError> {
    SigningBackendKind::from_str(&config.backend)
        .ok_or_else(|| ThresholdError::Message(format!("unknown signing.backend: {}", config.backend)))
}
```

---

### Step 3: Clean Up Observability

**Option A - Delete stubs**:
```bash
# Delete the stub files
rm igra-core/src/infrastructure/observability/metrics.rs
rm igra-core/src/infrastructure/observability/tracing.rs
rm igra-core/src/infrastructure/observability/health.rs
```

Update `infrastructure/observability/mod.rs`:
```rust
//! Observability infrastructure.
//!
//! Actual implementations (Prometheus, OpenTelemetry) are in igra-service.
//! This module provides trait definitions for observability interfaces.

// Currently empty - implementations in igra-service
```

**Option B - Define traits**: See code examples in [What To Do With infrastructure/observability](#what-to-do-with-infrastructureobservability) section.

---

### Step 4: Update Imports

After moving code, update imports throughout the codebase:

```rust
// Before
use crate::domain::pskt::builder::build_pskt_via_rpc;

// After
use crate::infrastructure::rpc::kaspa_integration::build_pskt_via_rpc;
```

```rust
// Before
use crate::infrastructure::transport::messages::PartialSigSubmit;

// After
use crate::domain::signing::PartialSignature;
```

---

## Verification Checklist

After completing the fixes, verify:

- [ ] `domain/` has NO imports from `infrastructure/`
- [ ] `domain/` has NO imports from `application/`
- [ ] `foundation/` has NO imports from other layers
- [ ] All domain tests run without mocking infrastructure
- [ ] `cargo build` succeeds
- [ ] `cargo test` passes

### Grep Check for Violations

Run these commands to find remaining violations:

```bash
# Check domain imports infrastructure
grep -r "use crate::infrastructure" igra-core/src/domain/

# Check domain imports application
grep -r "use crate::application" igra-core/src/domain/

# Check foundation imports other layers
grep -r "use crate::" igra-core/src/foundation/ | grep -v "foundation"
```

Expected output: **empty** (no violations)

---

## Summary

The refactoring is **85% complete**. The remaining work is:

1. **Fix 2 domain files** that import infrastructure (`pskt/builder.rs`, `signing/mod.rs`)
2. **Clean up observability** (delete stubs or define traits)
3. **Update documentation** to reflect actual architecture

Estimated effort: **2-4 hours** for critical fixes, **1-2 hours** for cleanup.

---

**End of Document**
