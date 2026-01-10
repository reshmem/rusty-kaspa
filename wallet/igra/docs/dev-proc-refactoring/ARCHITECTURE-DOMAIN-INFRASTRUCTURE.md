# Igra Architecture: Domain vs Infrastructure Separation

**Document ID**: ARCH-001
**Related**: REFACTOR-008, REFACTOR-009
**Status**: Proposed
**Created**: 2026-01-09

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architectural Philosophy](#architectural-philosophy)
3. [Current Architecture Analysis](#current-architecture-analysis)
4. [Proposed Architecture](#proposed-architecture)
5. [Module Classification](#module-classification)
6. [Detailed Module Map](#detailed-module-map)
7. [Design Principles](#design-principles)
8. [Migration Strategy](#migration-strategy)
9. [Testing Strategy](#testing-strategy)
10. [Benefits and Tradeoffs](#benefits-and-tradeoffs)

---

## Executive Summary

### Problem Statement

The current igra codebase mixes **domain logic** (business rules, validation, signing workflows) with **infrastructure concerns** (storage, networking, RPC). This coupling creates:

- **Testing complexity** - domain logic requires mocking storage/transport
- **Cognitive overhead** - business rules scattered across I/O code
- **Tight coupling** - changing storage/transport requires touching business logic
- **Reduced reusability** - domain logic cannot be extracted or reused independently

### Proposed Solution

Separate the codebase into three clear layers:

```
┌─────────────────────────────────────────┐
│          APPLICATION LAYER              │  (Orchestration, service entry points)
│   igra-service, CLI binaries            │
└─────────────────────────────────────────┘
              ↓ depends on
┌─────────────────────────────────────────┐
│           DOMAIN LAYER                  │  (Pure business logic, no I/O)
│  Event validation, policy enforcement,  │
│  signing workflows, PSKT building       │
└─────────────────────────────────────────┘
              ↓ depends on
┌─────────────────────────────────────────┐
│       INFRASTRUCTURE LAYER              │  (I/O, external systems)
│  Storage, Transport, RPC, Hyperlane     │
└─────────────────────────────────────────┘
              ↓ depends on
┌─────────────────────────────────────────┐
│         FOUNDATION LAYER                │  (Shared primitives)
│  Types, Error, Utilities, Constants     │
└─────────────────────────────────────────┘
```

**Key Principle**: Domain layer NEVER imports infrastructure. Infrastructure serves domain via trait abstractions.

---

## Architectural Philosophy

### What is Domain Logic?

Domain logic represents the **core business rules** of threshold signing:

- **Event validation** - Is this signing event valid and authorized?
- **Policy enforcement** - Does this transaction comply with group policy (destination allowlist, volume limits)?
- **Signing workflow** - What are the steps to coordinate a threshold signature?
- **PSKT construction** - How do we build a valid Partially Signed Kaspa Transaction?
- **Signature aggregation** - How do we combine m-of-n partial signatures?

**Characteristics**:
- ✅ Pure functions (deterministic, no side effects)
- ✅ Business rule validation
- ✅ State transitions and workflow logic
- ✅ Cryptographic operations (as business rules)
- ❌ No database calls
- ❌ No network I/O
- ❌ No file system access

### What is Infrastructure?

Infrastructure provides **capabilities that interact with the external world**:

- **Storage** - Persisting events, requests, signatures (RocksDB)
- **Transport** - P2P communication via gossip (Iroh)
- **RPC** - Kaspa node communication (gRPC)
- **Hyperlane ISM** - Cross-chain message verification (HTTP API)
- **Configuration** - Loading config from files, env vars, database
- **Audit** - Writing audit logs to storage
- **Rate limiting** - Tracking request rates per peer

**Characteristics**:
- ✅ I/O operations (network, disk, external APIs)
- ✅ Protocol implementations (gRPC, gossip, REST)
- ✅ Resource management (connections, file handles)
- ✅ Caching and performance optimizations
- ❌ No business logic
- ❌ No policy decisions

### The Dependency Rule

**Critical architectural constraint**:

```
Infrastructure → Domain ✅ (Infrastructure uses domain)
Domain → Infrastructure ❌ (FORBIDDEN - domain must not know about infrastructure)
```

**How this works in practice**:

```rust
// ❌ BAD: Domain logic directly calling infrastructure
pub fn validate_event(event: &SigningEvent, storage: &dyn Storage) -> Result<bool> {
    let policy = storage.get_group_policy(&event.group_id)?;  // Domain depends on Storage!
    check_policy(event, &policy)
}

// ✅ GOOD: Domain receives data, infrastructure handles I/O
pub fn validate_event(event: &SigningEvent, policy: &GroupPolicy) -> Result<bool> {
    check_policy(event, policy)  // Pure function, no I/O
}

// Infrastructure orchestrates:
pub async fn handle_event(storage: &dyn Storage, event: SigningEvent) -> Result<()> {
    let policy = storage.get_group_policy(&event.group_id).await?;  // I/O
    domain::validate_event(&event, &policy)?;  // Pure logic
    Ok(())
}
```

---

## Current Architecture Analysis

### Current Module Structure

```
igra-core/src/
├── audit/                 # MIXED: Audit trait (domain) + storage calls (infra)
├── config/                # INFRASTRUCTURE: File/env/DB config loading
├── coordination/          # MIXED: Workflow logic + storage/transport
│   ├── coordinator.rs     # Orchestration + storage + transport
│   ├── signer.rs          # Validation + storage + transport
│   ├── hashes.rs          # Domain logic (pure crypto)
│   ├── monitoring.rs      # Infrastructure (logging)
│   └── threshold.rs       # Domain logic (threshold checks)
├── event/                 # MIXED: Event types + processing + storage
├── hyperlane/             # INFRASTRUCTURE: Cross-chain verification API
├── kaspa_integration/     # INFRASTRUCTURE: Kaspa node RPC
├── pskt/                  # DOMAIN: PSKT building logic
│   ├── builder.rs         # Domain (transaction construction)
│   └── multisig.rs        # Domain (multisig script logic)
├── rpc/                   # INFRASTRUCTURE: Kaspa node gRPC
├── signing/               # DOMAIN: Cryptographic signing
│   ├── musig2.rs          # Domain (MuSig2 protocol)
│   ├── threshold.rs       # Domain (threshold sig)
│   └── mpc.rs             # Domain (MPC protocols)
├── storage/               # INFRASTRUCTURE: RocksDB persistence
│   ├── mod.rs             # Storage trait + RocksDB impl
│   └── rocks.rs           # RocksDB specifics
├── transport/             # INFRASTRUCTURE: P2P gossip
│   ├── mod.rs             # Transport trait
│   ├── messages.rs        # Message types (could be domain)
│   ├── identity.rs        # Peer identity (could be domain)
│   └── mock.rs            # Test infrastructure
├── validation/            # MIXED: Validation logic + message verification
├── state_machine.rs       # DOMAIN: Request lifecycle FSM
├── lifecycle.rs           # DOMAIN: Lifecycle observer trait
├── rate_limit.rs          # INFRASTRUCTURE: Rate limiting
├── model.rs               # FOUNDATION: Core types
├── types.rs               # FOUNDATION: ID types
├── error.rs               # FOUNDATION: Error types
└── util/                  # FOUNDATION: Utilities
```

### Problems with Current Structure

#### 1. **Signer mixes domain and infrastructure** (coordination/signer.rs)

```rust
pub struct Signer {
    transport: Arc<dyn Transport>,   // INFRASTRUCTURE
    storage: Arc<dyn Storage>,       // INFRASTRUCTURE
    lifecycle: Arc<dyn LifecycleObserver>,
}

impl Signer {
    pub fn validate_proposal(&self, ...) -> Result<SignerAck> {
        // Domain logic: hash computation, validation
        let computed_hash = event_hash(&signing_event)?;

        // Infrastructure: storage calls mixed in
        self.storage.insert_event(expected_event_hash, signing_event.clone())?;

        // Domain logic: policy checks
        if let Some(policy) = policy {
            self.check_policy(&signing_event, policy)?;
        }

        // Infrastructure: transport calls
        self.transport.publish_ack(&ack).await?;
    }
}
```

**Issue**: Cannot test validation logic without mocking storage/transport.

#### 2. **Event module mixes types and I/O** (event/mod.rs)

Contains both:
- Event types (`SigningEvent`, `EventSource`) - DOMAIN
- Event processing with storage - INFRASTRUCTURE
- Message verification - INFRASTRUCTURE

#### 3. **Coordination module is monolithic**

The `coordination/` module contains:
- Pure hash functions (`hashes.rs`) - DOMAIN
- Threshold checking (`threshold.rs`) - DOMAIN
- Orchestration with I/O (`coordinator.rs`, `signer.rs`) - MIXED
- Monitoring/logging (`monitoring.rs`) - INFRASTRUCTURE

#### 4. **No clear testing boundaries**

Testing domain logic requires:
- Setting up RocksDB
- Mocking transport layer
- Complex test fixtures

---

## Proposed Architecture

### New Module Structure

```
igra-core/src/
├── domain/                          # 🎯 PURE BUSINESS LOGIC (no I/O)
│   ├── mod.rs
│   │
│   ├── event/                       # Event domain model
│   │   ├── mod.rs
│   │   ├── types.rs                 # SigningEvent, EventMetadata
│   │   ├── validation.rs            # Event validation rules
│   │   └── hashing.rs               # Event hash computation
│   │
│   ├── request/                     # Request lifecycle
│   │   ├── mod.rs
│   │   ├── types.rs                 # SigningRequest, RequestDecision
│   │   ├── state_machine.rs         # FSM: Pending → Approved → Finalized
│   │   └── validation.rs            # Request validation rules
│   │
│   ├── policy/                      # Policy enforcement
│   │   ├── mod.rs
│   │   ├── types.rs                 # GroupPolicy, PolicyRule
│   │   ├── enforcement.rs           # Policy checking logic
│   │   └── volume_limits.rs         # Volume limit calculations
│   │
│   ├── signing/                     # Signing workflows
│   │   ├── mod.rs
│   │   ├── musig2.rs                # MuSig2 protocol
│   │   ├── threshold.rs             # Threshold signature protocol
│   │   ├── mpc.rs                   # MPC primitives
│   │   └── aggregation.rs           # Signature aggregation
│   │
│   ├── pskt/                        # PSKT construction
│   │   ├── mod.rs
│   │   ├── builder.rs               # Transaction builder
│   │   ├── multisig.rs              # Multisig script logic
│   │   ├── fee.rs                   # Fee calculation
│   │   └── validation.rs            # PSKT validation
│   │
│   ├── coordination/                # Coordination workflow (pure logic)
│   │   ├── mod.rs
│   │   ├── proposal.rs              # Proposal validation logic
│   │   ├── acknowledgment.rs        # Ack collection logic
│   │   ├── signature_collection.rs  # Signature collection logic
│   │   ├── finalization.rs          # Finalization logic
│   │   └── timeout.rs               # Timeout calculation
│   │
│   └── audit/                       # Audit event generation (pure)
│       ├── mod.rs
│       ├── types.rs                 # AuditEvent, PolicyDecision
│       └── builder.rs               # Audit event builders
│
├── infrastructure/                  # 🔌 I/O AND EXTERNAL SYSTEMS
│   ├── mod.rs
│   │
│   ├── storage/                     # Persistence layer
│   │   ├── mod.rs                   # Storage trait
│   │   ├── rocks/                   # RocksDB implementation
│   │   │   ├── mod.rs
│   │   │   ├── schema.rs            # Key/value schema
│   │   │   └── migration.rs         # Schema migrations
│   │   ├── memory.rs                # In-memory (testing)
│   │   └── audit_writer.rs          # Audit log persistence
│   │
│   ├── transport/                   # P2P communication
│   │   ├── mod.rs                   # Transport trait
│   │   ├── iroh/                    # Iroh gossip implementation
│   │   │   ├── mod.rs
│   │   │   ├── client.rs
│   │   │   └── config.rs
│   │   ├── mock.rs                  # Mock transport (testing)
│   │   └── rate_limiter.rs          # Rate limiting
│   │
│   ├── rpc/                         # Kaspa node RPC
│   │   ├── mod.rs                   # RPC trait
│   │   ├── grpc.rs                  # gRPC implementation
│   │   ├── circuit_breaker.rs       # Resilience patterns
│   │   └── retry.rs                 # Retry logic
│   │
│   ├── hyperlane/                   # Cross-chain verification
│   │   ├── mod.rs                   # Hyperlane client trait
│   │   ├── ism_client.rs            # ISM API client
│   │   └── types.rs                 # API types
│   │
│   ├── config/                      # Configuration loading
│   │   ├── mod.rs
│   │   ├── loader.rs                # File/env/DB loading
│   │   ├── validation.rs            # Config validation
│   │   └── persistence.rs           # Config persistence
│   │
│   └── observability/               # Metrics and monitoring
│       ├── mod.rs
│       ├── metrics.rs               # Prometheus metrics
│       ├── tracing.rs               # Distributed tracing
│       └── health.rs                # Health checks
│
├── application/                     # 🎮 ORCHESTRATION LAYER
│   ├── mod.rs
│   │
│   ├── coordinator.rs               # Coordinator orchestration
│   ├── signer.rs                    # Signer orchestration
│   ├── event_processor.rs           # Event processing orchestration
│   └── lifecycle.rs                 # Lifecycle hooks
│
├── foundation/                      # 🧱 SHARED PRIMITIVES
│   ├── mod.rs
│   │
│   ├── types/                       # Type definitions
│   │   ├── mod.rs
│   │   ├── ids.rs                   # RequestId, SessionId, PeerId
│   │   ├── primitives.rs            # Hash32, AmountSompi
│   │   ├── addresses.rs             # Kaspa addresses
│   │   └── time.rs                  # TimestampNanos
│   │
│   ├── error.rs                     # Error types
│   │
│   ├── util/                        # Utilities
│   │   ├── mod.rs
│   │   ├── time.rs                  # Time utilities
│   │   ├── encoding.rs              # Hex/base64 encoding
│   │   ├── conversion.rs            # Type conversions
│   │   └── crypto.rs                # Low-level crypto utils
│   │
│   └── constants.rs                 # System-wide constants
│
└── lib.rs                           # Public API surface
```

### Key Changes

1. **domain/** - Pure business logic, no infrastructure dependencies
2. **infrastructure/** - All I/O, external systems, protocols
3. **application/** - Orchestration layer that combines domain + infrastructure
4. **foundation/** - Shared types, errors, utilities (no business logic, no I/O)

---

## Module Classification

### Domain Modules

**Rule**: If it can be tested with pure data (no mocks), it's domain.

| Module | Responsibility | Key Characteristics |
|--------|----------------|---------------------|
| `domain/event` | Event validation, hashing | Pure functions, no storage |
| `domain/request` | Request state machine | Pure FSM, no I/O |
| `domain/policy` | Policy enforcement logic | Pure business rules |
| `domain/signing` | Signing protocols | Pure cryptography |
| `domain/pskt` | PSKT construction | Pure transaction logic |
| `domain/coordination` | Coordination workflow | Pure orchestration logic |
| `domain/audit` | Audit event generation | Pure data transformation |

**Example domain function**:
```rust
/// Validates that an event complies with group policy.
///
/// This is a pure function - testable with just data.
pub fn enforce_policy(
    event: &SigningEvent,
    policy: &GroupPolicy,
    current_daily_volume: AmountSompi,
) -> Result<(), PolicyViolation> {
    // Pure business logic - no I/O
    if !policy.allowed_destinations.contains(&event.destination_address) {
        return Err(PolicyViolation::DestinationNotAllowed);
    }

    let new_volume = current_daily_volume
        .checked_add(event.amount_sompi)
        .ok_or(PolicyViolation::VolumeOverflow)?;

    if new_volume > policy.daily_limit_sompi {
        return Err(PolicyViolation::DailyLimitExceeded {
            current: current_daily_volume,
            requested: event.amount_sompi,
            limit: policy.daily_limit_sompi,
        });
    }

    Ok(())
}
```

### Infrastructure Modules

**Rule**: If it talks to external systems (network, disk, APIs), it's infrastructure.

| Module | Responsibility | External Dependency |
|--------|----------------|---------------------|
| `infrastructure/storage` | Persistence | RocksDB, filesystem |
| `infrastructure/transport` | P2P gossip | Iroh, network sockets |
| `infrastructure/rpc` | Kaspa node RPC | gRPC, network |
| `infrastructure/hyperlane` | Cross-chain verification | HTTP API |
| `infrastructure/config` | Config loading | Files, env vars, DB |
| `infrastructure/observability` | Metrics, logs | Prometheus, tracing |

**Example infrastructure function**:
```rust
/// Fetches current daily volume from storage.
///
/// This is infrastructure - requires database access.
pub async fn get_daily_volume(
    storage: &dyn Storage,
    group_id: &GroupId,
    day_start: TimestampNanos,
) -> Result<AmountSompi, ThresholdError> {
    let events = storage
        .list_events_since(group_id, day_start)
        .await?;  // I/O operation

    let total = events
        .iter()
        .map(|e| e.amount_sompi)
        .sum();

    Ok(total)
}
```

### Application Layer (Orchestration)

**Rule**: Combines domain + infrastructure, coordinates workflows.

```rust
/// Application-layer coordinator - orchestrates domain + infrastructure.
pub struct CoordinatorService {
    // Infrastructure dependencies
    transport: Arc<dyn Transport>,
    storage: Arc<dyn Storage>,
    rpc: Arc<dyn NodeRpc>,

    // Observability
    metrics: Arc<Metrics>,
}

impl CoordinatorService {
    /// Handles a new signing event - orchestrates full workflow.
    pub async fn handle_event(
        &self,
        session_id: SessionId,
        request_id: RequestId,
        event: SigningEvent,
    ) -> Result<Hash32, ThresholdError> {
        // 1. Domain: Validate event structure
        domain::event::validate_structure(&event)?;

        // 2. Domain: Compute event hash
        let event_hash = domain::event::compute_hash(&event)?;

        // 3. Infrastructure: Load policy from storage
        let policy = self.storage
            .get_group_policy(&event.group_id)
            .await?;

        // 4. Infrastructure: Get current daily volume
        let day_start = domain::time::day_start_nanos(event.timestamp_nanos);
        let volume = infrastructure::storage::get_daily_volume(
            &*self.storage,
            &event.group_id,
            day_start,
        ).await?;

        // 5. Domain: Enforce policy
        domain::policy::enforce_policy(&event, &policy, volume)?;

        // 6. Infrastructure: Fetch UTXOs from Kaspa node
        let utxos = self.rpc
            .get_utxos_by_addresses(&[event.destination_address.clone()])
            .await?;

        // 7. Domain: Build PSKT
        let pskt = domain::pskt::build_transaction(
            &event,
            &utxos,
            &policy.change_address,
        )?;

        // 8. Infrastructure: Store event and request
        self.storage.insert_event(event_hash, event.clone()).await?;
        self.storage.insert_request(request).await?;

        // 9. Infrastructure: Broadcast proposal
        self.transport.broadcast_proposal(&proposal).await?;

        // 10. Observability: Record metrics
        self.metrics.events_processed.inc();

        Ok(event_hash)
    }
}
```

### Foundation Layer

**Rule**: Shared primitives used by all layers - no business logic, no I/O.

| Module | Contents | Used By |
|--------|----------|---------|
| `foundation/types` | IDs, primitives, addresses | All layers |
| `foundation/error` | Error types | All layers |
| `foundation/util` | Time, encoding, conversions | All layers |
| `foundation/constants` | System constants | All layers |

---

## Detailed Module Map

### Domain Layer Deep Dive

#### domain/event/

```rust
// domain/event/types.rs
pub struct SigningEvent {
    pub event_id: String,
    pub group_id: GroupId,
    pub destination_address: Address,
    pub amount_sompi: AmountSompi,
    pub timestamp_nanos: TimestampNanos,
    pub metadata: HashMap<String, String>,
}

// domain/event/validation.rs
pub fn validate_structure(event: &SigningEvent) -> Result<(), ValidationError> {
    if event.amount_sompi == 0 {
        return Err(ValidationError::ZeroAmount);
    }

    if event.event_id.is_empty() {
        return Err(ValidationError::MissingEventId);
    }

    // No I/O - pure validation
    Ok(())
}

// domain/event/hashing.rs
pub fn compute_hash(event: &SigningEvent) -> Result<Hash32, ThresholdError> {
    // Pure cryptographic operation
    let mut hasher = Blake3Hasher::new();
    hasher.update(event.event_id.as_bytes());
    hasher.update(&event.group_id.0);
    hasher.update(event.destination_address.as_bytes());
    hasher.update(&event.amount_sompi.to_le_bytes());
    hasher.update(&event.timestamp_nanos.to_le_bytes());

    Ok(Hash32(hasher.finalize().into()))
}
```

#### domain/policy/

```rust
// domain/policy/types.rs
pub struct GroupPolicy {
    pub allowed_destinations: Vec<Address>,
    pub daily_limit_sompi: AmountSompi,
    pub per_transaction_limit_sompi: AmountSompi,
    pub require_approval_above_sompi: AmountSompi,
}

pub enum PolicyViolation {
    DestinationNotAllowed { destination: Address },
    DailyLimitExceeded { current: AmountSompi, requested: AmountSompi, limit: AmountSompi },
    PerTransactionLimitExceeded { requested: AmountSompi, limit: AmountSompi },
}

// domain/policy/enforcement.rs
pub fn enforce_policy(
    event: &SigningEvent,
    policy: &GroupPolicy,
    current_daily_volume: AmountSompi,
) -> Result<(), PolicyViolation> {
    // All pure logic - no storage/network

    // Check destination allowlist
    if !policy.allowed_destinations.contains(&event.destination_address) {
        return Err(PolicyViolation::DestinationNotAllowed {
            destination: event.destination_address.clone(),
        });
    }

    // Check per-transaction limit
    if event.amount_sompi > policy.per_transaction_limit_sompi {
        return Err(PolicyViolation::PerTransactionLimitExceeded {
            requested: event.amount_sompi,
            limit: policy.per_transaction_limit_sompi,
        });
    }

    // Check daily limit
    let new_volume = current_daily_volume
        .checked_add(event.amount_sompi)
        .ok_or(PolicyViolation::VolumeOverflow)?;

    if new_volume > policy.daily_limit_sompi {
        return Err(PolicyViolation::DailyLimitExceeded {
            current: current_daily_volume,
            requested: event.amount_sompi,
            limit: policy.daily_limit_sompi,
        });
    }

    Ok(())
}
```

#### domain/coordination/

```rust
// domain/coordination/proposal.rs
pub struct ProposalValidation {
    pub event_hash_valid: bool,
    pub transaction_hash_valid: bool,
    pub validation_hash_valid: bool,
    pub policy_compliant: bool,
    pub accept: bool,
    pub rejection_reason: Option<String>,
}

pub fn validate_proposal(
    event: &SigningEvent,
    event_hash_expected: Hash32,
    pskt: &Pskt,
    transaction_hash_expected: Hash32,
    validation_hash_expected: Hash32,
    policy: &GroupPolicy,
    current_volume: AmountSompi,
) -> Result<ProposalValidation, ThresholdError> {
    // All pure validation - no I/O

    // Verify event hash
    let event_hash_computed = domain::event::compute_hash(event)?;
    let event_hash_valid = bool::from(event_hash_computed.ct_eq(&event_hash_expected));

    if !event_hash_valid {
        return Ok(ProposalValidation {
            event_hash_valid: false,
            accept: false,
            rejection_reason: Some("event_hash_mismatch".into()),
            ..Default::default()
        });
    }

    // Verify transaction hash
    let tx_hash_computed = domain::pskt::compute_transaction_hash(pskt)?;
    let transaction_hash_valid = bool::from(tx_hash_computed.ct_eq(&transaction_hash_expected));

    if !transaction_hash_valid {
        return Ok(ProposalValidation {
            event_hash_valid: true,
            transaction_hash_valid: false,
            accept: false,
            rejection_reason: Some("transaction_hash_mismatch".into()),
            ..Default::default()
        });
    }

    // Verify validation hash (composite)
    let validation_hash_computed = domain::coordination::compute_validation_hash(
        &event_hash_expected,
        &transaction_hash_expected,
        pskt,
    )?;
    let validation_hash_valid = bool::from(validation_hash_computed.ct_eq(&validation_hash_expected));

    if !validation_hash_valid {
        return Ok(ProposalValidation {
            event_hash_valid: true,
            transaction_hash_valid: true,
            validation_hash_valid: false,
            accept: false,
            rejection_reason: Some("validation_hash_mismatch".into()),
            ..Default::default()
        });
    }

    // Enforce policy
    let policy_compliant = domain::policy::enforce_policy(event, policy, current_volume).is_ok();

    if !policy_compliant {
        return Ok(ProposalValidation {
            event_hash_valid: true,
            transaction_hash_valid: true,
            validation_hash_valid: true,
            policy_compliant: false,
            accept: false,
            rejection_reason: Some("policy_violation".into()),
        });
    }

    // All checks passed
    Ok(ProposalValidation {
        event_hash_valid: true,
        transaction_hash_valid: true,
        validation_hash_valid: true,
        policy_compliant: true,
        accept: true,
        rejection_reason: None,
    })
}
```

### Infrastructure Layer Deep Dive

#### infrastructure/storage/

```rust
// infrastructure/storage/mod.rs
#[async_trait]
pub trait Storage: Send + Sync {
    // Event operations
    async fn insert_event(&self, event_hash: Hash32, event: SigningEvent) -> Result<()>;
    async fn get_event(&self, event_hash: &Hash32) -> Result<Option<SigningEvent>>;
    async fn list_events_since(&self, group_id: &GroupId, since: TimestampNanos) -> Result<Vec<SigningEvent>>;

    // Request operations
    async fn insert_request(&self, request: SigningRequest) -> Result<()>;
    async fn get_request(&self, request_id: &RequestId) -> Result<Option<SigningRequest>>;
    async fn update_request_decision(&self, request_id: &RequestId, decision: RequestDecision) -> Result<()>;

    // Policy operations
    async fn get_group_policy(&self, group_id: &GroupId) -> Result<Option<GroupPolicy>>;
    async fn upsert_group_policy(&self, group_id: GroupId, policy: GroupPolicy) -> Result<()>;

    // Signature operations
    async fn insert_partial_sig(&self, request_id: &RequestId, sig: PartialSigRecord) -> Result<()>;
    async fn list_partial_sigs(&self, request_id: &RequestId) -> Result<Vec<PartialSigRecord>>;

    // Audit operations
    async fn append_audit_event(&self, event: AuditEvent) -> Result<()>;

    // Health check
    fn health_check(&self) -> Result<()>;
}

// infrastructure/storage/rocks/mod.rs
pub struct RocksStorage {
    db: Arc<DB>,
    cf_events: ColumnFamily,
    cf_requests: ColumnFamily,
    cf_policies: ColumnFamily,
    cf_signatures: ColumnFamily,
    cf_audit: ColumnFamily,
}

#[async_trait]
impl Storage for RocksStorage {
    async fn insert_event(&self, event_hash: Hash32, event: SigningEvent) -> Result<()> {
        let key = schema::event_key(&event_hash);
        let value = bincode::serialize(&event)?;

        self.db.put_cf(&self.cf_events, key, value)?;
        Ok(())
    }

    // ... RocksDB-specific implementations
}
```

#### infrastructure/transport/

```rust
// infrastructure/transport/mod.rs
#[async_trait]
pub trait Transport: Send + Sync {
    // Proposal broadcasting (coordinator → signers)
    async fn broadcast_proposal(&self, proposal: &Proposal) -> Result<()>;

    // Acknowledgment submission (signer → coordinator)
    async fn send_ack(&self, coordinator_peer_id: &PeerId, ack: &SignerAck) -> Result<()>;

    // Signature submission (signer → coordinator)
    async fn send_partial_signatures(&self, coordinator_peer_id: &PeerId, sigs: &[PartialSig]) -> Result<()>;

    // Finalization notification (coordinator → signers)
    async fn notify_finalization(&self, finalization: &Finalization) -> Result<()>;

    // Subscribe to messages
    async fn subscribe(&self) -> Result<mpsc::Receiver<TransportMessage>>;

    // Identity
    fn peer_id(&self) -> PeerId;
}

// infrastructure/transport/iroh/mod.rs
pub struct IrohTransport {
    client: iroh::Client,
    topic: iroh::TopicId,
    peer_id: PeerId,
}

#[async_trait]
impl Transport for IrohTransport {
    async fn broadcast_proposal(&self, proposal: &Proposal) -> Result<()> {
        let payload = bincode::serialize(proposal)?;

        self.client
            .publish(self.topic, payload)
            .await?;

        Ok(())
    }

    // ... Iroh-specific implementations
}
```

#### infrastructure/rpc/

```rust
// infrastructure/rpc/mod.rs
#[async_trait]
pub trait NodeRpc: Send + Sync {
    // DAG info
    async fn get_blue_score(&self) -> Result<u64>;
    async fn get_block_dag_info(&self) -> Result<BlockDagInfo>;

    // UTXO queries
    async fn get_utxos_by_addresses(&self, addresses: &[Address]) -> Result<Vec<UtxoEntry>>;

    // Transaction submission
    async fn submit_transaction(&self, tx: &Transaction) -> Result<TransactionId>;
    async fn get_transaction(&self, tx_id: &TransactionId) -> Result<Option<Transaction>>;

    // Fee estimation
    async fn estimate_fee(&self, tx: &Transaction) -> Result<u64>;
}

// infrastructure/rpc/grpc.rs
pub struct GrpcNodeRpc {
    client: KaspaRpcClient,
    url: String,
}

#[async_trait]
impl NodeRpc for GrpcNodeRpc {
    async fn get_blue_score(&self) -> Result<u64> {
        let response = self.client
            .get_block_dag_info()
            .await?;

        Ok(response.blue_score)
    }

    async fn get_utxos_by_addresses(&self, addresses: &[Address]) -> Result<Vec<UtxoEntry>> {
        let request = GetUtxosByAddressesRequest {
            addresses: addresses.iter().map(|a| a.to_string()).collect(),
        };

        let response = self.client
            .get_utxos_by_addresses(request)
            .await?;

        // Convert gRPC types to domain types
        let utxos = response.entries
            .into_iter()
            .map(|e| UtxoEntry::from_grpc(e))
            .collect();

        Ok(utxos)
    }

    // ... gRPC-specific implementations
}
```

### Application Layer (Orchestration)

#### application/coordinator.rs

```rust
/// Application-layer coordinator - combines domain + infrastructure.
pub struct CoordinatorService {
    // Infrastructure
    transport: Arc<dyn Transport>,
    storage: Arc<dyn Storage>,
    rpc: Arc<dyn NodeRpc>,
    hyperlane: Arc<dyn HyperlaneClient>,

    // Configuration
    config: CoordinatorConfig,

    // Observability
    metrics: Arc<Metrics>,
    lifecycle: Arc<dyn LifecycleObserver>,
}

impl CoordinatorService {
    /// Orchestrates the full signing workflow.
    pub async fn initiate_signing(
        &self,
        session_id: SessionId,
        request_id: RequestId,
        event: SigningEvent,
        expires_at: TimestampNanos,
    ) -> Result<Hash32, ThresholdError> {
        let _timer = self.metrics.coordination_duration.start_timer();

        // === DOMAIN: Validate event structure ===
        domain::event::validate_structure(&event)?;

        // === DOMAIN: Compute event hash ===
        let event_hash = domain::event::compute_hash(&event)?;

        // === INFRASTRUCTURE: Verify cross-chain message (if applicable) ===
        if let Some(hyperlane_metadata) = &event.hyperlane_metadata {
            self.hyperlane
                .verify_message(hyperlane_metadata)
                .await?;
        }

        // === INFRASTRUCTURE: Load group policy ===
        let policy = self.storage
            .get_group_policy(&event.group_id)
            .await?
            .ok_or(ThresholdError::GroupNotFound)?;

        // === INFRASTRUCTURE: Calculate current daily volume ===
        let day_start = domain::time::day_start_nanos(event.timestamp_nanos);
        let current_volume = self.calculate_daily_volume(&event.group_id, day_start).await?;

        // === DOMAIN: Enforce policy ===
        domain::policy::enforce_policy(&event, &policy, current_volume)?;

        // === INFRASTRUCTURE: Fetch UTXOs from Kaspa node ===
        let multisig_address = &policy.multisig_address;
        let utxos = self.rpc
            .get_utxos_by_addresses(&[multisig_address.clone()])
            .await?;

        if utxos.is_empty() {
            return Err(ThresholdError::InsufficientFunds {
                required: event.amount_sompi,
                available: 0,
            });
        }

        // === DOMAIN: Build PSKT ===
        let pskt = domain::pskt::build_transaction(
            &event,
            &utxos,
            &policy.change_address,
            &policy.fee_config,
        )?;

        // === DOMAIN: Compute transaction hash ===
        let tx_hash = domain::pskt::compute_transaction_hash(&pskt)?;

        // === DOMAIN: Compute validation hash ===
        let validation_hash = domain::coordination::compute_validation_hash(
            &event_hash,
            &tx_hash,
            &pskt,
        )?;

        // === DOMAIN: Create signing request ===
        let request = domain::request::SigningRequest {
            request_id: request_id.clone(),
            session_id,
            group_id: event.group_id.clone(),
            event_hash,
            transaction_hash: tx_hash,
            validation_hash,
            expires_at_nanos: expires_at,
            decision: domain::request::RequestDecision::Pending,
            created_at: domain::time::current_timestamp_nanos()?,
        };

        // === INFRASTRUCTURE: Persist event and request ===
        self.storage.insert_event(event_hash, event.clone()).await?;
        self.storage.insert_request(request.clone()).await?;

        // === INFRASTRUCTURE: Store PSKT ===
        let pskt_bytes = bincode::serialize(&pskt)?;
        self.storage.store_proposal(&request_id, pskt_bytes).await?;

        // === DOMAIN: Generate audit event ===
        let audit_event = domain::audit::build_proposal_created_event(
            &request_id,
            &event,
            &event_hash,
        );

        // === INFRASTRUCTURE: Write audit log ===
        self.storage.append_audit_event(audit_event).await?;

        // === INFRASTRUCTURE: Broadcast proposal to signers ===
        let proposal = Proposal {
            session_id,
            request_id: request_id.clone(),
            coordinator_peer_id: self.transport.peer_id(),
            signing_event: event,
            event_hash,
            pskt_bytes,
            tx_hash,
            validation_hash,
            expires_at_nanos: expires_at,
        };

        self.transport.broadcast_proposal(&proposal).await?;

        // === OBSERVABILITY: Lifecycle hook ===
        self.lifecycle.on_proposal_created(&request);

        // === OBSERVABILITY: Metrics ===
        self.metrics.proposals_created.inc();

        Ok(event_hash)
    }

    /// Helper: Calculate daily volume (infrastructure + domain).
    async fn calculate_daily_volume(
        &self,
        group_id: &GroupId,
        day_start: TimestampNanos,
    ) -> Result<AmountSompi> {
        // Infrastructure: Fetch events
        let events = self.storage
            .list_events_since(group_id, day_start)
            .await?;

        // Domain: Sum amounts
        let total = domain::policy::calculate_volume(&events);

        Ok(total)
    }
}
```

#### application/signer.rs

```rust
/// Application-layer signer - combines domain + infrastructure.
pub struct SignerService {
    // Infrastructure
    transport: Arc<dyn Transport>,
    storage: Arc<dyn Storage>,
    signing_backend: Arc<dyn SignerBackend>,

    // Configuration
    config: SignerConfig,

    // Observability
    metrics: Arc<Metrics>,
    lifecycle: Arc<dyn LifecycleObserver>,
}

impl SignerService {
    /// Handles incoming proposal from coordinator.
    pub async fn handle_proposal(&self, proposal: Proposal) -> Result<()> {
        let _timer = self.metrics.proposal_validation_duration.start_timer();

        // === INFRASTRUCTURE: Load group policy ===
        let policy = self.storage
            .get_group_policy(&proposal.signing_event.group_id)
            .await?
            .ok_or(ThresholdError::GroupNotFound)?;

        // === INFRASTRUCTURE: Calculate current daily volume ===
        let day_start = domain::time::day_start_nanos(proposal.signing_event.timestamp_nanos);
        let current_volume = self.calculate_daily_volume(
            &proposal.signing_event.group_id,
            day_start,
        ).await?;

        // === INFRASTRUCTURE: Deserialize PSKT ===
        let pskt: Pskt = bincode::deserialize(&proposal.pskt_bytes)?;

        // === DOMAIN: Validate proposal ===
        let validation = domain::coordination::validate_proposal(
            &proposal.signing_event,
            proposal.event_hash,
            &pskt,
            proposal.tx_hash,
            proposal.validation_hash,
            &policy,
            current_volume,
        )?;

        // === INFRASTRUCTURE: Persist validation result ===
        let ack_record = SignerAckRecord {
            request_id: proposal.request_id.clone(),
            signer_peer_id: self.transport.peer_id(),
            accept: validation.accept,
            reason: validation.rejection_reason.clone(),
            timestamp_nanos: domain::time::current_timestamp_nanos()?,
        };

        self.storage
            .insert_signer_ack(&proposal.request_id, ack_record.clone())
            .await?;

        // === INFRASTRUCTURE: Send acknowledgment to coordinator ===
        let ack = SignerAck {
            request_id: proposal.request_id.clone(),
            signer_peer_id: self.transport.peer_id(),
            accept: validation.accept,
            reason: validation.rejection_reason,
        };

        self.transport
            .send_ack(&proposal.coordinator_peer_id, &ack)
            .await?;

        // === DOMAIN + INFRASTRUCTURE: Sign if accepted ===
        if validation.accept {
            self.sign_and_submit(proposal, pskt).await?;
        }

        // === OBSERVABILITY: Metrics ===
        if validation.accept {
            self.metrics.proposals_accepted.inc();
        } else {
            self.metrics.proposals_rejected.inc();
        }

        Ok(())
    }

    /// Signs PSKT and submits partial signatures.
    async fn sign_and_submit(&self, proposal: Proposal, pskt: Pskt) -> Result<()> {
        // === DOMAIN: Compute sighashes ===
        let sighashes = domain::pskt::compute_sighashes(&pskt)?;

        // === INFRASTRUCTURE: Sign with backend ===
        let signatures = self.signing_backend
            .sign_batch(&sighashes)
            .await?;

        // === DOMAIN: Build partial signature records ===
        let partial_sigs: Vec<PartialSig> = signatures
            .into_iter()
            .enumerate()
            .map(|(idx, sig)| PartialSig {
                request_id: proposal.request_id.clone(),
                signer_peer_id: self.transport.peer_id(),
                input_index: idx as u32,
                signature_bytes: sig,
                recovery_id: 0, // TODO: compute recovery ID
            })
            .collect();

        // === INFRASTRUCTURE: Persist signatures ===
        for sig in &partial_sigs {
            let record = PartialSigRecord::from(sig);
            self.storage
                .insert_partial_sig(&proposal.request_id, record)
                .await?;
        }

        // === INFRASTRUCTURE: Submit to coordinator ===
        self.transport
            .send_partial_signatures(&proposal.coordinator_peer_id, &partial_sigs)
            .await?;

        // === OBSERVABILITY: Metrics ===
        self.metrics.signatures_submitted.inc_by(partial_sigs.len() as u64);

        Ok(())
    }

    async fn calculate_daily_volume(
        &self,
        group_id: &GroupId,
        day_start: TimestampNanos,
    ) -> Result<AmountSompi> {
        let events = self.storage
            .list_events_since(group_id, day_start)
            .await?;

        Ok(domain::policy::calculate_volume(&events))
    }
}
```

---

## Design Principles

### 1. Dependency Inversion Principle (DIP)

**High-level modules (domain) should not depend on low-level modules (infrastructure).**

```rust
// ❌ BAD: Domain depends on concrete infrastructure
use crate::storage::RocksStorage;

pub fn process_event(event: SigningEvent, storage: &RocksStorage) -> Result<()> {
    // Domain logic tightly coupled to RocksDB
}

// ✅ GOOD: Domain depends on abstraction
pub fn process_event(event: SigningEvent) -> Result<EventProcessingResult> {
    // Pure domain logic, returns result
    // Infrastructure layer calls this and handles storage
}
```

### 2. Separation of Concerns (SoC)

**Each layer has a single responsibility:**

- **Domain**: Business rules and workflows
- **Infrastructure**: External system integration
- **Application**: Orchestration and coordination
- **Foundation**: Shared primitives

### 3. Ports and Adapters (Hexagonal Architecture)

**Domain defines "ports" (interfaces), infrastructure provides "adapters" (implementations).**

```rust
// Domain defines the port (what it needs)
pub trait PolicyRepository {
    fn get_policy(&self, group_id: &GroupId) -> Result<GroupPolicy>;
}

// Infrastructure provides adapter (how it's implemented)
impl PolicyRepository for RocksStorage {
    fn get_policy(&self, group_id: &GroupId) -> Result<GroupPolicy> {
        // RocksDB-specific implementation
    }
}
```

### 4. Pure Functions Where Possible

**Domain logic should be pure functions (deterministic, no side effects).**

```rust
// ✅ Pure function - easy to test
pub fn calculate_fee(
    amount: AmountSompi,
    fee_rate: u64,
) -> Result<AmountSompi> {
    amount
        .checked_mul(fee_rate)
        .and_then(|v| v.checked_div(1_000_000))
        .ok_or(ThresholdError::ArithmeticOverflow)
}

// ❌ Impure function - hard to test
pub async fn calculate_fee(
    amount: AmountSompi,
    rpc: &dyn NodeRpc,
) -> Result<AmountSompi> {
    let fee_rate = rpc.get_fee_rate().await?;  // Side effect: network I/O
    // ...
}
```

### 5. Command-Query Separation (CQS)

**Separate functions that change state (commands) from those that return data (queries).**

```rust
// Query (read-only, no side effects)
pub fn validate_policy(event: &SigningEvent, policy: &GroupPolicy) -> Result<bool> {
    // Pure validation
}

// Command (changes state, returns nothing or simple acknowledgment)
pub async fn store_event(storage: &dyn Storage, event: SigningEvent) -> Result<()> {
    storage.insert_event(event).await
}
```

### 6. Interface Segregation Principle (ISP)

**Don't force modules to depend on interfaces they don't use.**

```rust
// ❌ BAD: Fat interface
pub trait Storage {
    fn insert_event(...);
    fn get_event(...);
    fn insert_request(...);
    fn get_request(...);
    fn insert_signature(...);
    fn get_signature(...);
    // ... 50 more methods
}

// ✅ GOOD: Segregated interfaces
pub trait EventStorage {
    fn insert_event(...);
    fn get_event(...);
}

pub trait RequestStorage {
    fn insert_request(...);
    fn get_request(...);
}

pub trait SignatureStorage {
    fn insert_signature(...);
    fn get_signature(...);
}

// Combine when needed
pub trait Storage: EventStorage + RequestStorage + SignatureStorage {}
```

---

## Migration Strategy

### Phase 1: Create Foundation Layer (Week 1)

**Goal**: Extract shared types and utilities into `foundation/`.

**Steps**:

1. Create `foundation/` directory structure
2. Move `types.rs` → `foundation/types/`
3. Move `error.rs` → `foundation/error.rs`
4. Move `util/` → `foundation/util/`
5. Create `foundation/constants.rs` for magic numbers
6. Update imports across codebase

**Risk**: Low - purely organizational

**Testing**: Ensure all existing tests pass

### Phase 2: Extract Domain Logic (Weeks 2-3)

**Goal**: Create `domain/` layer with pure business logic.

**Steps**:

1. **Create `domain/event/`**
   - Extract event types from `model.rs`
   - Extract hash functions from `coordination/hashes.rs`
   - Add pure validation functions

2. **Create `domain/policy/`**
   - Extract policy types
   - Extract policy enforcement logic
   - Remove storage dependencies

3. **Create `domain/pskt/`**
   - Move `pskt/` module
   - Ensure no RPC dependencies

4. **Create `domain/request/`**
   - Extract request types
   - Extract state machine logic

5. **Create `domain/coordination/`**
   - Extract pure coordination logic
   - Remove transport/storage dependencies

**Risk**: Medium - requires careful extraction

**Testing**: Write comprehensive unit tests for each domain module (no mocks needed!)

### Phase 3: Organize Infrastructure (Week 4)

**Goal**: Move all I/O code into `infrastructure/`.

**Steps**:

1. Move `storage/` → `infrastructure/storage/`
2. Move `transport/` → `infrastructure/transport/`
3. Move `rpc/` → `infrastructure/rpc/`
4. Move `hyperlane/` → `infrastructure/hyperlane/`
5. Move `config/` → `infrastructure/config/`
6. Create `infrastructure/observability/` for metrics

**Risk**: Low - mostly moving files

**Testing**: Integration tests remain unchanged

### Phase 4: Create Application Layer (Week 5)

**Goal**: Build orchestration layer that combines domain + infrastructure.

**Steps**:

1. Create `application/coordinator.rs`
   - Extract orchestration from `coordination/coordinator.rs`
   - Use domain functions + infrastructure I/O

2. Create `application/signer.rs`
   - Extract orchestration from `coordination/signer.rs`
   - Use domain functions + infrastructure I/O

3. Create `application/event_processor.rs`
   - Extract from `event/mod.rs`

**Risk**: High - requires understanding full workflows

**Testing**: Integration tests, end-to-end tests

### Phase 5: Cleanup and Documentation (Week 6)

**Goal**: Remove old structure, update documentation.

**Steps**:

1. Delete old `coordination/` (logic moved to domain + application)
2. Delete old `event/` (split into domain + infrastructure)
3. Update `lib.rs` public API
4. Update README and architecture docs
5. Add comprehensive examples

**Risk**: Low

**Testing**: Full regression testing

---

## Testing Strategy

### Domain Testing (Unit Tests - No Mocks)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_enforcement_allows_valid_event() {
        // Pure data - no setup needed
        let event = SigningEvent {
            destination_address: addr("kaspa:test123"),
            amount_sompi: 1_000_000,
            // ...
        };

        let policy = GroupPolicy {
            allowed_destinations: vec![addr("kaspa:test123")],
            daily_limit_sompi: 10_000_000,
            per_transaction_limit_sompi: 5_000_000,
        };

        let current_volume = 0;

        // Test pure function
        let result = domain::policy::enforce_policy(&event, &policy, current_volume);

        assert!(result.is_ok());
    }

    #[test]
    fn test_policy_enforcement_rejects_exceeded_daily_limit() {
        let event = SigningEvent {
            destination_address: addr("kaspa:test123"),
            amount_sompi: 1_000_000,
            // ...
        };

        let policy = GroupPolicy {
            allowed_destinations: vec![addr("kaspa:test123")],
            daily_limit_sompi: 10_000_000,
            per_transaction_limit_sompi: 5_000_000,
        };

        let current_volume = 9_500_000;  // Already near limit

        let result = domain::policy::enforce_policy(&event, &policy, current_volume);

        assert!(matches!(result, Err(PolicyViolation::DailyLimitExceeded { .. })));
    }
}
```

### Infrastructure Testing (Integration Tests)

```rust
#[tokio::test]
async fn test_storage_event_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksStorage::open(temp_dir.path()).unwrap();

    let event = SigningEvent {
        event_id: "test-1".into(),
        // ...
    };

    let event_hash = domain::event::compute_hash(&event).unwrap();

    // Test infrastructure
    storage.insert_event(event_hash, event.clone()).await.unwrap();
    let retrieved = storage.get_event(&event_hash).await.unwrap();

    assert_eq!(retrieved, Some(event));
}
```

### Application Testing (End-to-End)

```rust
#[tokio::test]
async fn test_full_signing_workflow() {
    // Setup infrastructure
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(RocksStorage::open(temp_dir.path()).unwrap());
    let transport = Arc::new(MockTransport::new());
    let rpc = Arc::new(MockNodeRpc::new());

    // Setup application
    let coordinator = CoordinatorService::new(
        transport.clone(),
        storage.clone(),
        rpc.clone(),
    );

    // Execute workflow
    let event = SigningEvent { /* ... */ };
    let event_hash = coordinator
        .initiate_signing(session_id, request_id, event, expires_at)
        .await
        .unwrap();

    // Verify end-to-end behavior
    assert!(storage.get_event(&event_hash).await.unwrap().is_some());
    assert_eq!(transport.broadcast_count(), 1);
}
```

---

## Benefits and Tradeoffs

### Benefits

#### 1. **Testability**

| Before | After |
|--------|-------|
| Domain logic requires mocking storage/transport | Domain logic tests with pure data (no mocks) |
| Complex test setup (RocksDB, networking) | Simple unit tests run in milliseconds |
| Integration tests only | Unit + integration + E2E tests |

**Example**:
```rust
// Before: Requires RocksDB setup
#[tokio::test]
async fn test_validate_event() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksStorage::open(temp_dir.path()).unwrap();
    // 50 lines of setup...
}

// After: Pure data
#[test]
fn test_validate_event() {
    let event = SigningEvent { /* ... */ };
    assert!(domain::event::validate(&event).is_ok());
}
```

#### 2. **Maintainability**

- **Clear boundaries** - know exactly where to add new features
- **Reduced coupling** - change storage without touching domain
- **Self-documenting** - architecture matches mental model

#### 3. **Reusability**

- **Domain logic portable** - can be used in CLI, service, WASM
- **Infrastructure swappable** - replace RocksDB with PostgreSQL without touching domain
- **Composition** - combine domain functions in new ways

#### 4. **Security**

- **Audit surface reduced** - domain logic is small, pure, auditable
- **Separation of concerns** - policy enforcement isolated from I/O
- **Testing coverage** - 100% coverage possible for domain (no I/O randomness)

### Tradeoffs

#### 1. **More Code (Initially)**

- More files and modules
- Explicit orchestration in application layer
- Trait definitions for abstractions

**Mitigation**: Code is clearer, easier to navigate. Long-term maintenance improved.

#### 2. **Learning Curve**

- Team must understand layered architecture
- Need to decide: domain vs infrastructure vs application

**Mitigation**: Clear documentation (this doc!), code reviews, examples.

#### 3. **Performance Overhead (Minimal)**

- Function call overhead for abstraction layers
- Serialization/deserialization at boundaries

**Mitigation**:
- Rust inlining eliminates most overhead
- Can use `#[inline]` for hot paths
- Zero-cost abstractions via generics

#### 4. **Initial Refactoring Effort**

- 6 weeks to complete migration
- Risk of breaking existing functionality

**Mitigation**:
- Incremental migration (phase by phase)
- Comprehensive testing at each phase
- Feature freeze during migration

---

## Conclusion

This architecture provides a **clean separation between business logic (domain) and external systems (infrastructure)**, with an orchestration layer (application) that combines them.

### Key Takeaways

1. **Domain layer is pure** - no I/O, easy to test, portable
2. **Infrastructure layer handles I/O** - storage, networking, RPC
3. **Application layer orchestrates** - combines domain + infrastructure
4. **Foundation layer provides primitives** - types, errors, utilities

### Success Criteria

After migration, we should achieve:

- ✅ 100% test coverage for domain logic (unit tests only, no mocks)
- ✅ Clear module boundaries (no circular dependencies)
- ✅ Faster test suite (domain tests run in <1s)
- ✅ Easier onboarding (architecture is self-documenting)
- ✅ Improved maintainability (changes isolated to single layer)

### Next Steps

1. **Review this document with team**
2. **Get consensus on approach**
3. **Start Phase 1 (foundation layer)**
4. **Create tracking issues for each phase**
5. **Set up CI to enforce layer boundaries** (via `cargo-deny` or custom lints)

---

## Appendix: Enforcement Tools

### Cargo Deny Configuration

```toml
# deny.toml
[bans]
multiple-versions = "deny"

# Enforce layer boundaries
[[bans.deny]]
name = "domain"
deny = ["infrastructure"]  # Domain cannot depend on infrastructure

[[bans.deny]]
name = "domain"
deny = ["application"]  # Domain cannot depend on application
```

### Custom Lint (Future)

```rust
// Build script to enforce architecture
fn check_layer_dependencies() {
    // Parse Cargo.toml
    // Verify domain/ doesn't import infrastructure/
    // Fail build if violation found
}
```

---

**End of Document**
