//! Application layer: orchestration across domain logic and infrastructure I/O.

pub mod crdt_coordinator;
pub mod crdt_operations;
pub mod event_processor;
pub mod lifecycle;
pub mod monitoring;
pub mod pskt_operations;
pub mod pskt_signing;
pub mod signing_pipeline;
pub mod two_phase;

pub use crdt_coordinator::{CrdtAction, CrdtCoordinator};
pub use crdt_operations::{CrdtOperations, CrdtSigningMaterial, PartialSigRecord, StoredEvent};
pub use event_processor::{submit_signing_event, EventContext, SigningEventParams, SigningEventResult, SigningEventWire};
pub use lifecycle::{AuditLoggingObserver, CompositeObserver, LifecycleObserver, NoopObserver};
pub use monitoring::TransactionMonitor;
pub use pskt_operations::pskt_multisig;

// Domain exports for service-layer consumers (keeps igra-service domain-free).
pub use crate::domain::coordination::selection;
pub use crate::domain::coordination::{EventPhase, PhaseContext, TwoPhaseConfig};
pub use crate::domain::coordination::{Proposal, ProposalBroadcast};
pub use crate::domain::signing::aggregation;
pub use crate::domain::validation;
pub use crate::domain::{group_id, GroupPolicy, SourceType, StoredEventCrdt};
