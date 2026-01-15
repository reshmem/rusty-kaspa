//! Application layer: orchestration across domain logic and infrastructure I/O.

pub mod crdt_coordinator;
pub mod event_processor;
pub mod lifecycle;
pub mod monitoring;
pub mod two_phase;

pub use crdt_coordinator::{CrdtAction, CrdtCoordinator};
pub use event_processor::{submit_signing_event, EventContext, SigningEventParams, SigningEventResult, SigningEventWire};
pub use lifecycle::{AuditLoggingObserver, CompositeObserver, LifecycleObserver, NoopObserver};
pub use monitoring::TransactionMonitor;
