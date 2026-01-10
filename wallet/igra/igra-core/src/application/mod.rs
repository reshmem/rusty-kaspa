//! Application layer: orchestration across domain logic and infrastructure I/O.

pub mod coordinator;
pub mod signer;
pub mod event_processor;
pub mod lifecycle;
pub mod monitoring;

pub use coordinator::Coordinator;
pub use signer::Signer;
pub use event_processor::{submit_signing_event, EventContext, EventProcessor, SigningEventParams, SigningEventResult, SigningEventWire};
pub use lifecycle::{AuditLoggingObserver, CompositeObserver, LifecycleObserver, NoopObserver};
pub use monitoring::TransactionMonitor;
