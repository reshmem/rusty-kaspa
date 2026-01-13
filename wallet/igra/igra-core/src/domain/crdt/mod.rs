//! CRDT (Conflict-free Replicated Data Type) implementations for distributed coordination.
//!
//! This module provides pure CRDT data structures with no I/O dependencies.
//! These are used for leaderless signature collection across distributed signers.
//!
//! # Key Types
//! - `GSet<T>`: Grow-only set for signature collection
//! - `LWWRegister<T>`: Last-writer-wins register for completion status
//! - `EventCrdt`: Combined CRDT for a signing event
//!
//! # Key Properties
//! - Commutative: merge(A, B) == merge(B, A)
//! - Associative: merge(merge(A, B), C) == merge(A, merge(B, C))
//! - Idempotent: merge(A, A) == A

mod event_state;
mod gset;
mod lww;
mod types;

pub use event_state::{merge_event_states, EventCrdt};
pub use gset::GSet;
pub use lww::LWWRegister;
pub use types::{CompletionInfo, SignatureKey, SignatureRecord};

