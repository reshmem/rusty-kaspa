//! Service coordination layer.
//!
//! # Overview
//!
//! Coordinates distributed threshold signing across signers:
//! - CRDT gossip merges partial signatures and completion records.
//! - Two-phase proposal/commit selects a canonical transaction template for signing.
//! - Background loops drive anti-entropy sync, signing, and submission.
//!
//! This module is the glue between transport, storage, and application-level logic.

pub mod crdt;
pub mod helpers;
pub mod r#loop;
pub mod two_phase_handler;
pub mod two_phase_timeout;
mod unfinalized_reporter;

pub use crdt::{handle_crdt_broadcast, run_anti_entropy_loop};
pub use helpers::{derive_ordered_pubkeys, params_for_network_id};
pub use r#loop::run_coordination_loop;
