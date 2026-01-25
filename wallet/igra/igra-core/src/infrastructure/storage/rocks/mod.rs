//! RocksDB-backed storage implementation.
//!
//! `RocksStorage` is the primary persistent implementation of:
//! - `Storage` (CRDT state, event index, Hyperlane indexing, etc.)
//! - `PhaseStorage` (two-phase lifecycle and proposal storage)
//!
//! See `engine.rs` for lock semantics and the main implementation.

pub mod engine;
pub mod migration;
pub mod schema;
pub mod util;

pub use engine::RocksStorage;
