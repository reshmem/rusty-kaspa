//! Infrastructure-layer integration tests.
//!
//! Cargo only discovers integration tests that are direct children of `tests/`.
//! We keep the prescriptive `tests/integration/*.rs` structure and wire it up
//! via an explicit `[[test]]` target in `igra-core/Cargo.toml`.

#[path = "../fixtures/mod.rs"]
pub mod fixtures;

mod concurrent_crdt;
mod concurrent_phase;
mod config_loading;
mod crdt_storage;
mod hyperlane_client;
mod iroh_discovery_test;
mod phase_storage;
mod rpc_kaspa;
mod secret_cache_ttl;
mod serialization;
mod signed_hash;
mod storage_stress;
