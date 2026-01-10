//! Infrastructure-layer integration test entrypoint.
//!
//! Cargo only discovers integration tests that are direct children of `tests/`.
//! We keep the prescriptive `tests/integration/*.rs` structure and wire it up here.

#[path = "fixtures/mod.rs"]
pub mod fixtures;

#[path = "integration/mod.rs"]
mod integration;
