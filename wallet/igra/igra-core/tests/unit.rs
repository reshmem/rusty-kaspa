//! Domain-layer unit test entrypoint.
//!
//! Cargo only discovers integration tests that are direct children of `tests/`.
//! We keep the prescriptive `tests/unit/*.rs` structure and wire it up here.

#[path = "fixtures/mod.rs"]
pub mod fixtures;

#[path = "unit/mod.rs"]
mod unit;
