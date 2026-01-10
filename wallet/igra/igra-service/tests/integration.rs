//! End-to-end test entrypoint.
//!
//! Cargo only discovers integration tests that are direct children of `tests/`.
//! We keep the prescriptive `tests/integration/*.rs` module tree and wire it up here.

#[path = "harness/mod.rs"]
mod harness;

#[path = "integration/mod.rs"]
mod integration;
