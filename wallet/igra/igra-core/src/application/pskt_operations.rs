//! Application-layer facade for PSKT operations.
//!
//! This module re-exports the PSKT multisig helpers used by `igra-service` so the service code
//! does not need to import from `igra-core::domain::pskt::*` directly.

pub use crate::domain::pskt::multisig as pskt_multisig;
