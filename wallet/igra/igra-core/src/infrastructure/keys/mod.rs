//! Key management infrastructure (Phase 1: local backends only).

pub mod audit;
pub mod backends;
pub mod context;
pub mod error;
pub mod key_manager;
pub mod panic_guard;
pub mod protected_memory;
pub mod secret_store;
pub mod types;

pub use audit::{FileAuditLogger, KeyAuditLogger, NoopAuditLogger};
pub use backends::{EnvSecretStore, FileSecretStore, LocalKeyManager};
pub use context::KeyManagerContext;
pub use key_manager::KeyManager;
pub use secret_store::{SecretBytes, SecretStore};
pub use types::{KeyManagerCapabilities, KeyRef, RequestId, SecretName, SignatureScheme, SigningPayload};

#[cfg(test)]
mod tests;
