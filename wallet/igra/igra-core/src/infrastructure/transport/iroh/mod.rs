//! Iroh-specific transport re-exports (shim).
//!
//! Provides a stable path `infrastructure::transport::iroh::*`.

pub mod client;
pub mod config;
pub mod encoding;
pub mod filtering;
pub mod identity;
pub mod messages;
pub mod mock;
pub mod subscription;
pub mod traits;

pub use client::IrohTransport;
pub use config::IrohConfig;
pub use traits::*;
