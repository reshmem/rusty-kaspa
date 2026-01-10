//! Iroh-specific transport re-exports (shim).
//!
//! Provides a stable path `infrastructure::transport::iroh::*`.

pub mod identity;
pub mod messages;
pub mod mock;
pub mod traits;
pub mod client;
pub mod encoding;
pub mod filtering;
pub mod subscription;
pub mod config;

pub use traits::*;
pub use client::IrohTransport;
pub use config::IrohConfig;
