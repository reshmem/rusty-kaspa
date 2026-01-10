// Public crate surface is organized by layer: `domain`, `infrastructure`, `application`, `foundation`.
pub mod application;
pub mod foundation;
pub mod domain;
pub mod infrastructure;
pub use foundation::{Result, ThresholdError};
