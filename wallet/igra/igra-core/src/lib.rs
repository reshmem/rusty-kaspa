// Public crate surface is organized by layer: `domain`, `infrastructure`, `application`, `foundation`.
pub mod application;
pub mod domain;
pub mod foundation;
pub mod infrastructure;
pub use foundation::{Result, ThresholdError};
