//! Foundation layer: shared primitives grouped for the layered architecture.

pub mod config_helpers;
pub mod constants;
pub mod error;
pub mod hd;
pub mod types;
pub mod util;

pub use config_helpers::*;
pub use constants::*;
pub use error::*;
pub use hd::*;
pub use types::*;
pub use util::encoding::*;
pub use util::hex_fmt::{hx, hx32, Hex32, HexBytes};
pub use util::time::{current_timestamp_nanos_env, day_start_nanos, now_nanos};
