//! Safe conversion helpers to replace unchecked `as` casts.

use crate::error::ThresholdError;
use std::convert::TryFrom;

pub fn u64_to_u32(value: u64) -> Result<u32, ThresholdError> {
    u32::try_from(value).map_err(|_| ThresholdError::Message(format!("{} exceeds u32::MAX", value)))
}

pub fn u64_to_i32(value: u64) -> Result<i32, ThresholdError> {
    i32::try_from(value).map_err(|_| ThresholdError::Message(format!("{} exceeds i32 range", value)))
}

pub fn usize_to_u32(value: usize) -> Result<u32, ThresholdError> {
    u32::try_from(value).map_err(|_| ThresholdError::Message(format!("{} exceeds u32::MAX", value)))
}

pub fn usize_to_u8(value: usize) -> Result<u8, ThresholdError> {
    u8::try_from(value).map_err(|_| ThresholdError::Message(format!("{} exceeds u8::MAX", value)))
}
