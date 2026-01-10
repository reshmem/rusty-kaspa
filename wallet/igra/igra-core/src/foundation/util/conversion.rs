use crate::foundation::ThresholdError;

pub fn u64_to_u32(value: u64) -> Result<u32, ThresholdError> {
    u32::try_from(value).map_err(|_| ThresholdError::Message(format!("u64 {value} does not fit into u32")))
}

pub fn usize_to_u32(value: usize) -> Result<u32, ThresholdError> {
    u32::try_from(value).map_err(|_| ThresholdError::Message(format!("usize {value} does not fit into u32")))
}

pub fn u8_to_usize(value: u8) -> usize {
    usize::from(value)
}
