pub fn is_expired(now_nanos: u64, expires_at_nanos: u64) -> bool {
    now_nanos >= expires_at_nanos
}

pub fn seconds_remaining(now_nanos: u64, expires_at_nanos: u64) -> u64 {
    expires_at_nanos.saturating_sub(now_nanos) / 1_000_000_000
}
