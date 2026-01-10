use crate::foundation::Hash32;

/// Helper to build storage keys consistently.
pub struct KeyBuilder {
    buf: Vec<u8>,
}

impl KeyBuilder {
    pub fn with_capacity(cap: usize) -> Self {
        Self { buf: Vec::with_capacity(cap) }
    }

    pub fn prefix(mut self, prefix: &[u8]) -> Self {
        self.buf.extend_from_slice(prefix);
        self
    }

    pub fn hash32(mut self, hash: &Hash32) -> Self {
        self.buf.extend_from_slice(hash);
        self
    }

    pub fn str(mut self, value: &str) -> Self {
        self.buf.extend_from_slice(value.as_bytes());
        self
    }

    pub fn bytes(mut self, value: &[u8]) -> Self {
        self.buf.extend_from_slice(value);
        self
    }

    pub fn u32_be(mut self, value: u32) -> Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub fn u64_be(mut self, value: u64) -> Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub fn sep(mut self) -> Self {
        self.buf.push(b':');
        self
    }

    pub fn build(self) -> Vec<u8> {
        self.buf
    }
}

pub const CF_METADATA: &str = "metadata";
pub const CF_DEFAULT: &str = "default";
pub const CF_GROUP: &str = "group";
pub const CF_EVENT: &str = "event";
pub const CF_REQUEST: &str = "request";
pub const CF_PROPOSAL: &str = "proposal";
pub const CF_REQUEST_INPUT: &str = "request_input";
pub const CF_SIGNER_ACK: &str = "signer_ack";
pub const CF_PARTIAL_SIG: &str = "partial_sig";
pub const CF_VOLUME: &str = "volume";
pub const CF_SEEN: &str = "seen";
