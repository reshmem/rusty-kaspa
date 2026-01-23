//! Core types for key management.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable identifier for a secret.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct SecretName(String);

impl SecretName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for SecretName {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for SecretName {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Stable identifier for a cryptographic key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyRef {
    pub namespace: &'static str,
    pub key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
}

impl KeyRef {
    pub fn new(namespace: &'static str, key_id: impl Into<String>) -> Self {
        Self { namespace, key_id: key_id.into(), version: None }
    }

    pub fn with_version(mut self, version: u32) -> Self {
        self.version = Some(version);
        self
    }

    pub fn qualified_name(&self) -> String {
        match self.version {
            None => format!("{}.{}", self.namespace, self.key_id),
            Some(v) => format!("{}.{}.v{}", self.namespace, self.key_id, v),
        }
    }
}

impl fmt::Display for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.qualified_name())
    }
}

impl From<&KeyRef> for SecretName {
    fn from(value: &KeyRef) -> Self {
        SecretName::new(value.qualified_name())
    }
}

/// Signature scheme supported by KeyManager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureScheme {
    Secp256k1Schnorr,
    Secp256k1Ecdsa,
    Ed25519,
}

impl fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secp256k1Schnorr => write!(f, "secp256k1-schnorr"),
            Self::Secp256k1Ecdsa => write!(f, "secp256k1-ecdsa"),
            Self::Ed25519 => write!(f, "ed25519"),
        }
    }
}

/// Payload to be signed.
#[derive(Debug, Clone, Copy)]
pub enum SigningPayload<'a> {
    Message(&'a [u8]),
    Digest(&'a [u8]),
}

impl<'a> SigningPayload<'a> {
    pub fn as_bytes(&self) -> &'a [u8] {
        match self {
            Self::Message(bytes) => bytes,
            Self::Digest(bytes) => bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct KeyManagerCapabilities {
    pub supports_secp256k1_schnorr: bool,
    pub supports_secp256k1_ecdsa: bool,
    pub supports_ed25519: bool,
    pub supports_secret_export: bool,
    pub supports_key_rotation: bool,
}

/// Request ID for correlating operations in audit logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(u64);

impl RequestId {
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "req-{:016x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_name() {
        let name = SecretName::new("igra.hd.wallet_secret");
        assert_eq!(name.as_str(), "igra.hd.wallet_secret");
    }

    #[test]
    fn test_key_ref_qualified_name() {
        let key = KeyRef::new("igra.hd", "wallet_secret");
        assert_eq!(key.qualified_name(), "igra.hd.wallet_secret");

        let versioned = key.with_version(2);
        assert_eq!(versioned.qualified_name(), "igra.hd.wallet_secret.v2");
    }

    #[test]
    fn test_request_id_unique() {
        let id1 = RequestId::new();
        let id2 = RequestId::new();
        assert_ne!(id1, id2);
    }
}
