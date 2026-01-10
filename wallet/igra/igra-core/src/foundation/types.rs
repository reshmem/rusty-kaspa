use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;

pub type Hash32 = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(String);

impl RequestId {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Deref for RequestId {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl From<String> for RequestId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for RequestId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerId(String);

impl PeerId {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Deref for PeerId {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl From<String> for PeerId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for PeerId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(Hash32);

impl SessionId {
    pub fn new(value: Hash32) -> Self {
        Self(value)
    }

    pub fn as_hash(&self) -> &Hash32 {
        &self.0
    }
}

impl From<Hash32> for SessionId {
    fn from(value: Hash32) -> Self {
        Self(value)
    }
}

impl From<SessionId> for Hash32 {
    fn from(value: SessionId) -> Self {
        value.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransactionId(Hash32);

impl TransactionId {
    pub fn new(value: Hash32) -> Self {
        Self(value)
    }

    pub fn as_hash(&self) -> &Hash32 {
        &self.0
    }
}

impl From<Hash32> for TransactionId {
    fn from(value: Hash32) -> Self {
        Self(value)
    }
}

impl From<TransactionId> for Hash32 {
    fn from(value: TransactionId) -> Self {
        value.0
    }
}

impl From<kaspa_consensus_core::tx::TransactionId> for TransactionId {
    fn from(value: kaspa_consensus_core::tx::TransactionId) -> Self {
        Self(value.as_bytes())
    }
}
