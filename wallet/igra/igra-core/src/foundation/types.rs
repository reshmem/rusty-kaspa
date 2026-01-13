use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;

pub type Hash32 = [u8; 32];

macro_rules! define_id_type {
    (string $name:ident) => {
        #[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl Deref for $name {
            type Target = str;
            fn deref(&self) -> &Self::Target {
                self.as_str()
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_string())
            }
        }
    };

    (hash $name:ident) => {
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
        #[serde(transparent)]
        pub struct $name(Hash32);

        impl $name {
            pub fn new(value: Hash32) -> Self {
                Self(value)
            }

            pub fn as_hash(&self) -> &Hash32 {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(self.0))
            }
        }

        impl From<Hash32> for $name {
            fn from(value: Hash32) -> Self {
                Self(value)
            }
        }

        impl From<$name> for Hash32 {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

define_id_type!(string PeerId);
define_id_type!(hash SessionId);
define_id_type!(hash TransactionId);

impl From<kaspa_consensus_core::tx::TransactionId> for TransactionId {
    fn from(value: kaspa_consensus_core::tx::TransactionId) -> Self {
        Self(value.as_bytes())
    }
}
