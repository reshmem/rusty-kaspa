use crate::foundation::util::encoding::parse_hex_32bytes;
use crate::foundation::ThresholdError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

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
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
        pub struct $name(Hash32);

        impl $name {
            pub const fn new(value: Hash32) -> Self {
                Self(value)
            }

            pub fn as_hash(&self) -> &Hash32 {
                &self.0
            }

            pub fn ct_eq(&self, other: &Self) -> bool {
                use subtle::ConstantTimeEq;
                bool::from(self.0.as_ref().ct_eq(other.0.as_ref()))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(f, "{:02x}", byte)?;
                }
                Ok(())
            }
        }

        impl fmt::LowerHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                if f.alternate() {
                    f.write_str("0x")?;
                }
                for byte in self.0 {
                    write!(f, "{:02x}", byte)?;
                }
                Ok(())
            }
        }

        impl fmt::UpperHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                if f.alternate() {
                    f.write_str("0x")?;
                }
                for byte in self.0 {
                    write!(f, "{:02X}", byte)?;
                }
                Ok(())
            }
        }

        impl FromStr for $name {
            type Err = ThresholdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self::from(parse_hex_32bytes(s)?))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&self.to_string())
                } else {
                    self.0.serialize(serializer)
                }
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
                    let s = String::deserialize(deserializer)?;
                    s.parse().map_err(serde::de::Error::custom)
                } else {
                    let bytes = Hash32::deserialize(deserializer)?;
                    Ok(Self(bytes))
                }
            }
        }

        impl AsRef<Hash32> for $name {
            fn as_ref(&self) -> &Hash32 {
                &self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Deref for $name {
            type Target = Hash32;
            fn deref(&self) -> &Self::Target {
                &self.0
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
define_id_type!(hash ExternalId);
define_id_type!(hash EventId);
define_id_type!(hash GroupId);
define_id_type!(hash PayloadHash);
define_id_type!(hash SessionId);
define_id_type!(hash TransactionId);
define_id_type!(hash TxTemplateHash);

impl From<kaspa_consensus_core::tx::TransactionId> for TransactionId {
    fn from(value: kaspa_consensus_core::tx::TransactionId) -> Self {
        Self(value.as_bytes())
    }
}

/// Typed keys for event `source_data` metadata maps.
///
/// This is primarily used by integration edges (e.g. Hyperlane) to avoid stringly-typed keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MetadataKey {
    HyperlaneMode,
    HyperlaneMailboxDomain,
    HyperlaneMerkleTreeHookAddress,
    HyperlaneRoot,
    HyperlaneIndex,
    HyperlaneMessageId,
    HyperlaneQuorum,
    HyperlaneMsgVersion,
    HyperlaneMsgNonce,
    HyperlaneMsgOrigin,
    HyperlaneMsgSender,
    HyperlaneMsgDestination,
    HyperlaneMsgRecipient,
    HyperlaneMsgBodyHex,
}

impl MetadataKey {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::HyperlaneMode => "hyperlane.mode",
            Self::HyperlaneMailboxDomain => "hyperlane.mailbox_domain",
            Self::HyperlaneMerkleTreeHookAddress => "hyperlane.merkle_tree_hook_address",
            Self::HyperlaneRoot => "hyperlane.root",
            Self::HyperlaneIndex => "hyperlane.index",
            Self::HyperlaneMessageId => "hyperlane.message_id",
            Self::HyperlaneQuorum => "hyperlane.quorum",
            Self::HyperlaneMsgVersion => "hyperlane.msg.version",
            Self::HyperlaneMsgNonce => "hyperlane.msg.nonce",
            Self::HyperlaneMsgOrigin => "hyperlane.msg.origin",
            Self::HyperlaneMsgSender => "hyperlane.msg.sender",
            Self::HyperlaneMsgDestination => "hyperlane.msg.destination",
            Self::HyperlaneMsgRecipient => "hyperlane.msg.recipient",
            Self::HyperlaneMsgBodyHex => "hyperlane.msg.body_hex",
        }
    }
}

impl fmt::Display for MetadataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_id_from_str_accepts_prefixed_and_unprefixed() {
        let hex_prefixed = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let id1: EventId = hex_prefixed.parse().expect("event id parse");
        assert_eq!(id1.to_string(), "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        let hex_unprefixed = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let id2: EventId = hex_unprefixed.parse().expect("event id parse");
        assert_eq!(id1, id2);

        assert!("not-hex".parse::<EventId>().is_err());
        assert!("0xabcd".parse::<EventId>().is_err());
    }

    #[test]
    fn event_id_serde_json_is_hex_string() {
        let id = EventId::new([0xAB; 32]);
        let json = serde_json::to_string(&id).expect("serialize json");
        assert_eq!(json, format!("\"{}\"", id));
        let decoded: EventId = serde_json::from_str(&json).expect("deserialize json");
        assert_eq!(decoded, id);
    }

    #[test]
    fn event_id_bincode_is_stable_fixed_width() {
        let id = EventId::new([0xCD; 32]);
        let bytes = bincode::serialize(&id).expect("serialize bincode");
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn metadata_key_is_stable() {
        assert_eq!(MetadataKey::HyperlaneMsgOrigin.as_str(), "hyperlane.msg.origin");
        assert_eq!(MetadataKey::HyperlaneMsgOrigin.to_string(), "hyperlane.msg.origin");
    }
}
