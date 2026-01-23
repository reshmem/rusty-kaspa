use hyperlane_core::{HyperlaneMessage, H256};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;

#[derive(Debug, Deserialize)]
pub struct RpcHyperlaneMessage {
    pub version: u8,
    pub nonce: u32,
    pub origin: u32,
    pub sender: H256,
    pub destination: u32,
    pub recipient: H256,
    #[serde(deserialize_with = "deserialize_body_bytes")]
    pub body: Vec<u8>,
}

impl From<RpcHyperlaneMessage> for HyperlaneMessage {
    fn from(value: RpcHyperlaneMessage) -> Self {
        HyperlaneMessage {
            version: value.version,
            nonce: value.nonce,
            origin: value.origin,
            sender: value.sender,
            destination: value.destination,
            recipient: value.recipient,
            body: value.body,
        }
    }
}

fn deserialize_body_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BodyVisitor;

    impl<'de> Visitor<'de> for BodyVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("byte array or hex string")
        }

        fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            Deserialize::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_body_str(v).map_err(E::custom)
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.visit_str(&v)
        }
    }

    deserializer.deserialize_any(BodyVisitor)
}

fn parse_body_str(value: &str) -> Result<Vec<u8>, String> {
    igra_core::foundation::decode_hex_prefixed(value).map_err(|_| "invalid message body hex".to_string())
}
