#![allow(dead_code)]

use crate::fixtures::{TEST_DERIVATION_PATH, TEST_DESTINATION_ADDRESS, TEST_EVENT_ID};
use igra_core::domain::{EventSource, SigningEvent};
use std::collections::BTreeMap;

pub struct SigningEventBuilder {
    event_id: String,
    event_source: EventSource,
    derivation_path: String,
    derivation_index: Option<u32>,
    destination_address: String,
    amount_sompi: u64,
    metadata: BTreeMap<String, String>,
    timestamp_nanos: u64,
}

impl Default for SigningEventBuilder {
    fn default() -> Self {
        Self {
            event_id: TEST_EVENT_ID.to_string(),
            event_source: EventSource::Api { issuer: "tests".to_string() },
            derivation_path: TEST_DERIVATION_PATH.to_string(),
            derivation_index: Some(0),
            destination_address: TEST_DESTINATION_ADDRESS.to_string(),
            amount_sompi: 123,
            metadata: BTreeMap::new(),
            timestamp_nanos: 1,
        }
    }
}

impl SigningEventBuilder {
    pub fn amount_sompi(mut self, amount_sompi: u64) -> Self {
        self.amount_sompi = amount_sompi;
        self
    }

    pub fn destination_address(mut self, destination_address: impl Into<String>) -> Self {
        self.destination_address = destination_address.into();
        self
    }

    pub fn event_source(mut self, event_source: EventSource) -> Self {
        self.event_source = event_source;
        self
    }

    pub fn build(self) -> SigningEvent {
        SigningEvent {
            event_id: self.event_id,
            event_source: self.event_source,
            derivation_path: self.derivation_path,
            derivation_index: self.derivation_index,
            destination_address: self.destination_address,
            amount_sompi: self.amount_sompi,
            metadata: self.metadata,
            timestamp_nanos: self.timestamp_nanos,
            signature: None,
        }
    }
}
