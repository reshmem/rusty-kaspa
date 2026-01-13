#![allow(dead_code)]

use crate::fixtures::{TEST_DESTINATION_ADDRESS, TEST_EXTERNAL_ID_RAW};
use igra_core::domain::{Event, EventAuditData, SourceType, StoredEvent};
use kaspa_addresses::Address;
use kaspa_txscript::pay_to_address_script;
use std::collections::BTreeMap;

pub struct StoredEventBuilder {
    external_id_raw: String,
    source: SourceType,
    destination_raw: String,
    amount_sompi: u64,
    received_at_nanos: u64,
    source_data: BTreeMap<String, String>,
}

impl Default for StoredEventBuilder {
    fn default() -> Self {
        Self {
            external_id_raw: TEST_EXTERNAL_ID_RAW.to_string(),
            source: SourceType::Api,
            destination_raw: TEST_DESTINATION_ADDRESS.to_string(),
            amount_sompi: 123,
            received_at_nanos: 1,
            source_data: BTreeMap::new(),
        }
    }
}

impl StoredEventBuilder {
    pub fn amount_sompi(mut self, amount_sompi: u64) -> Self {
        self.amount_sompi = amount_sompi;
        self
    }

    pub fn destination_address(mut self, destination_address: impl Into<String>) -> Self {
        self.destination_raw = destination_address.into();
        self
    }

    pub fn source(mut self, source: SourceType) -> Self {
        self.source = source;
        self
    }

    pub fn build(self) -> StoredEvent {
        let raw = self.destination_raw.trim();
        let address = Address::try_from(raw).expect("test destination address");
        let destination = pay_to_address_script(&address);
        let external_id = hex::decode(self.external_id_raw.trim_start_matches("0x"))
            .expect("test external id")
            .as_slice()
            .try_into()
            .expect("external id is 32 bytes");

        let event = Event { external_id, source: self.source, destination, amount_sompi: self.amount_sompi };
        let audit = EventAuditData {
            external_id_raw: self.external_id_raw,
            destination_raw: self.destination_raw,
            source_data: self.source_data,
        };
        StoredEvent { event, received_at_nanos: self.received_at_nanos, audit, proof: None }
    }
}
