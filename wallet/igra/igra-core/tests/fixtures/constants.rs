#![allow(dead_code)]

use kaspa_addresses::Prefix;

pub const TEST_NETWORK_PREFIX: Prefix = Prefix::Testnet;
pub const TEST_DERIVATION_PATH: &str = "m/45'/111111'/0'/0/0";
pub const TEST_DESTINATION_ADDRESS: &str =
    "kaspatest:qz0hz8jkn6ptfhq3v9fg3jhqw5jtsfgy62wan8dhe8fqkhdqsahswcpe2ch3m";
pub const TEST_EVENT_ID: &str = "event-1";
pub const TEST_COORDINATOR_PEER_ID: &str = "peer-1";
