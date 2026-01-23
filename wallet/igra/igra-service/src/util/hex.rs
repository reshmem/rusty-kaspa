use hyperlane_core::H256;
use kaspa_consensus_core::tx::TransactionId as KaspaTransactionId;

pub fn parse_h256_hex(hex_str: &str) -> Result<H256, String> {
    let bytes = igra_core::foundation::parse_hex_32bytes(hex_str).map_err(|err| err.to_string())?;
    Ok(H256::from(bytes))
}

pub fn parse_kaspa_tx_id_hex(hex_str: &str) -> Result<KaspaTransactionId, String> {
    let bytes = igra_core::foundation::parse_hex_32bytes_allow_64bytes(hex_str).map_err(|err| err.to_string())?;
    Ok(KaspaTransactionId::from_bytes(bytes))
}
