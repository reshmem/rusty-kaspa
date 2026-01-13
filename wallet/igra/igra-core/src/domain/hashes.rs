use crate::domain::{Event, SourceType};
use crate::foundation::Hash32;
use blake3::Hasher;

const EVENT_ID_DOMAIN_V1: &[u8] = b"igra:event:v1:";

pub fn compute_event_id(event: &Event) -> Hash32 {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(EVENT_ID_DOMAIN_V1);
    encode_event_v1(event, &mut buf);
    *blake3::hash(&buf).as_bytes()
}

fn encode_event_v1(event: &Event, out: &mut Vec<u8>) {
    out.extend_from_slice(&event.external_id);
    encode_source_v1(&event.source, out);

    out.extend_from_slice(&event.destination.version().to_le_bytes());
    let script = event.destination.script();
    out.extend_from_slice(&(script.len() as u32).to_le_bytes());
    out.extend_from_slice(script);

    out.extend_from_slice(&event.amount_sompi.to_le_bytes());
}

fn encode_source_v1(source: &SourceType, out: &mut Vec<u8>) {
    match source {
        SourceType::Hyperlane { origin_domain } => {
            out.push(1);
            out.extend_from_slice(&origin_domain.to_le_bytes());
        }
        SourceType::LayerZero { src_eid } => {
            out.push(2);
            out.extend_from_slice(&src_eid.to_le_bytes());
        }
        SourceType::Api => out.push(3),
        SourceType::Manual => out.push(4),
    }
}

pub fn validation_hash(event_id: &Hash32, tx_template_hash: &Hash32, per_input_hashes: &[Hash32]) -> Hash32 {
    let mut hasher = Hasher::new();
    hasher.update(event_id);
    hasher.update(tx_template_hash);
    for hash in per_input_hashes {
        hasher.update(hash);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_addresses::Address;
    use kaspa_txscript::pay_to_address_script;

    #[test]
    fn event_id_v1_is_stable() {
        let address = Address::try_from("kaspadev:qp5mxzzk5gush9k2zv0pjhj3cmpq9n8nemljasdzxsqjr4x2dc6wc0225vqpw").unwrap();
        let destination = pay_to_address_script(&address);
        let event = Event {
            external_id: [0x42; 32],
            source: SourceType::Hyperlane { origin_domain: 1 },
            destination,
            amount_sompi: 1_000_000,
        };

        let event_id = compute_event_id(&event);
        assert_eq!(hex::encode(event_id), "1b6fa80793c49ade0124b3d9c57d8a969b7603c7b6e4a39f9a5ceacd9e312008");
    }
}
