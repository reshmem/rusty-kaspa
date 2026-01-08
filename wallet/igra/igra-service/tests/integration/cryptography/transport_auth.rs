use bincode::Options;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use igra_core::transport::identity::{Ed25519Signer, StaticEd25519Verifier};
use igra_core::transport::{FinalizeNotice, MessageEnvelope, SignatureSigner, SignatureVerifier, TransportMessage};
use igra_core::types::{PeerId, RequestId, SessionId};
use std::collections::HashMap;

fn payload_hash(payload: &TransportMessage) -> [u8; 32] {
    let bytes = bincode::DefaultOptions::new().with_fixint_encoding().serialize(payload).expect("serialize payload");
    *blake3::hash(&bytes).as_bytes()
}

#[test]
fn test_transport_envelope_authentication() {
    let seed = [7u8; 32];
    let signer = Ed25519Signer::from_seed(PeerId::from("peer-1"), seed);
    let mut keys = HashMap::new();
    keys.insert(PeerId::from("peer-1"), signer.verifying_key());
    let verifier = StaticEd25519Verifier::new(keys);

    let payload = TransportMessage::FinalizeNotice(FinalizeNotice { request_id: RequestId::from("req-1"), final_tx_id: [9u8; 32] });
    let hash = payload_hash(&payload);
    let signature = signer.sign(&hash);

    let envelope = MessageEnvelope {
        sender_peer_id: PeerId::from("peer-1"),
        group_id: [1u8; 32],
        session_id: SessionId::from([2u8; 32]),
        seq_no: 1,
        timestamp_nanos: 0,
        payload,
        payload_hash: hash,
        signature,
    };

    assert!(verifier.verify(&envelope.sender_peer_id, &envelope.payload_hash, &envelope.signature));

    let mut tampered = envelope.clone();
    tampered.payload =
        TransportMessage::FinalizeNotice(FinalizeNotice { request_id: RequestId::from("req-tampered"), final_tx_id: [8u8; 32] });
    let tampered_hash = payload_hash(&tampered.payload);
    assert_ne!(tampered_hash, envelope.payload_hash);
    assert!(!verifier.verify(&tampered.sender_peer_id, &tampered_hash, &tampered.signature));
}

#[test]
fn test_envelope_signature_format() {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let message = b"test message";
    let signature = signing_key.sign(message);

    assert_eq!(signature.to_bytes().len(), 64);
    assert!(verifying_key.verify(message, &signature).is_ok());
}
