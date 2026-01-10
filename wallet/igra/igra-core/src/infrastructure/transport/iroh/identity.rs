use super::traits::{SignatureSigner, SignatureVerifier};
use crate::foundation::Hash32;
use crate::foundation::PeerId;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::HashMap;

#[derive(Clone)]
pub struct Ed25519Signer {
    pub peer_id: PeerId,
    key: SigningKey,
}

impl Ed25519Signer {
    pub fn from_seed(peer_id: PeerId, seed: [u8; 32]) -> Self {
        Self { peer_id, key: SigningKey::from_bytes(&seed) }
    }

    pub fn sign_payload(&self, payload_hash: &Hash32) -> Vec<u8> {
        self.key.sign(payload_hash).to_bytes().to_vec()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

impl SignatureSigner for Ed25519Signer {
    fn sender_peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    fn sign(&self, payload_hash: &Hash32) -> Vec<u8> {
        self.sign_payload(payload_hash)
    }
}

pub struct StaticEd25519Verifier {
    keys: HashMap<PeerId, VerifyingKey>,
}

impl StaticEd25519Verifier {
    pub fn new(keys: HashMap<PeerId, VerifyingKey>) -> Self {
        Self { keys }
    }
}

impl SignatureVerifier for StaticEd25519Verifier {
    fn verify(&self, sender_peer_id: &PeerId, payload_hash: &Hash32, signature: &[u8]) -> bool {
        let key = match self.keys.get(sender_peer_id) {
            Some(key) => key,
            None => return false,
        };
        let signature = match Signature::from_slice(signature) {
            Ok(signature) => signature,
            Err(_) => return false,
        };
        key.verify_strict(payload_hash, &signature).is_ok()
    }
}
