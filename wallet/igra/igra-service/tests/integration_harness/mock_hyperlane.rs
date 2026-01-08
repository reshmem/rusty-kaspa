use igra_core::coordination::hashes::event_hash_without_signature;
use igra_core::error::ThresholdError;
use igra_core::model::SigningEvent;
use secp256k1::{ecdsa::Signature as SecpSignature, Message, PublicKey, Secp256k1, SecretKey};

#[derive(Clone)]
pub struct HyperlaneValidator {
    #[allow(dead_code)]
    pub address: String,
    pub private_key: SecretKey,
}

#[allow(dead_code)]
pub struct MockHyperlaneValidator {
    validators: Vec<HyperlaneValidator>,
    threshold: usize,
}

#[allow(dead_code)]
impl MockHyperlaneValidator {
    pub fn new(num_validators: usize, threshold: usize) -> Self {
        let mut validators = Vec::new();
        for idx in 0..num_validators {
            let key = SecretKey::from_slice(&[idx as u8 + 1; 32]).expect("validator key");
            validators.push(HyperlaneValidator { address: format!("validator-{}", idx + 1), private_key: key });
        }
        Self { validators, threshold }
    }

    pub fn get_validator_pubkeys(&self) -> Vec<PublicKey> {
        let secp = Secp256k1::new();
        self.validators.iter().map(|validator| PublicKey::from_secret_key(&secp, &validator.private_key)).collect()
    }

    pub fn sign_event_bytes(&self, event: &SigningEvent, signers: &[usize]) -> Result<Vec<u8>, ThresholdError> {
        let hash = event_hash_without_signature(event)?;
        let message = Message::from_digest_slice(&hash).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let secp = Secp256k1::new();
        let mut out = Vec::new();
        for index in signers {
            let validator =
                self.validators.get(*index).ok_or_else(|| ThresholdError::Message("validator index out of range".to_string()))?;
            let sig: SecpSignature = secp.sign_ecdsa(&message, &validator.private_key);
            out.extend_from_slice(&sig.serialize_compact());
        }
        Ok(out)
    }

    pub fn sign_event_hexes(&self, event: &SigningEvent, signers: &[usize]) -> Result<Vec<String>, ThresholdError> {
        let hash = event_hash_without_signature(event)?;
        let message = Message::from_digest_slice(&hash).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let secp = Secp256k1::new();
        let mut out = Vec::new();
        for index in signers {
            let validator =
                self.validators.get(*index).ok_or_else(|| ThresholdError::Message("validator index out of range".to_string()))?;
            let sig: SecpSignature = secp.sign_ecdsa(&message, &validator.private_key);
            out.push(hex::encode(sig.serialize_compact()));
        }
        Ok(out)
    }

    pub fn sign_with_quorum(&self, event: &SigningEvent) -> Result<Vec<u8>, ThresholdError> {
        let signers = (0..self.threshold).collect::<Vec<_>>();
        self.sign_event_bytes(event, &signers)
    }

    pub fn sign_with_insufficient(&self, event: &SigningEvent) -> Result<Vec<u8>, ThresholdError> {
        let signers = (0..self.threshold.saturating_sub(1)).collect::<Vec<_>>();
        self.sign_event_bytes(event, &signers)
    }

    pub fn verify_event_signature(
        &self,
        event: &SigningEvent,
        signature: &[u8],
        validator_index: usize,
    ) -> Result<bool, ThresholdError> {
        let hash = event_hash_without_signature(event)?;
        let message = Message::from_digest_slice(&hash).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let validator =
            self.validators.get(validator_index).ok_or_else(|| ThresholdError::Message("validator index out of range".to_string()))?;
        let secp = Secp256k1::verification_only();
        let sig = SecpSignature::from_compact(signature).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &validator.private_key);
        Ok(secp.verify_ecdsa(&message, &sig, &pubkey).is_ok())
    }
}
