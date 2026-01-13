use crate::domain::pskt::multisig as pskt_multisig;
use crate::domain::signing::results::{SignatureOutput, SigningResult};
use crate::domain::signing::{SignerBackend, SigningBackendKind};
use crate::foundation::RequestId;
use crate::foundation::SigningKeypair;
use crate::foundation::ThresholdError;

pub struct ThresholdSigner {
    keypair: SigningKeypair,
}

impl ThresholdSigner {
    pub fn new(keypair: SigningKeypair) -> Self {
        Self { keypair }
    }
}

impl SignerBackend for ThresholdSigner {
    fn kind(&self) -> SigningBackendKind {
        SigningBackendKind::Threshold
    }

    fn sign(&self, kpsbt_blob: &[u8], request_id: &RequestId) -> Result<SigningResult, ThresholdError> {
        let keypair = self.keypair.to_secp256k1()?;
        let canonical_pubkey = pskt_multisig::canonical_schnorr_pubkey_for_keypair(&keypair);
        let signer_pskt = pskt_multisig::deserialize_pskt_signer(kpsbt_blob)?;
        let input_count = signer_pskt.inputs.len();
        let signed = pskt_multisig::sign_pskt(signer_pskt, &keypair)?.pskt;
        let partials = pskt_multisig::partial_sigs_for_pubkey(&signed, &canonical_pubkey);
        let signatures_produced: Vec<SignatureOutput> = partials
            .into_iter()
            .map(|(input_index, signature)| SignatureOutput {
                input_index,
                pubkey: canonical_pubkey.serialize().to_vec(),
                signature,
            })
            .collect();

        if signatures_produced.is_empty() {
            return Err(ThresholdError::SigningFailed("no signatures produced".to_string()));
        }

        Ok(SigningResult {
            request_id: request_id.clone(),
            input_count,
            signatures_produced,
            signer_pubkey: canonical_pubkey.serialize().to_vec(),
        })
    }
}
