use crate::foundation::ThresholdError;
use crate::foundation::SigningKeypair;
use crate::domain::pskt::multisig as pskt_multisig;
use crate::domain::signing::{SignerBackend, SigningBackendKind};
use crate::domain::signing::PartialSigSubmit;
use crate::foundation::RequestId;

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

    fn sign(&self, kpsbt_blob: &[u8], request_id: &RequestId) -> Result<Vec<PartialSigSubmit>, ThresholdError> {
        let keypair = self.keypair.to_secp256k1()?;
        let signer_pskt = pskt_multisig::deserialize_pskt_signer(kpsbt_blob)?;
        let signed = pskt_multisig::sign_pskt(signer_pskt, &keypair)?;
        let partials = pskt_multisig::partial_sigs_for_pubkey(&signed, &self.keypair.public_key());
        let signatures = partials
            .into_iter()
            .map(|(input_index, signature)| PartialSigSubmit {
                request_id: request_id.clone(),
                input_index,
                pubkey: self.keypair.public_key().serialize().to_vec(),
                signature,
            })
            .collect();
        Ok(signatures)
    }
}
