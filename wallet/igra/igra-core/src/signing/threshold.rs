use crate::error::ThresholdError;
use crate::hd::SigningKeypair;
use crate::pskt::multisig as pskt_multisig;
use crate::signing::{SignerBackend, SigningBackendKind};
use crate::transport::PartialSigSubmit;
use crate::types::RequestId;

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

    fn sign(&self, kpsbt_blob: &[u8]) -> Result<Vec<PartialSigSubmit>, ThresholdError> {
        let keypair = self.keypair.to_secp256k1()?;
        let signer_pskt = pskt_multisig::deserialize_pskt_signer(kpsbt_blob)?;
        let signed = pskt_multisig::sign_pskt(signer_pskt, &keypair)?;
        let partials = pskt_multisig::partial_sigs_for_pubkey(&signed, &self.keypair.public_key());
        let signatures = partials
            .into_iter()
            .map(|(input_index, signature)| PartialSigSubmit {
                request_id: RequestId::from(""),
                input_index,
                pubkey: self.keypair.public_key().serialize().to_vec(),
                signature,
            })
            .collect();
        Ok(signatures)
    }
}
