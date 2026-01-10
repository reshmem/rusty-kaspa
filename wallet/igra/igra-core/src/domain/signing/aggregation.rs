use crate::domain::pskt::multisig;
use crate::foundation::ThresholdError;
use kaspa_wallet_pskt::prelude::{Combiner, Finalizer, Signer, PSKT};

/// Combine a base PSKT with a signer PSKT (pure aggregation, no I/O).
pub fn aggregate_signed_pskt(base: PSKT<Combiner>, signed: PSKT<Signer>) -> Result<PSKT<Combiner>, ThresholdError> {
    multisig::combine_pskts(base, signed)
}

/// Finalize a combined PSKT into a finalized PSKT, given required signatures and ordering.
pub fn finalize_pskt(
    pskt: PSKT<Combiner>,
    required_signatures: usize,
    ordered_pubkeys: &[secp256k1::PublicKey],
) -> Result<PSKT<Finalizer>, ThresholdError> {
    multisig::finalize_multisig(pskt, required_signatures, ordered_pubkeys)
}
