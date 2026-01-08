use crate::error::ThresholdError;
use crate::model::Hash32;
use crate::model::PartialSigRecord;
use borsh::to_vec as borsh_to_vec;
use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    ScriptPublicKey, SignableTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::{opcodes::codes::OpData65, script_builder::ScriptBuilder};
use kaspa_wallet_pskt::prelude::{
    Combiner, Creator, Finalizer, InputBuilder, OutputBuilder, SignInputOk, Signature, Signer, Updater, PSKT,
};
use kaspa_wallet_pskt::pskt::{Inner, Input, Output, Version};
use secp256k1::{Keypair, Message, PublicKey, Secp256k1};
use std::iter;

#[derive(Clone, Debug)]
pub struct MultisigInput {
    pub utxo_entry: UtxoEntry,
    pub previous_outpoint: TransactionOutpoint,
    pub redeem_script: Vec<u8>,
    pub sig_op_count: u8,
}

#[derive(Clone, Debug)]
pub struct MultisigOutput {
    pub amount: u64,
    pub script_public_key: ScriptPublicKey,
}

pub fn build_pskt(inputs: &[MultisigInput], outputs: &[MultisigOutput]) -> Result<PSKT<Updater>, ThresholdError> {
    let mut pskt = PSKT::<Creator>::default().inputs_modifiable().outputs_modifiable().constructor();

    for input in inputs {
        let input = InputBuilder::default()
            .utxo_entry(input.utxo_entry.clone())
            .previous_outpoint(input.previous_outpoint)
            .sig_op_count(input.sig_op_count)
            .redeem_script(input.redeem_script.clone())
            .build()
            .map_err(|err| ThresholdError::Message(err.to_string()))?;
        pskt = pskt.input(input);
    }

    for output in outputs {
        let output = OutputBuilder::default()
            .amount(output.amount)
            .script_public_key(output.script_public_key.clone())
            .build()
            .map_err(|err| ThresholdError::Message(err.to_string()))?;
        pskt = pskt.output(output);
    }

    Ok(pskt.no_more_inputs().no_more_outputs().updater())
}

pub fn set_sequence_all(pskt: PSKT<Updater>, sequence: u64) -> Result<PSKT<Updater>, ThresholdError> {
    let mut updated = pskt;
    for index in 0..updated.inputs.len() {
        updated = updated.set_sequence(sequence, index).map_err(|err| ThresholdError::Message(err.to_string()))?;
    }
    Ok(updated)
}

pub fn to_signer(pskt: PSKT<Updater>) -> PSKT<Signer> {
    pskt.signer()
}

pub fn serialize_pskt<ROLE>(pskt: &PSKT<ROLE>) -> Result<Vec<u8>, ThresholdError> {
    let inner: &Inner = &*pskt;
    serde_json::to_vec(inner).map_err(|err| ThresholdError::Message(err.to_string()))
}

pub fn deserialize_pskt_signer(bytes: &[u8]) -> Result<PSKT<Signer>, ThresholdError> {
    let inner: Inner = serde_json::from_slice(bytes).map_err(|err| ThresholdError::Message(err.to_string()))?;
    Ok(PSKT::from(inner))
}

pub fn deserialize_pskt_combiner(bytes: &[u8]) -> Result<PSKT<Combiner>, ThresholdError> {
    let inner: Inner = serde_json::from_slice(bytes).map_err(|err| ThresholdError::Message(err.to_string()))?;
    Ok(PSKT::from(inner))
}

pub fn apply_partial_sigs(pskt_blob: &[u8], partials: &[PartialSigRecord]) -> Result<PSKT<Combiner>, ThresholdError> {
    let mut inner: Inner = serde_json::from_slice(pskt_blob).map_err(|err| ThresholdError::Message(err.to_string()))?;
    for sig in partials {
        let input = inner
            .inputs
            .get_mut(sig.input_index as usize)
            .ok_or_else(|| ThresholdError::Message("partial sig input index out of bounds".to_string()))?;
        let pubkey = PublicKey::from_slice(&sig.pubkey).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let signature =
            secp256k1::schnorr::Signature::from_slice(&sig.signature).map_err(|err| ThresholdError::Message(err.to_string()))?;
        input.partial_sigs.insert(pubkey, Signature::Schnorr(signature));
    }
    Ok(PSKT::from(inner))
}

pub fn tx_template_hash(pskt: &PSKT<Signer>) -> Result<Hash32, ThresholdError> {
    let inner: &Inner = &*pskt;
    let tx = signable_tx_from_inner(inner);
    let bytes = borsh_to_vec(&tx.tx).map_err(|err| ThresholdError::Message(err.to_string()))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

pub fn input_hashes(pskt: &PSKT<Signer>) -> Result<Vec<Hash32>, ThresholdError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let inner: &Inner = &*pskt;
    let tx = signable_tx_from_inner(inner);
    let sighashes = pskt.inputs.iter().map(|input| input.sighash_type).collect::<Vec<_>>();
    Ok(tx
        .tx
        .inputs
        .iter()
        .enumerate()
        .map(|(idx, _)| calc_schnorr_signature_hash(&tx.as_verifiable(), idx, sighashes[idx], &reused_values).as_bytes())
        .collect())
}

pub fn partial_sigs_for_pubkey(pskt: &PSKT<Signer>, pubkey: &PublicKey) -> Vec<(u32, Vec<u8>)> {
    pskt.inputs
        .iter()
        .enumerate()
        .filter_map(|(idx, input)| input.partial_sigs.get(pubkey).map(|sig| (idx as u32, sig.into_bytes().to_vec())))
        .collect()
}

fn signable_tx_from_inner(inner: &Inner) -> SignableTransaction {
    let tx = Transaction::new(
        inner.global.tx_version,
        inner
            .inputs
            .iter()
            .map(|Input { previous_outpoint, sequence, sig_op_count, .. }| TransactionInput {
                previous_outpoint: *previous_outpoint,
                signature_script: vec![],
                sequence: sequence.unwrap_or(u64::MAX),
                sig_op_count: sig_op_count.unwrap_or(0),
            })
            .collect(),
        inner
            .outputs
            .iter()
            .map(|Output { amount, script_public_key, .. }| TransactionOutput {
                value: *amount,
                script_public_key: script_public_key.clone(),
            })
            .collect(),
        inner.inputs.iter().map(|input: &Input| input.min_time).max().unwrap_or(inner.global.fallback_lock_time).unwrap_or(0),
        SUBNETWORK_ID_NATIVE,
        0,
        if inner.global.version >= Version::One { inner.global.payload.clone().unwrap_or_default() } else { vec![] },
    );

    let entries = inner.inputs.iter().filter_map(|Input { utxo_entry, .. }| utxo_entry.clone()).collect();
    SignableTransaction::with_entries(tx, entries)
}

pub fn sign_pskt(pskt: PSKT<Signer>, keypair: &Keypair) -> Result<PSKT<Signer>, ThresholdError> {
    let secp = Secp256k1::new();
    let reused_values = SigHashReusedValuesUnsync::new();

    pskt.pass_signature_sync(|tx, sighashes| -> Result<Vec<SignInputOk>, String> {
        tx.tx
            .inputs
            .iter()
            .enumerate()
            .map(|(idx, _)| {
                let hash = calc_schnorr_signature_hash(&tx.as_verifiable(), idx, sighashes[idx], &reused_values);
                let msg = Message::from_digest_slice(hash.as_bytes().as_slice()).map_err(|err| err.to_string())?;
                Ok(SignInputOk {
                    signature: Signature::Schnorr(secp.sign_schnorr(&msg, keypair)),
                    pub_key: keypair.public_key(),
                    key_source: None,
                })
            })
            .collect()
    })
    .map_err(|err| ThresholdError::Message(err.to_string()))
}

pub fn combine_pskts(base: PSKT<Combiner>, signed: PSKT<Signer>) -> Result<PSKT<Combiner>, ThresholdError> {
    (base + signed).map_err(|err| ThresholdError::Message(err.to_string()))
}

pub fn finalize_multisig(
    pskt: PSKT<Combiner>,
    required_signatures: usize,
    ordered_pubkeys: &[PublicKey],
) -> Result<PSKT<Finalizer>, ThresholdError> {
    let finalizer = pskt.finalizer();
    finalizer
        .finalize_sync(|inner| -> Result<Vec<Vec<u8>>, String> {
            Ok(inner
                .inputs
                .iter()
                .map(|input| {
                    let mut sigs_pushed = 0;
                    let mut signatures = Vec::new();

                    for pubkey in ordered_pubkeys {
                        if sigs_pushed >= required_signatures {
                            break;
                        }
                        let sig = match input.partial_sigs.get(pubkey) {
                            Some(sig) => sig.into_bytes(),
                            None => continue,
                        };
                        signatures.extend(iter::once(OpData65).chain(sig).chain([input.sighash_type.to_u8()]));
                        sigs_pushed += 1;
                    }

                    if sigs_pushed < required_signatures {
                        return Err("insufficient signatures".to_string());
                    }

                    let redeem = input.redeem_script.as_ref().ok_or_else(|| "missing redeem script".to_string())?;
                    let redeem_script = ScriptBuilder::new().add_data(redeem).map_err(|err| err.to_string())?.drain();
                    Ok(signatures.into_iter().chain(redeem_script.into_iter()).collect())
                })
                .collect::<Result<Vec<Vec<u8>>, String>>()?)
        })
        .map_err(|err| ThresholdError::Message(err.to_string()))
}

pub fn extract_tx(
    pskt: PSKT<Finalizer>,
    params: &kaspa_consensus_core::config::params::Params,
) -> Result<kaspa_consensus_core::tx::Transaction, ThresholdError> {
    let extractor = pskt.extractor().map_err(|err| ThresholdError::Message(err.to_string()))?;
    let tx = extractor.extract_tx(params).map_err(|err| ThresholdError::Message(err.to_string()))?;
    Ok(tx.tx)
}
