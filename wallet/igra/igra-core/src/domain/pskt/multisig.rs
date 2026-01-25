use crate::domain::pskt::results::{PsktBuildResult, PsktFinalizeResult, PsktSignResult, TransactionExtractionResult};
use crate::domain::PartialSigRecord;
use crate::foundation::{Hash32, ThresholdError, TxTemplateHash};
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
use secp256k1::{Keypair, Message, Parity, PublicKey, Secp256k1, XOnlyPublicKey};
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

fn build_pskt_inner(
    inputs: impl IntoIterator<Item = MultisigInput>,
    outputs: impl IntoIterator<Item = MultisigOutput>,
) -> Result<PsktBuildResult, ThresholdError> {
    let mut total_input_amount = 0u64;
    let mut total_output_amount = 0u64;
    let mut pskt = PSKT::<Creator>::default().inputs_modifiable().outputs_modifiable().constructor();

    for input in inputs {
        total_input_amount = total_input_amount.saturating_add(input.utxo_entry.amount);
        let input = InputBuilder::default()
            .utxo_entry(input.utxo_entry)
            .previous_outpoint(input.previous_outpoint)
            .sig_op_count(input.sig_op_count)
            .redeem_script(input.redeem_script)
            .build()
            .map_err(|err| ThresholdError::PsktError { operation: "build_input".into(), details: err.to_string() })?;
        pskt = pskt.input(input);
    }

    for output in outputs {
        total_output_amount = total_output_amount.saturating_add(output.amount);
        let output = OutputBuilder::default()
            .amount(output.amount)
            .script_public_key(output.script_public_key)
            .build()
            .map_err(|err| ThresholdError::PsktError { operation: "build_output".into(), details: err.to_string() })?;
        pskt = pskt.output(output);
    }

    let pskt = pskt.no_more_inputs().no_more_outputs().updater();
    Ok(PsktBuildResult {
        input_count: pskt.inputs.len(),
        output_count: pskt.outputs.len(),
        total_input_amount,
        total_output_amount,
        pskt,
    })
}

pub fn build_pskt(inputs: &[MultisigInput], outputs: &[MultisigOutput]) -> Result<PsktBuildResult, ThresholdError> {
    build_pskt_inner(inputs.iter().cloned(), outputs.iter().cloned())
}

pub fn build_pskt_owned(inputs: Vec<MultisigInput>, outputs: Vec<MultisigOutput>) -> Result<PsktBuildResult, ThresholdError> {
    build_pskt_inner(inputs, outputs)
}

pub fn set_sequence_all(pskt: PSKT<Updater>, sequence: u64) -> Result<PSKT<Updater>, ThresholdError> {
    let mut updated = pskt;
    for index in 0..updated.inputs.len() {
        updated = updated
            .set_sequence(sequence, index)
            .map_err(|err| ThresholdError::PsktError { operation: "set_sequence".into(), details: err.to_string() })?;
    }
    Ok(updated)
}

pub fn to_signer(pskt: PSKT<Updater>) -> PSKT<Signer> {
    pskt.signer()
}

pub fn serialize_pskt<ROLE>(pskt: &PSKT<ROLE>) -> Result<Vec<u8>, ThresholdError> {
    let inner: &Inner = pskt;
    let bytes = serde_json::to_vec(inner)
        .map_err(|err| ThresholdError::SerializationError { format: "json".into(), details: err.to_string() })?;
    Ok(bytes)
}

pub fn deserialize_pskt_signer(bytes: &[u8]) -> Result<PSKT<Signer>, ThresholdError> {
    let inner: Inner = serde_json::from_slice(bytes)
        .map_err(|err| ThresholdError::SerializationError { format: "json".into(), details: err.to_string() })?;
    Ok(PSKT::from(inner))
}

pub fn deserialize_pskt_combiner(bytes: &[u8]) -> Result<PSKT<Combiner>, ThresholdError> {
    let inner: Inner = serde_json::from_slice(bytes)
        .map_err(|err| ThresholdError::SerializationError { format: "json".into(), details: err.to_string() })?;
    Ok(PSKT::from(inner))
}

pub fn apply_partial_sigs(pskt_blob: &[u8], partials: &[PartialSigRecord]) -> Result<PSKT<Combiner>, ThresholdError> {
    let mut inner: Inner = serde_json::from_slice(pskt_blob)
        .map_err(|err| ThresholdError::SerializationError { format: "json".into(), details: err.to_string() })?;
    for sig in partials.iter() {
        let max = inner.inputs.len().saturating_sub(1) as u32;
        let input =
            inner.inputs.get_mut(sig.input_index as usize).ok_or(ThresholdError::InvalidInputIndex { index: sig.input_index, max })?;
        // Canonicalize Schnorr pubkey identity to x-only even parity.
        // This makes partial sigs compatible across historical versions that used different pubkey parities.
        let pubkey = PublicKey::from_slice(&sig.pubkey)
            .map_err(|err| ThresholdError::CryptoError { operation: "parse_pubkey".into(), details: err.to_string() })?;
        let (xonly, _) = pubkey.x_only_public_key();
        let pubkey = PublicKey::from_x_only_public_key(xonly, Parity::Even);
        let signature = secp256k1::schnorr::Signature::from_slice(&sig.signature)
            .map_err(|err| ThresholdError::CryptoError { operation: "parse_signature".into(), details: err.to_string() })?;
        input.partial_sigs.insert(pubkey, Signature::Schnorr(signature));
    }
    Ok(PSKT::from(inner))
}

pub fn tx_template_hash(pskt: &PSKT<Signer>) -> Result<TxTemplateHash, ThresholdError> {
    let inner: &Inner = pskt;
    let tx = signable_tx_from_inner(inner);
    let bytes =
        borsh_to_vec(&tx.tx).map_err(|err| ThresholdError::SerializationError { format: "borsh".into(), details: err.to_string() })?;
    let hash = *blake3::hash(&bytes).as_bytes();
    Ok(TxTemplateHash::from(hash))
}

pub fn validate_kpsbt_blob_matches_tx_template_hash(kpsbt_blob: &[u8], expected: &TxTemplateHash) -> Result<(), ThresholdError> {
    let pskt = deserialize_pskt_signer(kpsbt_blob)?;
    let computed = tx_template_hash(&pskt)?;
    if computed != *expected {
        return Err(ThresholdError::PsktMismatch { expected: expected.to_string(), actual: computed.to_string() });
    }
    Ok(())
}

pub fn input_hashes(pskt: &PSKT<Signer>) -> Result<Vec<Hash32>, ThresholdError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let inner: &Inner = pskt;
    let tx = signable_tx_from_inner(inner);
    let sighashes = pskt.inputs.iter().map(|input| input.sighash_type).collect::<Vec<_>>();
    let mut out = Vec::with_capacity(tx.tx.inputs.len());
    for (idx, _) in tx.tx.inputs.iter().enumerate() {
        let hash = calc_schnorr_signature_hash(&tx.as_verifiable(), idx, sighashes[idx], &reused_values).as_bytes();
        out.push(hash);
    }
    Ok(out)
}

pub fn partial_sigs_for_pubkey(pskt: &PSKT<Signer>, pubkey: &PublicKey) -> Vec<(u32, Vec<u8>)> {
    pskt.inputs
        .iter()
        .enumerate()
        .filter_map(|(idx, input)| input.partial_sigs.get(pubkey).map(|sig| (idx as u32, sig.into_bytes().to_vec())))
        .collect()
}

pub fn canonical_schnorr_pubkey_for_keypair(keypair: &Keypair) -> PublicKey {
    let (xonly, _) = keypair.x_only_public_key();
    PublicKey::from_x_only_public_key(xonly, Parity::Even)
}

pub fn ordered_pubkeys_from_redeem_script(redeem_script: &[u8]) -> Result<Vec<PublicKey>, ThresholdError> {
    fn decode_small_int(op: u8) -> Option<usize> {
        match op {
            0x00 => Some(0),
            0x51..=0x60 => Some((op - 0x50) as usize),
            _ => None,
        }
    }

    if redeem_script.len() < 3 {
        return Err(ThresholdError::PsktValidationFailed("redeem script too short".to_string()));
    }

    let mut p = 0usize;
    let m = decode_small_int(redeem_script[p])
        .ok_or_else(|| ThresholdError::PsktValidationFailed("invalid multisig redeem script: bad M opcode".to_string()))?;
    p += 1;

    let mut xonly_keys = Vec::new();
    while p < redeem_script.len() {
        if redeem_script[p] != 0x20 {
            break;
        }
        p += 1;
        if p + 32 > redeem_script.len() {
            return Err(ThresholdError::PsktValidationFailed("invalid multisig redeem script: truncated pubkey push".to_string()));
        }
        xonly_keys.push(redeem_script[p..p + 32].to_vec());
        p += 32;
    }

    if p >= redeem_script.len() {
        return Err(ThresholdError::PsktValidationFailed("invalid multisig redeem script: missing N opcode".to_string()));
    }
    let n = decode_small_int(redeem_script[p])
        .ok_or_else(|| ThresholdError::PsktValidationFailed("invalid multisig redeem script: bad N opcode".to_string()))?;
    p += 1;

    if p >= redeem_script.len() || redeem_script[p] != 0xae {
        return Err(ThresholdError::PsktValidationFailed("invalid multisig redeem script: missing OP_CHECKMULTISIG".to_string()));
    }

    if n == 0 || m == 0 || m > n {
        return Err(ThresholdError::PsktValidationFailed(format!("invalid multisig redeem script: invalid threshold m={m} n={n}")));
    }
    if xonly_keys.len() != n {
        return Err(ThresholdError::PsktValidationFailed(format!(
            "invalid multisig redeem script: pubkey count {} does not match N {n}",
            xonly_keys.len()
        )));
    }

    let mut pubkeys = Vec::with_capacity(xonly_keys.len());
    for key_bytes in xonly_keys {
        let xonly = XOnlyPublicKey::from_slice(&key_bytes)
            .map_err(|err| ThresholdError::CryptoError { operation: "parse_pubkey".into(), details: err.to_string() })?;
        pubkeys.push(PublicKey::from_x_only_public_key(xonly, Parity::Even));
    }

    Ok(pubkeys)
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
        if inner.global.version >= Version::One { inner.global.payload.as_deref().unwrap_or_default().to_vec() } else { Vec::new() },
    );

    let entries = inner.inputs.iter().filter_map(|Input { utxo_entry, .. }| utxo_entry.clone()).collect();
    SignableTransaction::with_entries(tx, entries)
}

pub fn sign_pskt(pskt: PSKT<Signer>, keypair: &Keypair) -> Result<PsktSignResult, ThresholdError> {
    let secp = Secp256k1::new();
    let reused_values = SigHashReusedValuesUnsync::new();
    let input_count = pskt.inputs.len();
    let canonical_pubkey = canonical_schnorr_pubkey_for_keypair(keypair);

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
                    pub_key: canonical_pubkey,
                    key_source: None,
                })
            })
            .collect()
    })
    .map_err(|err| ThresholdError::PsktError { operation: "sign_pskt".into(), details: err.to_string() })
    .map(|signed| PsktSignResult { input_count, signatures_added: input_count, pskt: signed })
}

pub fn combine_pskts(base: PSKT<Combiner>, signed: PSKT<Signer>) -> Result<PSKT<Combiner>, ThresholdError> {
    (base + signed).map_err(|err| ThresholdError::PsktError { operation: "combine_pskts".into(), details: err.to_string() })
}

pub fn finalize_multisig(
    pskt: PSKT<Combiner>,
    required_signatures: usize,
    ordered_pubkeys: &[PublicKey],
) -> Result<PsktFinalizeResult, ThresholdError> {
    let input_count = pskt.inputs.len();
    let finalizer = pskt.finalizer();
    let signature_counts = std::cell::RefCell::new(Vec::<usize>::new());
    finalizer
        .finalize_sync(|inner| -> Result<Vec<Vec<u8>>, String> {
            *signature_counts.borrow_mut() = Vec::with_capacity(inner.inputs.len());
            inner
                .inputs
                .iter()
                .map(|input| {
                    let mut sigs_pushed = 0;
                    // Each signature is 1 (OP_DATA_65) + 64 (sig) + 1 (sighash) = 66 bytes.
                    let mut signatures = Vec::with_capacity(required_signatures.saturating_mul(66));

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

                    signature_counts.borrow_mut().push(sigs_pushed);
                    if sigs_pushed < required_signatures {
                        return Err(format!("insufficient signatures: have {} of {} required", sigs_pushed, required_signatures));
                    }

                    let redeem = input.redeem_script.as_ref().ok_or_else(|| "missing redeem script".to_string())?;
                    let redeem_script = ScriptBuilder::new().add_data(redeem).map_err(|err| err.to_string())?.drain();
                    Ok(signatures.into_iter().chain(redeem_script).collect())
                })
                .collect::<Result<Vec<Vec<u8>>, String>>()
        })
        .map_err(|err| ThresholdError::PsktError { operation: "finalize_pskt".into(), details: err.to_string() })
        .map(|finalizer| PsktFinalizeResult {
            input_count,
            signatures_per_input: signature_counts.into_inner(),
            required_signatures,
            pskt: finalizer,
        })
}

pub fn extract_tx(
    pskt: PSKT<Finalizer>,
    params: &kaspa_consensus_core::config::params::Params,
) -> Result<TransactionExtractionResult, ThresholdError> {
    let extractor =
        pskt.extractor().map_err(|err| ThresholdError::PsktError { operation: "extractor".into(), details: err.to_string() })?;
    let tx = extractor
        .extract_tx(params)
        .map_err(|err| ThresholdError::PsktError { operation: "extract_tx".into(), details: err.to_string() })?;
    let tx_id = tx.tx.id().as_bytes();
    Ok(TransactionExtractionResult {
        tx_id,
        input_count: tx.tx.inputs.len(),
        output_count: tx.tx.outputs.len(),
        mass: tx.tx.mass(),
        tx: tx.tx,
    })
}
