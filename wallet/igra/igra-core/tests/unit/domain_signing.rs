use igra_core::domain::pskt::multisig::{
    build_pskt, combine_pskts, extract_tx, finalize_multisig, sign_pskt, MultisigInput, MultisigOutput,
};
use kaspa_consensus_core::config::params::TESTNET_PARAMS;
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::standard::multisig_redeem_script;
use secp256k1::{Keypair, Secp256k1, SecretKey};

fn test_keypair(seed: u8) -> Keypair {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[seed; 32]).expect("secret key");
    Keypair::from_secret_key(&secp, &secret)
}

fn test_redeem_script(kp1: &Keypair, kp2: &Keypair) -> Vec<u8> {
    let (x1, _) = kp1.public_key().x_only_public_key();
    let (x2, _) = kp2.public_key().x_only_public_key();
    multisig_redeem_script([x1.serialize(), x2.serialize()].iter(), 2).expect("redeem script")
}

fn test_input(amount: u64, redeem_script: &[u8]) -> MultisigInput {
    let spk = kaspa_txscript::standard::pay_to_script_hash_script(redeem_script);
    let entry = UtxoEntry::new(amount, spk, 0, false);
    let tx_id = TransactionId::from_slice(&[3u8; 32]);
    MultisigInput {
        utxo_entry: entry,
        previous_outpoint: TransactionOutpoint::new(tx_id, 0),
        redeem_script: redeem_script.to_vec(),
        sig_op_count: 2,
    }
}

#[test]
fn test_threshold_signing_when_all_sigs_present_then_finalizes_and_extracts_tx() {
    let kp1 = test_keypair(1);
    let kp2 = test_keypair(2);
    let redeem = test_redeem_script(&kp1, &kp2);
    let inputs = vec![test_input(10_000, &redeem)];
    let outputs = vec![MultisigOutput { amount: 9_000, script_public_key: ScriptPublicKey::from_vec(0, vec![1, 2, 3]) }];

    let pskt = build_pskt(&inputs, &outputs).expect("pskt").pskt;
    let signer1 = sign_pskt(pskt.clone().signer(), &kp1).expect("signer1").pskt;
    let signer2 = sign_pskt(pskt.clone().signer(), &kp2).expect("signer2").pskt;

    let combined = combine_pskts(pskt.combiner(), signer1).expect("combine1");
    let combined = combine_pskts(combined, signer2).expect("combine2");

    let finalized = finalize_multisig(combined, 2, &[kp1.public_key(), kp2.public_key()]).expect("finalize").pskt;
    let tx = extract_tx(finalized, &TESTNET_PARAMS).expect("extract tx");
    assert!(!tx.tx.inputs.is_empty());
    assert!(tx.tx.inputs.iter().all(|input| !input.signature_script.is_empty()));
}
