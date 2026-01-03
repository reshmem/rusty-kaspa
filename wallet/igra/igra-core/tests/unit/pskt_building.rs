use igra_core::pskt::multisig::{build_pskt, deserialize_pskt_signer, serialize_pskt, MultisigInput, MultisigOutput};
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::standard::multisig_redeem_script;
use secp256k1::{Keypair, Secp256k1, SecretKey};

fn test_keypair(seed: u8) -> Keypair {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[seed; 32]).expect("secret key");
    Keypair::from_secret_key(&secp, &secret)
}

fn test_redeem_script() -> Vec<u8> {
    let kp1 = test_keypair(1);
    let kp2 = test_keypair(2);
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

fn test_output(amount: u64) -> MultisigOutput {
    MultisigOutput {
        amount,
        script_public_key: ScriptPublicKey::from_vec(0, vec![1, 2, 3]),
    }
}

#[test]
fn pskt_serialization_is_deterministic() {
    let redeem = test_redeem_script();
    let inputs = vec![test_input(10_000, &redeem)];
    let outputs = vec![test_output(9_000)];

    let pskt_a = build_pskt(&inputs, &outputs).expect("pskt a");
    let pskt_b = build_pskt(&inputs, &outputs).expect("pskt b");
    let bytes_a = serialize_pskt(&pskt_a).expect("serialize a");
    let bytes_b = serialize_pskt(&pskt_b).expect("serialize b");
    assert_eq!(bytes_a, bytes_b);

    let signer = deserialize_pskt_signer(&bytes_a).expect("deserialize");
    assert_eq!(signer.inputs.len(), 1);
    assert_eq!(signer.outputs.len(), 1);
}
