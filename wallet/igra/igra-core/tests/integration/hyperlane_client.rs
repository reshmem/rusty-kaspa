#![cfg(feature = "hyperlane")]

use hyperlane_core::accumulator::merkle::{merkle_root_from_branch, Proof};
use hyperlane_core::{Checkpoint, CheckpointWithMessageId, HyperlaneMessage, Signable, Signature, H256, U256};
use igra_core::infrastructure::config::{HyperlaneConfig, HyperlaneDomainConfig, HyperlaneIsmMode};
use igra_core::infrastructure::hyperlane::{ConfiguredIsm, IsmMode, IsmVerifier, ProofMetadata};
use secp256k1::{rand::rngs::OsRng, Message as SecpMessage, PublicKey, Secp256k1, SecretKey};

fn pk_hex(pk: &PublicKey) -> String {
    format!("{}", hex::encode(pk.serialize()))
}

fn make_sig(hash: H256, sk: &SecretKey) -> Signature {
    let secp = Secp256k1::new();
    let msg = SecpMessage::from_digest_slice(hash.as_ref()).expect("msg");
    let rec = secp.sign_ecdsa_recoverable(&msg, sk);
    let (rec_id, bytes) = rec.serialize_compact();
    let mut r = [0u8; 32];
    r.copy_from_slice(&bytes[0..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&bytes[32..64]);
    Signature {
        r: U256::from_big_endian(&r),
        s: U256::from_big_endian(&s),
        v: rec_id.to_i32() as u64, // 0/1 form (mapped to 27/28 in verifier)
    }
}

fn make_message() -> HyperlaneMessage {
    HyperlaneMessage {
        version: 3,
        nonce: 1,
        origin: 5,
        sender: H256::from_low_u64_be(1),
        destination: 7,
        recipient: H256::from_low_u64_be(2),
        body: b"hello".to_vec(),
    }
}

fn domain_cfg(domain: u32, pks: &[PublicKey], threshold: u8, mode: HyperlaneIsmMode) -> HyperlaneDomainConfig {
    HyperlaneDomainConfig { domain, validators: pks.iter().map(pk_hex).collect(), threshold, mode }
}

#[test]
fn message_id_multisig_succeeds() {
    let secp = Secp256k1::new();
    let sk1 = SecretKey::new(&mut OsRng);
    let sk2 = SecretKey::new(&mut OsRng);
    let sk3 = SecretKey::new(&mut OsRng);
    let pks = vec![
        PublicKey::from_secret_key(&secp, &sk1),
        PublicKey::from_secret_key(&secp, &sk2),
        PublicKey::from_secret_key(&secp, &sk3),
    ];

    let cfg = HyperlaneConfig { domains: vec![domain_cfg(5, &pks, 2, HyperlaneIsmMode::MessageIdMultisig)], ..Default::default() };
    let ism = ConfiguredIsm::from_config(&cfg).expect("config ok");

    let message = make_message();
    let checkpoint = Checkpoint {
        merkle_tree_hook_address: H256::zero(),
        mailbox_domain: message.origin,
        root: H256::from_low_u64_be(123),
        index: 0,
    };
    let cp_with_msg = CheckpointWithMessageId { checkpoint, message_id: message.id() };
    let signing_hash = cp_with_msg.signing_hash();

    let sig1 = make_sig(signing_hash, &sk1);
    let sig2 = make_sig(signing_hash, &sk2);

    let meta = ProofMetadata { checkpoint: cp_with_msg, merkle_proof: None, signatures: vec![sig1, sig2] };

    let report = ism.verify_proof(&message, &meta, IsmMode::MessageIdMultisig).expect("verification should pass");

    assert_eq!(report.quorum, 2);
    assert_eq!(report.message_id, message.id());
    assert_eq!(report.root, checkpoint.root);
}

#[test]
fn message_id_multisig_insufficient_quorum() {
    let secp = Secp256k1::new();
    let sk1 = SecretKey::new(&mut OsRng);
    let sk2 = SecretKey::new(&mut OsRng);
    let pks = vec![PublicKey::from_secret_key(&secp, &sk1), PublicKey::from_secret_key(&secp, &sk2)];

    let cfg = HyperlaneConfig { domains: vec![domain_cfg(5, &pks, 2, HyperlaneIsmMode::MessageIdMultisig)], ..Default::default() };
    let ism = ConfiguredIsm::from_config(&cfg).expect("config ok");

    let message = make_message();
    let checkpoint = Checkpoint {
        merkle_tree_hook_address: H256::zero(),
        mailbox_domain: message.origin,
        root: H256::from_low_u64_be(123),
        index: 0,
    };
    let cp_with_msg = CheckpointWithMessageId { checkpoint, message_id: message.id() };
    let signing_hash = cp_with_msg.signing_hash();

    let sig1 = make_sig(signing_hash, &sk1);

    let meta = ProofMetadata { checkpoint: cp_with_msg, merkle_proof: None, signatures: vec![sig1] };

    let err = ism.verify_proof(&message, &meta, IsmMode::MessageIdMultisig).unwrap_err();
    assert!(err.contains("insufficient"));
}

#[test]
fn merkle_root_multisig_succeeds() {
    let secp = Secp256k1::new();
    let sk1 = SecretKey::new(&mut OsRng);
    let sk2 = SecretKey::new(&mut OsRng);
    let pks = vec![PublicKey::from_secret_key(&secp, &sk1), PublicKey::from_secret_key(&secp, &sk2)];

    let cfg = HyperlaneConfig { domains: vec![domain_cfg(5, &pks, 2, HyperlaneIsmMode::MerkleRootMultisig)], ..Default::default() };
    let ism = ConfiguredIsm::from_config(&cfg).expect("config ok");

    let message = make_message();
    let leaf = message.id();
    let path = [H256::zero(); 32];
    // simple path with zeros; compute root accordingly
    let root = merkle_root_from_branch(leaf, &path, path.len(), 0);
    let checkpoint = Checkpoint { merkle_tree_hook_address: H256::zero(), mailbox_domain: message.origin, root, index: 0 };
    let cp_with_msg = CheckpointWithMessageId { checkpoint, message_id: leaf };
    let signing_hash = cp_with_msg.signing_hash();

    let sig1 = make_sig(signing_hash, &sk1);
    let sig2 = make_sig(signing_hash, &sk2);

    let meta = ProofMetadata {
        checkpoint: cp_with_msg,
        merkle_proof: Some(Proof { leaf, index: 0, path }),
        signatures: vec![sig1, sig2],
    };

    let report = ism.verify_proof(&message, &meta, IsmMode::MerkleRootMultisig).expect("verification should pass");

    assert_eq!(report.quorum, 2);
    assert_eq!(report.root, root);
}

#[test]
fn legacy_flat_validators_require_threshold() {
    let secp = Secp256k1::new();
    let sk1 = SecretKey::new(&mut OsRng);
    let sk2 = SecretKey::new(&mut OsRng);
    let pks = vec![PublicKey::from_secret_key(&secp, &sk1), PublicKey::from_secret_key(&secp, &sk2)];

    let cfg = HyperlaneConfig {
        validators: pks.iter().map(pk_hex).collect(),
        threshold: Some(2),
        domains: vec![domain_cfg(0, &pks, 2, HyperlaneIsmMode::MessageIdMultisig)],
        ..Default::default()
    };
    let ism = ConfiguredIsm::from_config(&cfg).expect("config ok");
    let set = ism.validators_and_threshold(0, H256::zero()).expect("set");
    assert_eq!(set.domain, 0);
    assert_eq!(set.validators.len(), 2);
    assert_eq!(set.threshold, 2);
}
