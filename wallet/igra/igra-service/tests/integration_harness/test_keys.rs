use iroh::{PublicKey as IrohPublicKey, SecretKey as IrohSecretKey};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_txscript::standard::multisig_redeem_script;
use secp256k1::{Keypair, Secp256k1};
use sha3::{Digest, Keccak256};

pub const SIGNER_MNEMONICS: [&str; 3] = [
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
];

pub const IROH_PEERS: [&str; 3] = ["signer-1", "signer-2", "signer-3"];

pub const IROH_SEED_HEX: [&str; 3] = [
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
];

pub const SIGNER_MNEMONICS_5: [&str; 5] = [
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
];

pub const IROH_PEERS_5: [&str; 5] = ["signer-1", "signer-2", "signer-3", "signer-4", "signer-5"];

pub const IROH_SEED_HEX_5: [&str; 5] = [
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
];

pub struct TestKeyGenerator {
    seed: [u8; 32],
}

impl TestKeyGenerator {
    pub fn new(seed: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(seed.as_bytes());
        let hash = hasher.finalize();
        Self { seed: *hash.as_bytes() }
    }

    pub fn generate_kaspa_keypair(&self, index: u32) -> (secp256k1::SecretKey, secp256k1::PublicKey) {
        let mut input = self.seed.to_vec();
        input.extend_from_slice(&index.to_le_bytes());
        let mut hasher = blake3::Hasher::new();
        hasher.update(&input);
        let key_bytes = hasher.finalize();

        let secret = secp256k1::SecretKey::from_slice(key_bytes.as_bytes()).expect("secret key");
        let public = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret);
        (secret, public)
    }

    pub fn generate_kaspa_keypair_full(&self, index: u32) -> Keypair {
        let secp = Secp256k1::new();
        let (secret, _) = self.generate_kaspa_keypair(index);
        Keypair::from_secret_key(&secp, &secret)
    }

    pub fn generate_kaspa_address(&self, index: u32, network: Prefix) -> Address {
        let (_, pubkey) = self.generate_kaspa_keypair(index);
        let (xonly, _) = pubkey.x_only_public_key();
        Address::new(network, Version::PubKey, &xonly.serialize())
    }

    pub fn generate_validator_keypair(&self, index: u32) -> (secp256k1::SecretKey, String) {
        let (secret, pubkey) = self.generate_kaspa_keypair(1000 + index);
        let pubkey_bytes = &pubkey.serialize_uncompressed()[1..];
        let mut hasher = Keccak256::new();
        hasher.update(pubkey_bytes);
        let hash = hasher.finalize();
        let eth_address = format!("0x{}", hex::encode(&hash[12..]));
        (secret, eth_address)
    }

    pub fn generate_iroh_keypair(&self, index: u32) -> (IrohSecretKey, IrohPublicKey) {
        let mut input = self.seed.to_vec();
        input.extend_from_slice(b"iroh");
        input.extend_from_slice(&index.to_le_bytes());
        let mut hasher = blake3::Hasher::new();
        hasher.update(&input);
        let key_bytes = hasher.finalize();
        let secret = IrohSecretKey::from_bytes(key_bytes.as_bytes());
        let public = secret.public();
        (secret, public)
    }

    pub fn generate_redeem_script(&self, m: usize, n: usize) -> Vec<u8> {
        let mut pubkeys = Vec::with_capacity(n);
        for idx in 0..n {
            let (_, pubkey) = self.generate_kaspa_keypair(idx as u32);
            let (xonly, _) = pubkey.x_only_public_key();
            pubkeys.push(xonly.serialize());
        }
        multisig_redeem_script(pubkeys.iter(), m).expect("redeem script")
    }
}
