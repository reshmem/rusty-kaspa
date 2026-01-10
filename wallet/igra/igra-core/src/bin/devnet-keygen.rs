use ed25519_dalek::SigningKey;
use igra_core::foundation::ThresholdError;
use igra_core::domain::group_id::compute_group_id;
use igra_core::domain::{GroupConfig, GroupMetadata, GroupPolicy};
use kaspa_addresses::Prefix;
use kaspa_bip32::{AddressType, ChildNumber, ExtendedPrivateKey, Language, Mnemonic, WordCount};
use kaspa_wallet_core::derivation::create_multisig_address;
use kaspa_wallet_core::encryption::EncryptionKind;
use kaspa_wallet_core::prelude::Secret;
use kaspa_wallet_core::storage::keydata::PrvKeyData;
use kaspa_wallet_keys::derivation::gen1::{PubkeyDerivationManager, WalletDerivationManager};
use kaspa_wallet_keys::derivation::traits::WalletDerivationManagerTrait;
use rand::rngs::OsRng;
use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::Serialize;

#[derive(Serialize)]
struct WalletOut {
    mnemonic: String,
    password: String,
    name: String,
    mining_address: String,
    private_key_hex: String,
}

#[derive(Serialize)]
struct SignerOut {
    profile: String,
    mnemonic: String,
    iroh_seed_hex: String,
    iroh_peer_id: String,
    iroh_pubkey_hex: String,
    pubkey_hex: String,
    address: String,
    derivation_path: String,
}

#[derive(Serialize)]
struct HyperlaneKeyOut {
    name: String,
    private_key_hex: String,
    public_key_hex: String,
}

#[derive(Serialize)]
struct Output {
    wallet: WalletOut,
    signers: Vec<SignerOut>,
    signer_addresses: Vec<String>,
    member_pubkeys: Vec<String>,
    redeem_script_hex: String,
    source_addresses: Vec<String>,
    change_address: String,
    hyperlane_keys: Vec<HyperlaneKeyOut>,
    group_id: String,
    multisig_address: String,
}

fn mnemonic_phrase() -> Result<Mnemonic, ThresholdError> {
    Mnemonic::random(WordCount::Words24, Language::English).map_err(|e| ThresholdError::Message(format!("mnemonic: {e}")))
}

fn pubkey_hex(pk: &PublicKey) -> String {
    hex::encode(pk.serialize())
}

fn random_seed_hex() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn peer_id_from_seed(seed_hex: &str) -> Result<String, ThresholdError> {
    let bytes = hex::decode(seed_hex)?;
    let digest = blake3::hash(&bytes);
    let prefix = &digest.as_bytes()[..8];
    Ok(format!("peer-{}", hex::encode(prefix)))
}

fn derive_pubkey_and_address(
    mnemonic: &Mnemonic,
    is_multisig: bool,
    account_index: u64,
    cosigner_index: Option<u32>,
) -> Result<(PublicKey, String), ThresholdError> {
    let xprv = kaspa_bip32::ExtendedPrivateKey::<kaspa_bip32::SecretKey>::new(mnemonic.to_seed(""))
        .map_err(|e| ThresholdError::Message(format!("xprv: {e}")))?;
    let xprv_str = xprv.to_string(kaspa_bip32::Prefix::KPRV).to_string();
    let wallet = WalletDerivationManager::from_master_xprv(&xprv_str, is_multisig, account_index, cosigner_index)
        .map_err(|e| ThresholdError::Message(format!("wallet derive: {e}")))?;
    let pk = wallet.derive_receive_pubkey(0).map_err(|e| ThresholdError::Message(format!("pubkey derive: {e}")))?;
    let address = PubkeyDerivationManager::create_address(&pk, Prefix::Devnet, false)
        .map_err(|e| ThresholdError::Message(format!("address derive: {e}")))?;
    Ok((pk, address.to_string()))
}

fn derive_wallet_private_key_hex(mnemonic: &Mnemonic) -> Result<String, ThresholdError> {
    let xprv = ExtendedPrivateKey::<kaspa_bip32::SecretKey>::new(mnemonic.to_seed(""))
        .map_err(|e| ThresholdError::Message(format!("xprv: {e}")))?;
    let path = WalletDerivationManager::build_derivate_path(false, 0, None, Some(AddressType::Receive))
        .map_err(|e| ThresholdError::Message(format!("derive path: {e}")))?;
    let receive_root = xprv.derive_path(&path).map_err(|e| ThresholdError::Message(format!("receive root: {e}")))?;
    let leaf = receive_root
        .derive_child(ChildNumber::new(0, false).map_err(|e| ThresholdError::Message(format!("child: {e}")))?)
        .map_err(|e| ThresholdError::Message(format!("derive child: {e}")))?;
    Ok(hex::encode(leaf.private_key().secret_bytes()))
}

fn main() -> Result<(), ThresholdError> {
    let password = "devnet".to_string();
    let name = "devnet".to_string();

    // Wallet (funding/mining)
    let wallet_mnemonic = mnemonic_phrase()?;
    let (_, mining_address) = derive_pubkey_and_address(&wallet_mnemonic, false, 0, None)?;
    let wallet_private_key_hex = derive_wallet_private_key_hex(&wallet_mnemonic)?;
    let wallet = WalletOut {
        mnemonic: wallet_mnemonic.phrase().to_string(),
        password: password.clone(),
        name: name.clone(),
        mining_address,
        private_key_hex: wallet_private_key_hex,
    };

    // Signers
    let derivation_path = igra_core::foundation::derivation_path_from_index(0);
    let payment_secret = None::<Secret>;
    let mut signers = Vec::new();
    let mut member_pubkeys = Vec::new();
    let mut source_addresses: Vec<String> = Vec::new();

    for (i, profile) in ["signer-1", "signer-2", "signer-3"].iter().enumerate() {
        let mnemonic = mnemonic_phrase()?;

        // Derive pubkey and address
        let (pubkey, address) = derive_pubkey_and_address(&mnemonic, true, 0, Some(i as u32))?;
        member_pubkeys.push(pubkey_hex(&pubkey));
        source_addresses.push(address.clone());

        // Iroh seed
        let iroh_seed_hex = random_seed_hex();
        let iroh_seed_bytes: [u8; 32] = hex::decode(&iroh_seed_hex)
            .map_err(|e| ThresholdError::Message(format!("seed hex: {e}")))?
            .as_slice()
            .try_into()
            .map_err(|_| ThresholdError::Message("32-byte seed required".to_string()))?;
        let iroh_signing = SigningKey::from_bytes(&iroh_seed_bytes);
        let iroh_pubkey_hex = hex::encode(iroh_signing.verifying_key().to_bytes());
        let iroh_peer_id = peer_id_from_seed(&iroh_seed_hex)?;

        let signer = SignerOut {
            profile: profile.to_string(),
            mnemonic: mnemonic.phrase().to_string(),
            iroh_seed_hex,
            iroh_peer_id,
            iroh_pubkey_hex,
            pubkey_hex: pubkey_hex(&pubkey),
            address,
            derivation_path: derivation_path.clone(),
        };
        signers.push(signer);
    }

    // Redeem script for 2-of-3 using signer mnemonics
    let prv_keys: Vec<PrvKeyData> = signers
        .iter()
        .map(|s| {
            let mn = Mnemonic::new(s.mnemonic.as_str(), Language::English)
                .map_err(|e| ThresholdError::Message(format!("mn parse: {e}")))?;
            PrvKeyData::try_from_mnemonic(mn, payment_secret.as_ref(), EncryptionKind::XChaCha20Poly1305, None)
                .map_err(|e| ThresholdError::Message(format!("prv: {e}")))
        })
        .collect::<Result<_, _>>()?;
    let pubkeys = igra_core::foundation::derive_pubkeys(igra_core::foundation::HdInputs {
        key_data: &prv_keys,
        xpubs: &[],
        derivation_path: &derivation_path,
        payment_secret: payment_secret.as_ref(),
    })
    .expect("derive pubkeys");
    let redeem_script = igra_core::foundation::redeem_script_from_pubkeys(&pubkeys, 2).expect("redeem");
    let redeem_script_hex = hex::encode(redeem_script);

    let multisig_address = {
        let keys: Vec<PublicKey> = member_pubkeys
            .iter()
            .map(|hex_pk| {
                let bytes = hex::decode(hex_pk).expect("pubkey hex decode");
                PublicKey::from_slice(&bytes).expect("pubkey parse")
            })
            .collect();
        create_multisig_address(2, keys, Prefix::Devnet, true).expect("multisig address").to_string()
    };
    let change_address = multisig_address.clone();

    // Hyperlane validators (2)
    let secp = Secp256k1::new();
    let mut hyperlane_keys = Vec::new();
    for idx in 0..2 {
        let secret = SecretKey::new(&mut OsRng);
        let public = PublicKey::from_secret_key(&secp, &secret);
        hyperlane_keys.push(HyperlaneKeyOut {
            name: format!("validator-{}", idx + 1),
            private_key_hex: hex::encode(secret.secret_bytes()),
            public_key_hex: pubkey_hex(&public),
        });
    }

    // Build policy to match the devnet template (empty allowlist, devnet limits).
    let policy = GroupPolicy {
        allowed_destinations: Vec::new(),
        min_amount_sompi: Some(1_000_000),
        max_amount_sompi: Some(100_000_000_000),
        max_daily_volume_sompi: Some(500_000_000_000),
        require_reason: false,
    };
    let group_metadata = GroupMetadata { creation_timestamp_nanos: 0, group_name: None, policy_version: 1, extra: Default::default() };

    let output = Output {
        wallet,
        signers,
        signer_addresses: source_addresses.clone(),
        member_pubkeys: member_pubkeys.clone(),
        redeem_script_hex,
        source_addresses: vec![multisig_address.clone()],
        change_address,
        hyperlane_keys,
        group_id: {
            let member_pubkeys_bytes: Vec<Vec<u8>> = member_pubkeys
                .iter()
                .map(|hex_pk| hex::decode(hex_pk).map_err(ThresholdError::from))
                .collect::<Result<_, _>>()?;
            let group_cfg = GroupConfig {
                network_id: 0,
                threshold_m: 2,
                threshold_n: 3,
                member_pubkeys: member_pubkeys_bytes,
                fee_rate_sompi_per_gram: 0,
                finality_blue_score_threshold: 0,
                dust_threshold_sompi: 0,
                min_recipient_amount_sompi: 0,
                session_timeout_seconds: 60,
                group_metadata,
                policy,
            };
            hex::encode(compute_group_id(&group_cfg)?)
        },
        multisig_address,
    };

    let json = serde_json::to_string_pretty(&output)?;
    println!("{json}");
    Ok(())
}
