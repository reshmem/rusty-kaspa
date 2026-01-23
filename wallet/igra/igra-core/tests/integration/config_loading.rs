use igra_core::domain::group_id::compute_group_id;
use igra_core::infrastructure::config::load_app_config_from_path;
use igra_core::infrastructure::config::load_app_config_from_profile_path;
use igra_core::infrastructure::config::KeyType;
use std::collections::BTreeSet;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

fn config_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("igra repo root").to_path_buf()
}

fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|err| err.into_inner())
}

fn load_from_profile(config_path: &Path, profile: &str) -> igra_core::infrastructure::config::AppConfig {
    let _guard = lock_env();
    let data_dir = tempfile::tempdir().expect("temp data dir");

    env::set_var("KASPA_IGRA_WALLET_SECRET", "devnet-test-secret-please-change");
    env::set_var("KASPA_DATA_DIR", data_dir.path());

    let config = load_app_config_from_profile_path(config_path, profile).expect("load app config");

    env::remove_var("KASPA_DATA_DIR");
    env::remove_var("KASPA_IGRA_WALLET_SECRET");

    config
}

#[test]
fn test_config_loading_when_hd_key_type_raw_then_requires_redeem_script() {
    let _guard = lock_env();
    let data_dir = tempfile::tempdir().expect("temp data dir");
    env::set_var("KASPA_DATA_DIR", data_dir.path());

    let toml_path = data_dir.path().join("igra-raw.toml");
    std::fs::write(
        &toml_path,
        r#"
        [service]
        node_rpc_url = "grpc://127.0.0.1:16110"
        [service.hd]
        key_type = "raw_private_key"
        "#,
    )
    .expect("write toml");

    let err = load_app_config_from_path(&toml_path).expect_err("raw key without redeem script should fail validation");
    assert!(err.to_string().contains("service.pskt.redeem_script_hex is required when service.hd.key_type=raw_private_key"));

    env::remove_var("KASPA_DATA_DIR");
}

#[test]
fn test_config_loading_when_hd_key_type_raw_then_loads() {
    let _guard = lock_env();
    let data_dir = tempfile::tempdir().expect("temp data dir");
    env::set_var("KASPA_DATA_DIR", data_dir.path());

    let toml_path = data_dir.path().join("igra-raw.toml");
    std::fs::write(
        &toml_path,
        r#"
        [service]
        node_rpc_url = "grpc://127.0.0.1:16110"
        [service.pskt]
        redeem_script_hex = "00"
        [service.hd]
        key_type = "raw_private_key"
        "#,
    )
    .expect("write toml");

    let config = load_app_config_from_path(&toml_path).expect("load app config");
    let hd = config.service.hd.as_ref().expect("hd config");
    assert_eq!(hd.key_type, KeyType::RawPrivateKey);

    env::remove_var("KASPA_DATA_DIR");
}

#[test]
fn test_config_loading_when_hd_key_type_default_then_hd_mnemonic() {
    let _guard = lock_env();
    let data_dir = tempfile::tempdir().expect("temp data dir");
    env::set_var("KASPA_DATA_DIR", data_dir.path());
    env::set_var("KASPA_IGRA_WALLET_SECRET", "devnet-test-secret-please-change");

    let toml_path = data_dir.path().join("igra-hd.toml");
    std::fs::write(
        &toml_path,
        r#"
        [service]
        node_rpc_url = "grpc://127.0.0.1:16110"
        [service.pskt]
        redeem_script_hex = "00"
        [service.hd]
        mnemonics = ["abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"]
        "#,
    )
    .expect("write toml");

    let config = load_app_config_from_path(&toml_path).expect("load app config");
    let hd = config.service.hd.as_ref().expect("hd config");
    assert_eq!(hd.key_type, KeyType::HdMnemonic);

    env::remove_var("KASPA_DATA_DIR");
    env::remove_var("KASPA_IGRA_WALLET_SECRET");
}

#[test]
fn test_config_loading_when_profiled_toml_then_group_id_matches_iroh_group_id() {
    let root = config_root();
    let signer_config = root.join("artifacts/igra-config.toml");
    let expected_peers = ["signer-1", "signer-2", "signer-3"];
    let expected_verifiers = [
        "signer-1:03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
        "signer-2:29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7",
        "signer-3:2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d",
    ];

    for (idx, profile) in expected_peers.iter().enumerate() {
        let config = load_from_profile(&signer_config, profile);
        let group = config.group.as_ref().expect("group config");
        let group_id = compute_group_id(group).expect("group id").group_id;
        let group_id_hex = hex::encode(group_id);

        assert_eq!(group.threshold_m, 2);
        assert_eq!(group.threshold_n, 3);
        assert_eq!(group.member_pubkeys.len(), 3);

        let configured_group_id = config.iroh.group_id.as_ref().expect("iroh.group_id");
        assert_eq!(configured_group_id, &group_id_hex);

        let peer_id = config.iroh.peer_id.as_ref().expect("iroh.peer_id");
        assert_eq!(peer_id, expected_peers[idx]);

        let verifier_set = config.iroh.verifier_keys.iter().cloned().collect::<BTreeSet<_>>();
        let expected_set = expected_verifiers.iter().map(|v| v.to_string()).collect::<BTreeSet<_>>();
        assert_eq!(verifier_set, expected_set);
    }
}

#[test]
fn test_config_loading_when_hyperlane_validators_present_then_loads() {
    let _guard = lock_env();
    let data_dir = tempfile::tempdir().expect("temp data dir");
    env::set_var("KASPA_DATA_DIR", data_dir.path());

    let toml_path = data_dir.path().join("igra-hyperlane.toml");
    std::fs::write(
        &toml_path,
        r#"
        [hyperlane]
        validators = ["03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"]
        threshold = 1
        "#,
    )
    .expect("write toml");

    let config = load_app_config_from_path(&toml_path).expect("load app config");
    assert_eq!(config.hyperlane.validators.len(), 1);
    assert_eq!(config.hyperlane.threshold, Some(1));

    env::remove_var("KASPA_DATA_DIR");
}
