use igra_core::config::AppConfig;
use igra_core::coordination::coordinator::Coordinator;
use igra_core::hd::derive_keypair_from_key_data;
use igra_core::model::{EventSource, PartialSigRecord, RequestDecision, SigningEvent};
use igra_core::types::{PeerId, RequestId, SessionId, TransactionId as RequestTransactionId};
use igra_core::pskt::multisig as pskt_multisig;
use igra_core::rpc::UnimplementedRpc;
use igra_core::signing::SignerBackend;
use igra_core::storage::rocks::RocksStorage;
use igra_core::storage::Storage;
use igra_core::transport::mock::{MockHub, MockTransport};
use igra_core::transport::Transport;
use kaspa_consensus_core::config::params::DEVNET_PARAMS;
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionId as KaspaTransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::standard::multisig_redeem_script;
use igra_core::hd::SigningKeypair;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use tempfile::TempDir;

fn config_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("igra repo root")
        .to_path_buf()
}

fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().expect("env lock")
}

fn load_from_ini_profile(config_path: &Path, profile: &str) -> AppConfig {
    let _guard = lock_env();
    let data_dir = tempfile::tempdir().expect("temp data dir");

    env::set_var("KASPA_DATA_DIR", data_dir.path());

    let config = igra_core::config::load_app_config_from_profile_path(config_path, profile)
        .expect("load app config");

    env::remove_var("KASPA_DATA_DIR");
    config
}

fn keypair_from_config(config: &AppConfig, derivation_path: &str) -> SigningKeypair {
    let hd = config.service.hd.as_ref().expect("hd config");
    let key_data = hd.decrypt_mnemonics().expect("decrypt mnemonics");
    let key_data = key_data.first().expect("mnemonic missing");
    derive_keypair_from_key_data(key_data, derivation_path, None).expect("derive keypair")
}

#[tokio::test]
async fn two_of_three_signing_flow_finalizes() {
    let root = config_root();
    let signer_config = root.join("artifacts/igra-config.ini");
    let signer_profiles = ["signer-1", "signer-2", "signer-3"];

    env::set_var("KASPA_IGRA_WALLET_SECRET", "devnet-test-secret-please-change");

    let configs = signer_profiles
        .iter()
        .map(|profile| load_from_ini_profile(&signer_config, profile))
        .collect::<Vec<_>>();

    let derivation_path = "m/45'/111111'/0'/0/0";
    let keypairs = configs
        .iter()
        .map(|config| {
            (
                PeerId::from(config.iroh.peer_id.clone().expect("peer id")),
                keypair_from_config(config, derivation_path),
            )
        })
        .collect::<Vec<_>>();

    let public_keys = keypairs.iter().map(|(_, kp)| kp.public_key()).collect::<Vec<_>>();
    let xonly_keys = public_keys
        .iter()
        .map(|pk| pk.x_only_public_key().0.serialize())
        .collect::<Vec<_>>();

    let redeem = multisig_redeem_script(xonly_keys.iter(), 2).expect("redeem script");
    let spk = kaspa_txscript::standard::pay_to_script_hash_script(&redeem);
    let tx_id = KaspaTransactionId::from_slice(&[9u8; 32]);
    let input = pskt_multisig::MultisigInput {
        utxo_entry: UtxoEntry::new(10_000, spk, 0, false),
        previous_outpoint: TransactionOutpoint::new(tx_id, 0),
        redeem_script: redeem.clone(),
        sig_op_count: 2,
    };
    let output = pskt_multisig::MultisigOutput {
        amount: 9_000,
        script_public_key: ScriptPublicKey::from_vec(0, vec![1, 2, 3]),
    };
    let pskt = pskt_multisig::build_pskt(&[input], &[output]).expect("pskt build");
    let pskt_blob = pskt_multisig::serialize_pskt(&pskt).expect("pskt serialize");
    let signer_pskt = pskt_multisig::deserialize_pskt_signer(&pskt_blob).expect("signer pskt");
    let tx_template_hash = pskt_multisig::tx_template_hash(&signer_pskt).expect("tx hash");
    let per_input_hashes = pskt_multisig::input_hashes(&signer_pskt).expect("input hashes");

    let signing_event = SigningEvent {
        event_id: "event-2of3".to_string(),
        event_source: EventSource::Api { issuer: "integration-test".to_string() },
        derivation_path: derivation_path.to_string(),
        derivation_index: Some(0),
        destination_address: configs[0]
            .runtime
            .test_recipient
            .clone()
            .expect("test recipient"),
        amount_sompi: 123,
        metadata: Default::default(),
        timestamp_nanos: 1,
        signature: None,
    };

    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let hub = Arc::new(MockHub::new());
    let transport = Arc::new(MockTransport::new(hub, PeerId::from("signer-1"), [7u8; 32], 0));
    let _proposal_subscription = transport
        .subscribe_group([7u8; 32])
        .await
        .expect("proposal subscription");
    let coordinator = Coordinator::new(transport, storage.clone());

    let session_id = SessionId::from([1u8; 32]);
    let request_id = RequestId::from("req-2of3");

    coordinator
        .propose_session(
            session_id,
            request_id.clone(),
            signing_event,
            pskt_blob.clone(),
            tx_template_hash,
            &per_input_hashes,
            0,
            PeerId::from("signer-1"),
        )
        .await
        .expect("proposal");

    for (peer_id, keypair) in keypairs.iter().take(2) {
        let signer = igra_core::signing::threshold::ThresholdSigner::new(keypair.clone());
        let sigs = signer.sign(&pskt_blob).expect("sign pskt");
        for sig in sigs {
            storage
                .insert_partial_sig(
                    &request_id,
                    PartialSigRecord {
                        signer_peer_id: peer_id.clone(),
                        input_index: sig.input_index,
                        pubkey: sig.pubkey,
                        signature: sig.signature,
                        timestamp_nanos: 0,
                    },
                )
                .expect("insert partial sig");
        }
    }

    let partials = storage.list_partial_sigs(&request_id).expect("list partials");
    let combined = pskt_multisig::apply_partial_sigs(&pskt_blob, &partials).expect("apply partials");

    let rpc = Arc::new(UnimplementedRpc::new());
    let tx_id = coordinator
        .finalize_and_submit_multisig(&*rpc, &request_id, combined, 2, &public_keys, &DEVNET_PARAMS)
        .await
        .expect("finalize");

    assert!(!rpc.submitted_transactions().is_empty(), "transaction submitted");
    let stored = storage.get_request(&request_id).expect("stored request").expect("request");
    assert!(matches!(stored.decision, RequestDecision::Finalized));
    assert_eq!(stored.final_tx_id, Some(RequestTransactionId::from(tx_id)));

    env::remove_var("KASPA_IGRA_WALLET_SECRET");
}
