use criterion::{black_box, criterion_group, criterion_main, Criterion};
use igra_core::config::{PsktBuildConfig, PsktOutput};
use igra_core::model::FeePaymentMode;
use igra_core::pskt::builder::build_pskt_with_client;
use igra_core::rpc::{UtxoWithOutpoint, UnimplementedRpc};
use kaspa_addresses::Address;
use kaspa_consensus_core::tx::{TransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::pay_to_address_script;
use kaspa_txscript::standard::multisig_redeem_script;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use tokio::runtime::Runtime;

fn test_keypair(seed: u8) -> Keypair {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[seed; 32]).expect("secret key");
    Keypair::from_secret_key(&secp, &secret)
}

fn redeem_script_hex() -> String {
    let kp1 = test_keypair(1);
    let kp2 = test_keypair(2);
    let (x1, _) = kp1.public_key().x_only_public_key();
    let (x2, _) = kp2.public_key().x_only_public_key();
    let redeem = multisig_redeem_script([x1.serialize(), x2.serialize()].iter(), 2).expect("redeem");
    hex::encode(redeem)
}

fn build_utxos(address: &Address, count: usize, amount: u64) -> Vec<UtxoWithOutpoint> {
    (0..count)
        .map(|idx| UtxoWithOutpoint {
            address: Some(address.clone()),
            outpoint: TransactionOutpoint::new(TransactionId::from_slice(&[idx as u8; 32]), idx as u32),
            entry: UtxoEntry::new(amount, pay_to_address_script(address), 0, false),
        })
        .collect()
}

fn bench_pskt_build(c: &mut Criterion) {
    let rt = Runtime::new().expect("runtime");
    let address = "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3";
    let addr = Address::constructor(address);
    let redeem_script = redeem_script_hex();

    for count in [10usize, 50, 100, 200] {
        let utxos = build_utxos(&addr, count, 1_000_000_000);
        let rpc = UnimplementedRpc::with_utxos(utxos);
        let config = PsktBuildConfig {
            node_rpc_url: String::new(),
            source_addresses: vec![address.to_string()],
            redeem_script_hex: redeem_script.clone(),
            sig_op_count: 2,
            outputs: vec![PsktOutput {
                address: address.to_string(),
                amount_sompi: 1_000_000_000,
            }],
            fee_payment_mode: FeePaymentMode::RecipientPays,
            fee_sompi: Some(0),
            change_address: Some(address.to_string()),
        };

        let bench_id = format!("pskt_build_{}_utxos", count);
        c.bench_function(&bench_id, |b| {
            b.iter(|| {
                let pskt = rt.block_on(async { build_pskt_with_client(&rpc, &config).await.expect("pskt") });
                black_box(pskt);
            })
        });
    }
}

criterion_group!(benches, bench_pskt_build);
criterion_main!(benches);
