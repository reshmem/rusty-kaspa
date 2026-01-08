use kaspa_addresses::Address;
use kaspa_grpc_client::GrpcClient;
use kaspa_notify::subscription::context::SubscriptionContext;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::notify::mode::NotificationMode;
use std::env;

#[tokio::main]
async fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let mut rpc = "127.0.0.1:16110".to_string();
    let mut addrs: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--rpc" => {
                if i + 1 >= args.len() {
                    eprintln!("--rpc requires a value");
                    std::process::exit(1);
                }
                rpc = args[i + 1].clone();
                i += 2;
            }
            "--addresses" => {
                if i + 1 >= args.len() {
                    eprintln!("--addresses requires a comma-separated list");
                    std::process::exit(1);
                }
                addrs.extend(args[i + 1].split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
                i += 2;
            }
            "--help" | "-h" => {
                usage();
                return;
            }
            other => {
                // treat any other positional as address
                addrs.push(other.to_string());
                i += 1;
            }
        }
    }

    if addrs.is_empty() {
        usage();
        std::process::exit(1);
    }

    let address_strings = addrs.clone();
    let addresses: Vec<Address> = addrs
        .iter()
        .map(|a| Address::try_from(a.as_str()).unwrap_or_else(|e| {
            eprintln!("Invalid address '{}': {}", a, e);
            std::process::exit(1);
        }))
        .collect();

    let subscription_context = SubscriptionContext::new();
    let client = GrpcClient::connect_with_args(
        NotificationMode::Direct,
        format!("grpc://{}", rpc),
        Some(subscription_context),
        true,
        None,
        false,
        Some(500_000),
        Default::default(),
    )
    .await
    .expect("connect to rpc");

    let resp = client.get_utxos_by_addresses(addresses).await.expect("get_utxos_by_addresses");
    // Group by address so we can print per-address totals.
    use std::collections::HashMap;
    let mut per_addr: HashMap<String, Vec<kaspa_rpc_core::model::tx::RpcUtxoEntry>> = HashMap::new();
    for entry in resp {
        let addr = entry.address.expect("address field present").to_string();
        per_addr.entry(addr).or_default().push(entry.utxo_entry);
    }
    let mut grand_total = 0u64;
    for addr in address_strings {
        let utxos = per_addr.get(&addr);
        let total: u64 = utxos.map(|v| v.iter().map(|u| u.amount).sum()).unwrap_or(0);
        grand_total += total;
        println!("Address {}: {} sompi (~{:.8} KAS)", addr, total, total as f64 / 100_000_000.0);
    }
    println!("Grand total: {} sompi (~{:.8} KAS)", grand_total, grand_total as f64 / 100_000_000.0);
}

fn usage() {
    eprintln!("Usage: devnet-balance [--rpc HOST:PORT] [--addresses addr1,addr2,...]");
    eprintln!("Positional addresses are also accepted. Default rpc: 127.0.0.1:16110");
}
