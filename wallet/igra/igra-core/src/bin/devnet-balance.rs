use igra_core::foundation::GRPC_MAX_MESSAGE_SIZE_BYTES;
use kaspa_addresses::Address;
use kaspa_grpc_client::GrpcClient;
use kaspa_notify::subscription::context::SubscriptionContext;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::notify::mode::NotificationMode;
use std::env;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let mut rpc = "127.0.0.1:16110".to_string();
    let mut addrs: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--rpc" => {
                if i + 1 >= args.len() {
                    eprintln!("--rpc requires a value");
                    return ExitCode::FAILURE;
                }
                rpc = args[i + 1].clone();
                i += 2;
            }
            "--addresses" => {
                if i + 1 >= args.len() {
                    eprintln!("--addresses requires a comma-separated list");
                    return ExitCode::FAILURE;
                }
                addrs.extend(args[i + 1].split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
                i += 2;
            }
            "--help" | "-h" => {
                usage();
                return ExitCode::SUCCESS;
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
        return ExitCode::FAILURE;
    }

    let address_strings = addrs.clone();
    let mut addresses: Vec<Address> = Vec::new();
    for a in addrs.iter() {
        match Address::try_from(a.as_str()) {
            Ok(addr) => addresses.push(addr),
            Err(e) => {
                eprintln!("Invalid address '{}': {}", a, e);
                return ExitCode::FAILURE;
            }
        }
    }

    let subscription_context = SubscriptionContext::new();
    let client = match GrpcClient::connect_with_args(
        NotificationMode::Direct,
        format!("grpc://{}", rpc),
        Some(subscription_context),
        true,
        None,
        false,
        Some(GRPC_MAX_MESSAGE_SIZE_BYTES),
        Default::default(),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to connect to rpc {}: {}", rpc, e);
            return ExitCode::FAILURE;
        }
    };

    let resp = match client.get_utxos_by_addresses(addresses).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("get_utxos_by_addresses failed: {}", e);
            return ExitCode::FAILURE;
        }
    };
    // Group by address so we can print per-address totals.
    use std::collections::HashMap;
    let mut per_addr: HashMap<String, Vec<kaspa_rpc_core::model::tx::RpcUtxoEntry>> = HashMap::new();
    for entry in resp {
        if let Some(addr) = entry.address {
            per_addr.entry(addr.to_string()).or_default().push(entry.utxo_entry);
        }
    }
    let mut grand_total = 0u64;
    for addr in address_strings {
        let utxos = per_addr.get(&addr);
        let total: u64 = utxos.map(|v| v.iter().map(|u| u.amount).sum()).unwrap_or(0);
        grand_total += total;
        println!("Address {}: {} sompi (~{:.8} KAS)", addr, total, total as f64 / 100_000_000.0);
    }
    println!("Grand total: {} sompi (~{:.8} KAS)", grand_total, grand_total as f64 / 100_000_000.0);
    ExitCode::SUCCESS
}

fn usage() {
    eprintln!("Usage: devnet-balance [--rpc HOST:PORT] [--addresses addr1,addr2,...]");
    eprintln!("Positional addresses are also accepted. Default rpc: 127.0.0.1:16110");
}
