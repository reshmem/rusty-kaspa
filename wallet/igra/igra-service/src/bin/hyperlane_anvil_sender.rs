use alloy::network::EthereumWallet;
use alloy::providers::Provider;
use alloy::providers::ProviderBuilder;
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolCall;
use alloy::{primitives::keccak256, primitives::Address, primitives::B256};
use clap::Parser;
use kaspa_addresses::Address as KaspaAddress;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

sol! {
    function dispatch(uint32 destinationDomain, bytes32 recipientAddress, bytes calldata messageBody) payable returns (bytes32 messageId);
}

const DEFAULT_EVM_RPC_URL: &str = "http://127.0.0.1:8545";
const DEFAULT_DESTINATION_DOMAIN: u32 = 7;
const DEFAULT_AMOUNT_SOMPI: u64 = 20_000_000;
const DEFAULT_RECIPIENT_TAG: &str = "igra:v1:";

#[derive(Parser, Debug, Clone)]
#[command(name = "hyperlane_anvil_sender")]
#[command(about = "Send Hyperlane Mailbox.dispatch() transactions into Anvil for Igra devnet testing")]
struct Args {
    /// Anvil JSON-RPC URL.
    #[arg(long, default_value = DEFAULT_EVM_RPC_URL)]
    rpc_url: String,

    /// Mailbox contract address (0x...).
    ///
    /// If omitted, will be loaded from `--registry` + `--chain` by reading `chains/<chain>/addresses.yaml`.
    #[arg(long)]
    mailbox: Option<String>,

    /// Hyperlane registry directory containing `chains/<chain>/addresses.yaml`.
    #[arg(long)]
    registry: Option<PathBuf>,

    /// Chain name under registry (defaults to `anvil1`).
    #[arg(long, default_value = "anvil1")]
    chain: String,

    /// Private key (0x... hex) used to sign dispatch transactions.
    #[arg(long)]
    private_key: String,

    /// Destination domain id (Kaspa devnet is 7).
    #[arg(long, default_value_t = DEFAULT_DESTINATION_DOMAIN)]
    destination_domain: u32,

    /// Kaspa destination address to embed in the message body.
    ///
    /// If omitted, will be loaded from `--igra-root/config/devnet-keys.json` as `wallet.mining_address`.
    #[arg(long)]
    kaspa_address: Option<String>,

    /// Igra devnet root directory (to read `config/devnet-keys.json`).
    #[arg(long)]
    igra_root: Option<PathBuf>,

    /// Amount to transfer (sompi), embedded in the message body.
    #[arg(long, default_value_t = DEFAULT_AMOUNT_SOMPI)]
    amount_sompi: u64,

    /// Number of dispatches to send.
    #[arg(long, default_value_t = 1)]
    count: u32,

    /// Delay between dispatches (milliseconds).
    #[arg(long, default_value_t = 0)]
    delay_ms: u64,
}

#[derive(Deserialize)]
struct DevnetKeysFile {
    wallet: DevnetWallet,
}

#[derive(Deserialize)]
struct DevnetWallet {
    mining_address: String,
}

fn parse_evm_address(input: &str) -> Result<Address, String> {
    Address::from_str(input.trim()).map_err(|e| format!("invalid EVM address={input}: {e}"))
}

fn read_mining_address_from_devnet_keys(path: &Path) -> Result<String, String> {
    let data = fs::read(path).map_err(|e| format!("failed to read devnet keys at {path:?}: {e}"))?;
    let parsed: DevnetKeysFile = serde_json::from_slice(&data).map_err(|e| format!("invalid json in {path:?}: {e}"))?;
    if parsed.wallet.mining_address.trim().is_empty() {
        return Err(format!("missing wallet.mining_address in {path:?}"));
    }
    Ok(parsed.wallet.mining_address)
}

fn read_mailbox_from_registry(registry: &Path, chain: &str) -> Result<Address, String> {
    let path = registry.join("chains").join(chain).join("addresses.yaml");
    let data = fs::read(&path).map_err(|e| format!("failed to read {path:?}: {e}"))?;
    let yaml: serde_yaml::Value = serde_yaml::from_slice(&data).map_err(|e| format!("invalid yaml in {path:?}: {e}"))?;

    let mailbox = yaml
        .get("mailbox")
        .and_then(|v| v.as_str())
        .or_else(|| yaml.get("addresses").and_then(|a| a.get("mailbox")).and_then(|v| v.as_str()))
        .ok_or_else(|| format!("missing mailbox in {path:?} (expected `mailbox:` or `addresses.mailbox:`)"))?;

    parse_evm_address(mailbox)
}

fn compute_recipient_bytes32(kaspa_address: &str) -> B256 {
    let mut preimage = Vec::with_capacity(DEFAULT_RECIPIENT_TAG.len() + kaspa_address.len());
    preimage.extend_from_slice(DEFAULT_RECIPIENT_TAG.as_bytes());
    preimage.extend_from_slice(kaspa_address.as_bytes());
    keccak256(preimage)
}

fn build_message_body(amount_sompi: u64, kaspa_address: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + kaspa_address.as_bytes().len());
    body.extend_from_slice(&amount_sompi.to_le_bytes());
    body.extend_from_slice(kaspa_address.as_bytes());
    body
}

fn resolve_kaspa_address(args: &Args) -> Result<String, String> {
    if let Some(addr) = &args.kaspa_address {
        return Ok(addr.clone());
    }
    let igra_root = args
        .igra_root
        .as_ref()
        .ok_or_else(|| "missing --kaspa-address; provide --igra-root to load wallet.mining_address".to_string())?;
    let devnet_keys = igra_root.join("config").join("devnet-keys.json");
    read_mining_address_from_devnet_keys(&devnet_keys)
}

fn resolve_mailbox(args: &Args) -> Result<Address, String> {
    if let Some(mailbox) = &args.mailbox {
        return parse_evm_address(mailbox);
    }
    let registry = args
        .registry
        .as_ref()
        .ok_or_else(|| "missing --mailbox; provide --registry + --chain to load chains/<chain>/addresses.yaml".to_string())?;
    read_mailbox_from_registry(registry, &args.chain)
}

fn validate_kaspa_address(address: &str) -> Result<(), String> {
    KaspaAddress::try_from(address).map_err(|e| format!("invalid kaspa address={address}: {e}"))?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mailbox = resolve_mailbox(&args).map_err(|e| format!("resolve mailbox failed: {e}"))?;
    let kaspa_address = resolve_kaspa_address(&args).map_err(|e| format!("resolve kaspa address failed: {e}"))?;
    validate_kaspa_address(&kaspa_address).map_err(|e| format!("kaspa address validation failed: {e}"))?;

    let signer: PrivateKeySigner = args.private_key.trim().parse().map_err(|e| format!("invalid --private-key: {e}"))?;
    let wallet = EthereumWallet::from(signer);

    let provider = ProviderBuilder::new().with_recommended_fillers().wallet(wallet).on_http(args.rpc_url.parse()?);

    let recipient = compute_recipient_bytes32(&kaspa_address);
    let delay = Duration::from_millis(args.delay_ms);

    println!(
        "Dispatching to mailbox={:?} destination_domain={} kaspa_address={} recipient_bytes32=0x{} count={} amount_sompi={} rpc_url={}",
        mailbox,
        args.destination_domain,
        kaspa_address,
        hex::encode(recipient),
        args.count,
        args.amount_sompi,
        args.rpc_url
    );

    for i in 0..args.count {
        let body = build_message_body(args.amount_sompi, &kaspa_address);
        let call = dispatchCall { destinationDomain: args.destination_domain, recipientAddress: recipient, messageBody: body.into() };

        let tx = TransactionRequest::default().to(mailbox).input(call.abi_encode().into());

        let pending = provider.send_transaction(tx).await.map_err(|e| format!("dispatch send failed (i={i}): {e}"))?;

        let receipt = pending.get_receipt().await.map_err(|e| format!("dispatch receipt failed (i={i}): {e}"))?;

        println!(
            "dispatched i={} tx_hash={:?} status={:?} block_number={:?}",
            i,
            receipt.transaction_hash,
            receipt.status(),
            receipt.block_number
        );

        if !delay.is_zero() && i + 1 < args.count {
            tokio::time::sleep(delay).await;
        }
    }

    Ok(())
}
