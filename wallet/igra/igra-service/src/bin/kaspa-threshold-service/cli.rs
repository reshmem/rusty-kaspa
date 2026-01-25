use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "kaspa-threshold-service")]
#[command(about = "Kaspa threshold signature service", long_about = None)]
pub struct Cli {
    /// Network mode (mainnet, testnet, devnet)
    ///
    /// Determines security validation level.
    #[arg(long, default_value = "mainnet", value_name = "MODE")]
    #[arg(value_parser = ["mainnet", "testnet", "devnet"])]
    pub network: String,

    /// Allow remote Kaspa RPC endpoint in mainnet (NOT RECOMMENDED).
    ///
    /// Mainnet defaults to local-only RPC for security; this flag is an explicit opt-in.
    #[arg(long)]
    pub allow_remote_rpc: bool,

    /// Path to configuration file
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Profile name to load from `[profiles.<name>]` in the TOML config
    #[arg(long)]
    pub profile: Option<String>,

    /// Override data directory
    #[arg(short, long)]
    pub data_dir: Option<PathBuf>,

    /// Override node RPC URL
    #[arg(short, long)]
    pub node_url: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    pub log_level: String,

    /// Validate configuration + startup security checks and exit.
    #[arg(long)]
    pub validate_only: bool,

    /// Finalize PSKT from JSON file
    #[arg(long)]
    pub finalize: Option<PathBuf>,

    /// Dump audit trail for request ID
    #[arg(long)]
    pub audit: Option<String>,
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }

    pub fn apply_to_env(&self) {
        if let Some(config_path) = &self.config {
            std::env::set_var(igra_core::infrastructure::config::CONFIG_PATH_ENV, config_path);
        }

        if let Some(data_dir) = &self.data_dir {
            std::env::set_var(igra_core::infrastructure::config::DATA_DIR_ENV, data_dir);
        }

        if let Some(node_url) = &self.node_url {
            // Figment env override for `service.node_rpc_url` (and pskt cascade).
            std::env::set_var("IGRA_SERVICE__NODE_RPC_URL", node_url);
            std::env::set_var("IGRA_SERVICE__PSKT__NODE_RPC_URL", node_url);
        }

        if let Some(finalize_path) = &self.finalize {
            std::env::set_var(igra_core::infrastructure::config::FINALIZE_PSKT_JSON_ENV, finalize_path);
        }

        if let Some(audit_id) = &self.audit {
            std::env::set_var(igra_core::infrastructure::config::AUDIT_REQUEST_ID_ENV, audit_id);
        }
    }
}
