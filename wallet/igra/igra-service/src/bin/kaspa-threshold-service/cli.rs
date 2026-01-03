use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "kaspa-threshold-service")]
#[command(about = "Kaspa threshold signature service", long_about = None)]
pub struct Cli {
    /// Path to configuration file
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Override data directory
    #[arg(short, long)]
    pub data_dir: Option<PathBuf>,

    /// Override node RPC URL
    #[arg(short, long)]
    pub node_url: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    pub log_level: String,

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
            std::env::set_var(igra_core::config::CONFIG_PATH_ENV, config_path);
        }

        if let Some(data_dir) = &self.data_dir {
            std::env::set_var(igra_core::config::DATA_DIR_ENV, data_dir);
        }

        if let Some(node_url) = &self.node_url {
            std::env::set_var(igra_core::config::NODE_URL_ENV, node_url);
        }

        if let Some(finalize_path) = &self.finalize {
            std::env::set_var(igra_core::config::FINALIZE_PSKT_JSON_ENV, finalize_path);
        }

        if let Some(audit_id) = &self.audit {
            std::env::set_var(igra_core::config::AUDIT_REQUEST_ID_ENV, audit_id);
        }
    }
}
