use super::report::{ErrorCategory, ValidationReport};
use super::rules;
use super::NetworkMode;
use crate::foundation::ThresholdError;
use crate::infrastructure::config::AppConfig;
use crate::infrastructure::keys::KeyManagerContext;
use crate::infrastructure::rpc::KaspaGrpcQueryClient;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationStrictness {
    Error,
    Warning,
    Ignore,
}

#[derive(Clone, Debug, Default)]
pub struct ValidationContext {
    pub config_path: Option<PathBuf>,
    pub allow_remote_rpc: bool,
    /// The filter string passed to `infrastructure::logging::init_logger` (CLI `--log-level`).
    pub log_filters: Option<String>,
    /// `KASPA_IGRA_LOG_DIR` value, if any.
    pub log_dir: Option<PathBuf>,
}

pub struct SecurityValidator {
    mode: NetworkMode,
}

impl SecurityValidator {
    pub const fn new(mode: NetworkMode) -> Self {
        Self { mode }
    }

    pub const fn mode(&self) -> NetworkMode {
        self.mode
    }

    fn strictness(&self) -> (ValidationStrictness, ValidationStrictness, ValidationStrictness) {
        match self.mode {
            NetworkMode::Mainnet => (ValidationStrictness::Error, ValidationStrictness::Error, ValidationStrictness::Error),
            NetworkMode::Testnet => (ValidationStrictness::Warning, ValidationStrictness::Warning, ValidationStrictness::Warning),
            NetworkMode::Devnet => (ValidationStrictness::Ignore, ValidationStrictness::Ignore, ValidationStrictness::Ignore),
        }
    }

    /// Static validation that does not require network access.
    pub fn validate_static(&self, app_config: &AppConfig, ctx: &ValidationContext) -> ValidationReport {
        let mut report = ValidationReport::new(self.mode);
        let (secrets_level, config_level, fs_level) = self.strictness();

        rules::config::validate_network_confirmation(app_config, self.mode, config_level, &mut report);
        rules::secrets::validate_secrets(app_config, self.mode, ctx, secrets_level, &mut report);
        rules::rpc::validate_rpc_endpoints(app_config, self.mode, ctx, &mut report);
        rules::logging::validate_logging(self.mode, ctx, &mut report);
        rules::filesystem::validate_filesystem(app_config, self.mode, ctx, fs_level, &mut report);
        rules::config::validate_addresses_and_threshold(app_config, self.mode, config_level, &mut report);

        report
    }

    /// Startup checks that require access to secrets and node RPC.
    pub async fn validate_startup(
        &self,
        app_config: &AppConfig,
        kaspa_query: &KaspaGrpcQueryClient,
        key_ctx: &KeyManagerContext,
    ) -> Result<ValidationReport, ThresholdError> {
        let mut report = ValidationReport::new(self.mode);
        let (_secrets_level, _config_level, fs_level) = self.strictness();

        rules::startup::validate_runtime_environment(self.mode, app_config, fs_level, &mut report);
        rules::startup::validate_kaspa_node(self.mode, kaspa_query, &mut report).await;
        rules::startup::validate_required_secrets(self.mode, app_config, key_ctx, &mut report).await?;

        let has_secret_errors = report.errors.iter().any(|issue| issue.category == ErrorCategory::Secrets);
        if has_secret_errors {
            return Err(ThresholdError::ConfigError(format!("startup validation failed (required secrets unavailable):\n{}", report)));
        }

        if report.has_errors() && self.mode.is_production() {
            return Err(ThresholdError::ConfigError(format!("startup validation failed:\n{}", report)));
        }

        if report.has_errors() && !self.mode.is_production() {
            report.add_warning(ErrorCategory::Startup, "startup checks failed in non-mainnet mode; continuing (dev/test posture)");
        }

        Ok(report)
    }
}
