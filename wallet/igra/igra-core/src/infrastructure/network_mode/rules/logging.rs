use super::super::report::{ErrorCategory, ValidationReport};
use super::super::{NetworkMode, ValidationContext};
use std::path::Path;

pub fn validate_logging(mode: NetworkMode, ctx: &ValidationContext, report: &mut ValidationReport) {
    let filters = ctx.log_filters.as_deref().unwrap_or("").to_lowercase();
    if mode == NetworkMode::Mainnet {
        if filters.contains("debug") || filters.contains("trace") {
            report.add_error(ErrorCategory::Logging, "mainnet forbids debug/trace logging (set --log-level=info or higher)");
        }

        let Some(log_dir) = ctx.log_dir.as_deref() else {
            report.add_error(
                ErrorCategory::Logging,
                "mainnet requires log files + rotation: set KASPA_IGRA_LOG_DIR to a dedicated directory",
            );
            return;
        };
        if !Path::new(log_dir).exists() {
            report.add_error(ErrorCategory::Logging, format!("log dir does not exist: {}", log_dir.display()));
        }
    }
}
