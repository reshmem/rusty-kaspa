//! Validation report and error accumulation.

use super::NetworkMode;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    Secrets,
    RpcEndpoint,
    Configuration,
    Logging,
    FilePermissions,
    Startup,
    Network,
}

#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub category: ErrorCategory,
    pub message: String,
}

/// Validation report with errors and warnings.
#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub network_mode: NetworkMode,
    pub errors: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
}

impl ValidationReport {
    pub fn new(network_mode: NetworkMode) -> Self {
        Self { network_mode, errors: Vec::new(), warnings: Vec::new() }
    }

    pub fn add_error(&mut self, category: ErrorCategory, message: impl Into<String>) {
        self.errors.push(ValidationIssue { category, message: message.into() });
    }

    pub fn add_warning(&mut self, category: ErrorCategory, message: impl Into<String>) {
        self.warnings.push(ValidationIssue { category, message: message.into() });
    }

    pub fn merge(&mut self, other: ValidationReport) {
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    pub fn format_report(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("\n🔍 Security Validation Report ({})\n", self.network_mode));
        out.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

        if self.errors.is_empty() && self.warnings.is_empty() {
            out.push_str("✅ All validation checks passed\n");
            return out;
        }

        if !self.errors.is_empty() {
            out.push_str(&format!("❌ {} ERROR(S) FOUND:\n\n", self.errors.len()));
            for (i, issue) in self.errors.iter().enumerate() {
                out.push_str(&format!("  {}. [{:?}] {}\n", i + 1, issue.category, issue.message));
            }
            out.push('\n');
        }

        if !self.warnings.is_empty() {
            out.push_str(&format!("⚠️  {} WARNING(S):\n\n", self.warnings.len()));
            for (i, issue) in self.warnings.iter().enumerate() {
                out.push_str(&format!("  {}. [{:?}] {}\n", i + 1, issue.category, issue.message));
            }
            out.push('\n');
        }

        if self.network_mode.is_production() && self.has_errors() {
            out.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            out.push_str("❌ Mainnet validation FAILED - fix errors above before starting\n");
        }

        out
    }
}

impl fmt::Display for ValidationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.format_report())
    }
}
