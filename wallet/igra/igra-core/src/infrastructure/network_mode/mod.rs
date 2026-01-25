//! Network mode security validation.
//!
//! Network mode determines the service's security posture. The goal is to prevent
//! accidental production misconfiguration by enforcing stricter validation when the
//! value-at-risk is highest.

mod report;
mod rules;
mod validator;

use crate::foundation::ThresholdError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

pub use report::{ErrorCategory, ValidationReport};
pub use validator::{SecurityValidator, ValidationContext, ValidationStrictness};

/// Network mode determines security posture (Mainnet/Testnet/Devnet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    /// Production network with real funds (strict enforcement).
    Mainnet,
    /// Pre-production test network (warnings, reasonable defaults).
    Testnet,
    /// Development network (minimal restrictions).
    Devnet,
}

impl NetworkMode {
    pub const fn is_production(&self) -> bool {
        matches!(self, Self::Mainnet)
    }

    pub const fn address_prefix(&self) -> &'static str {
        match self {
            Self::Mainnet => "kaspa:",
            Self::Testnet => "kaspatest:",
            Self::Devnet => "kaspadev:",
        }
    }

    /// BIP44 coin type as a string.
    pub const fn coin_type(&self) -> &'static str {
        match self {
            Self::Mainnet => "111110",
            Self::Testnet => "111111",
            Self::Devnet => "111111",
        }
    }

    /// Expected Kaspa node network id (best-effort string match).
    pub const fn kaspa_network_id_hint(&self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Devnet => "devnet",
        }
    }
}

impl Default for NetworkMode {
    fn default() -> Self {
        // Safe-by-default: strictest mode.
        Self::Mainnet
    }
}

impl fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Devnet => write!(f, "devnet"),
        }
    }
}

impl FromStr for NetworkMode {
    type Err = ThresholdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "devnet" => Ok(Self::Devnet),
            other => Err(ThresholdError::ConfigError(format!("invalid network mode '{other}'; expected: mainnet, testnet, devnet"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_mode_parse_and_defaults() {
        assert_eq!("mainnet".parse::<NetworkMode>().unwrap(), NetworkMode::Mainnet);
        assert_eq!("TESTNET".parse::<NetworkMode>().unwrap(), NetworkMode::Testnet);
        assert_eq!("devnet".parse::<NetworkMode>().unwrap(), NetworkMode::Devnet);
        assert!("invalid".parse::<NetworkMode>().is_err());
        assert_eq!(NetworkMode::default(), NetworkMode::Mainnet);
    }

    #[test]
    fn network_mode_prefix_and_coin_type() {
        assert_eq!(NetworkMode::Mainnet.address_prefix(), "kaspa:");
        assert_eq!(NetworkMode::Testnet.address_prefix(), "kaspatest:");
        assert_eq!(NetworkMode::Devnet.address_prefix(), "kaspadev:");
        assert_eq!(NetworkMode::Mainnet.coin_type(), "111110");
        assert_eq!(NetworkMode::Testnet.coin_type(), "111111");
    }
}
