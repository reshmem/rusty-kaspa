//! Iroh discovery and relay configuration helpers.
//!
//! Iroh supports multiple discovery mechanisms (static, pkarr, DNS) and relay servers for NAT traversal.
//! This module converts Igra config into `iroh::endpoint::Builder` settings.

use crate::foundation::{ThresholdError, MAX_RELAY_URL_LENGTH, PKARR_REPUBLISH_INTERVAL_SECS};
use crate::infrastructure::config::{IrohDiscoveryConfig, IrohRelayConfig};
use iroh::discovery::dns::DnsDiscovery;
use iroh::discovery::pkarr::PkarrPublisher;
use iroh::discovery::static_provider::StaticProvider;
use iroh::{EndpointAddr, RelayConfig, RelayMap, RelayMode, RelayUrl};
use log::{info, warn};
use std::time::Duration;

/// Apply discovery mechanisms to an endpoint builder.
///
/// Iroh combines multiple discovery services using `ConcurrentDiscovery` internally.
/// Returns the updated builder and a list of enabled provider names (for logging/metrics).
pub fn attach_discovery(
    mut builder: iroh::endpoint::Builder,
    static_addrs: Vec<EndpointAddr>,
    discovery_config: &IrohDiscoveryConfig,
) -> Result<(iroh::endpoint::Builder, Vec<&'static str>), ThresholdError> {
    let mut providers: Vec<&'static str> = Vec::new();

    if !static_addrs.is_empty() {
        info!("discovery: enabling static provider bootstrap_addrs={}", static_addrs.len());
        let static_provider = StaticProvider::new();
        for addr in static_addrs {
            static_provider.add_endpoint_info(addr);
        }
        builder = builder.discovery(static_provider);
        providers.push("static");
    } else {
        warn!("discovery: no static bootstrap_addrs configured");
    }

    if discovery_config.enable_pkarr {
        info!("discovery: enabling pkarr provider");
        let pkarr = PkarrPublisher::n0_dns().republish_interval(Duration::from_secs(PKARR_REPUBLISH_INTERVAL_SECS));
        builder = builder.discovery(pkarr);
        providers.push("pkarr");
    }

    if discovery_config.enable_dns {
        let domain = discovery_config
            .dns_domain
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .ok_or_else(|| ThresholdError::InvalidDnsDomain { domain: "<missing>".to_string() })?;
        info!("discovery: enabling DNS provider domain={}", domain);
        let dns = DnsDiscovery::builder(domain.to_string());
        builder = builder.discovery(dns);
        providers.push("dns");
    }

    if providers.is_empty() {
        warn!("discovery: no discovery providers configured");
    } else {
        info!("discovery: configured providers={}", providers.join(","));
    }

    Ok((builder, providers))
}

/// Parse relay mode from config.
pub fn parse_relay_mode(relay_config: &IrohRelayConfig) -> Result<RelayMode, ThresholdError> {
    if !relay_config.enable {
        return Ok(RelayMode::Disabled);
    }

    let custom = relay_config.custom_url.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let Some(custom_url) = custom else {
        return Ok(RelayMode::Default);
    };

    if custom_url.len() > MAX_RELAY_URL_LENGTH {
        return Err(ThresholdError::InvalidRelayConfig {
            reason: format!("custom_url too long: {} > {}", custom_url.len(), MAX_RELAY_URL_LENGTH),
        });
    }

    let relay_url: RelayUrl = custom_url.parse().map_err(|_err| ThresholdError::MalformedRelayUrl { url: custom_url.to_string() })?;

    // Minimal relay configuration: single relay URL, QUIC config omitted (HTTP-only is still usable).
    let relay_config = RelayConfig { url: relay_url, quic: None };
    let relay_map = RelayMap::from_iter([relay_config]);
    Ok(RelayMode::Custom(relay_map))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_mode_disabled() {
        let cfg = IrohRelayConfig { enable: false, custom_url: None };
        let mode = parse_relay_mode(&cfg).expect("should parse");
        assert!(matches!(mode, RelayMode::Disabled));
    }

    #[test]
    fn relay_mode_default() {
        let cfg = IrohRelayConfig { enable: true, custom_url: None };
        let mode = parse_relay_mode(&cfg).expect("should parse");
        assert!(matches!(mode, RelayMode::Default));
    }

    #[test]
    fn relay_mode_custom_valid() {
        let cfg = IrohRelayConfig { enable: true, custom_url: Some("https://relay.example.com".to_string()) };
        let mode = parse_relay_mode(&cfg).expect("should parse");
        assert!(matches!(mode, RelayMode::Custom(_)));
    }

    #[test]
    fn relay_mode_custom_invalid_url() {
        let cfg = IrohRelayConfig { enable: true, custom_url: Some("not a url".to_string()) };
        let err = parse_relay_mode(&cfg).expect_err("should fail");
        assert!(matches!(err, ThresholdError::MalformedRelayUrl { .. }));
    }

    #[test]
    fn discovery_empty_providers_returns_empty_list() {
        let cfg = IrohDiscoveryConfig::default();
        let builder = iroh::Endpoint::empty_builder(RelayMode::Disabled);
        let (_builder, providers) = attach_discovery(builder, vec![], &cfg).expect("should succeed");
        assert!(providers.is_empty());
    }

    #[test]
    fn discovery_pkarr_only_configures_provider() {
        let cfg = IrohDiscoveryConfig { enable_pkarr: true, enable_dns: false, dns_domain: None };
        let builder = iroh::Endpoint::empty_builder(RelayMode::Disabled);
        let (_builder, providers) = attach_discovery(builder, vec![], &cfg).expect("should succeed");
        assert_eq!(providers, vec!["pkarr"]);
    }
}
