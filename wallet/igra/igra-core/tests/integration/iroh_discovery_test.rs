use igra_core::infrastructure::config::validation::{validate_iroh_discovery, validate_iroh_relay};
use igra_core::infrastructure::config::{IrohDiscoveryConfig, IrohRelayConfig};
use igra_core::infrastructure::transport::iroh::discovery;
use iroh::RelayMode;

#[test]
fn validate_discovery_requires_domain_for_dns() {
    let cfg = IrohDiscoveryConfig { enable_pkarr: false, enable_dns: true, dns_domain: None };
    let err = validate_iroh_discovery(&cfg).expect_err("should fail");
    assert!(err.contains("dns_domain"));

    let cfg = IrohDiscoveryConfig { enable_pkarr: false, enable_dns: true, dns_domain: Some("discovery.example.com".to_string()) };
    validate_iroh_discovery(&cfg).expect("should validate");
}

#[test]
fn validate_relay_rejects_invalid_url() {
    let cfg = IrohRelayConfig { enable: true, custom_url: Some("ftp://relay.example.com".to_string()) };
    let err = validate_iroh_relay(&cfg).expect_err("should fail");
    assert!(err.contains("http://") || err.contains("https://"));

    let cfg = IrohRelayConfig { enable: true, custom_url: Some("https://relay.example.com".to_string()) };
    validate_iroh_relay(&cfg).expect("should validate");
}

#[test]
fn relay_mode_parsing_matches_config() {
    let cfg = IrohRelayConfig { enable: false, custom_url: None };
    let mode = discovery::parse_relay_mode(&cfg).expect("should parse");
    assert!(matches!(mode, RelayMode::Disabled));

    let cfg = IrohRelayConfig { enable: true, custom_url: None };
    let mode = discovery::parse_relay_mode(&cfg).expect("should parse");
    assert!(matches!(mode, RelayMode::Default));
}

#[tokio::test]
async fn test_endpoint_with_pkarr_builder_constructs() {
    if std::env::var("CI").is_ok() {
        return;
    }

    let discovery_config = IrohDiscoveryConfig { enable_pkarr: true, enable_dns: false, dns_domain: None };
    let relay_config = IrohRelayConfig { enable: false, custom_url: None };

    let relay_mode = discovery::parse_relay_mode(&relay_config).expect("should parse relay");
    assert!(matches!(relay_mode, RelayMode::Disabled));

    let builder = iroh::Endpoint::empty_builder(relay_mode);
    let (_builder, providers) = discovery::attach_discovery(builder, vec![], &discovery_config).expect("should attach discovery");
    assert!(providers.contains(&"pkarr"));
}
