use super::super::report::{ErrorCategory, ValidationReport};
use super::super::{NetworkMode, ValidationContext};
use crate::infrastructure::config::AppConfig;

fn parse_rpc_host(url: &str) -> Option<&str> {
    let url = url.trim();
    let scheme_end = url.find("://")?;
    let rest = &url[scheme_end + 3..];
    let rest = rest.split('/').next().unwrap_or(rest);
    let hostport = rest.split('@').last().unwrap_or(rest);
    Some(hostport.split(':').next().unwrap_or(hostport))
}

fn parse_rpc_scheme(url: &str) -> Option<&str> {
    url.trim().split("://").next()
}

fn is_local_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1" || host.starts_with("127.")
}

fn has_userinfo(url: &str) -> bool {
    let url = url.trim();
    let Some(scheme_end) = url.find("://") else {
        return false;
    };
    let rest = &url[scheme_end + 3..];
    let authority = rest.split('/').next().unwrap_or(rest);
    authority.contains('@')
}

pub fn validate_rpc_endpoints(app_config: &AppConfig, mode: NetworkMode, ctx: &ValidationContext, report: &mut ValidationReport) {
    let url = app_config.service.node_rpc_url.trim();
    if url.is_empty() {
        report.add_error(ErrorCategory::RpcEndpoint, "missing service.node_rpc_url");
        return;
    }

    let Some(host) = parse_rpc_host(url) else {
        report.add_error(ErrorCategory::RpcEndpoint, format!("invalid service.node_rpc_url (cannot parse host): {url}"));
        return;
    };
    let scheme = parse_rpc_scheme(url).unwrap_or("");

    let is_local = is_local_host(host);
    if mode == NetworkMode::Mainnet && !is_local {
        if !ctx.allow_remote_rpc {
            report.add_error(
                ErrorCategory::RpcEndpoint,
                format!(
                    "mainnet requires local RPC by default; got remote endpoint '{url}'. Use `--allow-remote-rpc` to explicitly opt-in."
                ),
            );
            return;
        }

        if scheme != "grpcs" && scheme != "https" {
            report
                .add_error(ErrorCategory::RpcEndpoint, format!("mainnet remote RPC must use TLS (grpcs:// or https://). Got: {url}"));
        }

        if !has_userinfo(url) {
            report.add_error(
                ErrorCategory::RpcEndpoint,
                format!(
                    "mainnet remote RPC must include authentication (userinfo before '@'): got '{url}'. Example: grpcs://token@host:port"
                ),
            );
        }

        report.add_warning(
            ErrorCategory::RpcEndpoint,
            format!("SECURITY WARNING: using remote RPC endpoint in mainnet host={host} url={url}"),
        );
    }

    if mode == NetworkMode::Testnet && !is_local {
        if scheme != "grpcs" && scheme != "https" {
            report.add_warning(ErrorCategory::RpcEndpoint, format!("testnet using insecure remote RPC (consider grpcs://): {url}"));
        }
    }
}
