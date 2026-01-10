use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use subtle::ConstantTimeEq;
use tracing::{debug, info, warn};

pub fn authorize_rpc(headers: &HeaderMap, expected: Option<&str>) -> Result<(), String> {
    let expected = match expected {
        Some(value) if !value.trim().is_empty() => value.trim(),
        _ => {
            info!("rpc auth disabled (no token configured)");
            return Ok(());
        }
    };

    info!("rpc auth enabled");
    if let Some(value) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        if constant_time_eq(value, expected) {
            debug!("rpc auth succeeded via x-api-key");
            return Ok(());
        }
    }
    if let Some(value) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(token) = value.strip_prefix("Bearer ") {
            if constant_time_eq(token, expected) {
                debug!("rpc auth succeeded via bearer token");
                return Ok(());
            }
        }
    }
    warn!("rpc auth failed");
    Err("unauthorized".to_string())
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}
