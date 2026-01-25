use super::correlation::CorrelationId;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use log::{debug, error, trace, warn};
use std::time::Instant;

fn sanitize_headers(headers: &axum::http::HeaderMap) -> Vec<(String, String)> {
    const REDACT: &[&str] = &["authorization", "x-api-key", "cookie"];
    const MAX_HEADER_VALUE_LEN: usize = 128;
    headers
        .iter()
        .map(|(name, value)| {
            let key = name.as_str().to_string();
            let val = if REDACT.contains(&name.as_str()) {
                "<redacted>".to_string()
            } else {
                value
                    .to_str()
                    .map(|s| {
                        let mut out = s.to_string();
                        if out.len() > MAX_HEADER_VALUE_LEN {
                            out.truncate(MAX_HEADER_VALUE_LEN);
                            out.push('…');
                        }
                        out
                    })
                    .unwrap_or_else(|_| "<non-utf8>".to_string())
            };
            (key, val)
        })
        .collect()
}

pub async fn logging_middleware(req: Request<Body>, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let client_ip =
        req.extensions().get::<ConnectInfo<std::net::SocketAddr>>().map(|ConnectInfo(addr)| addr.ip().to_string()).unwrap_or_default();
    let correlation_id = req.extensions().get::<CorrelationId>().map(|id| id.0.clone());
    let request_headers = sanitize_headers(req.headers());
    let request_body_size = req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let start = Instant::now();

    let response = next.run(req).await;

    let duration = start.elapsed();
    let status = response.status();
    let response_headers = sanitize_headers(response.headers());
    let response_body_size = response
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    debug!(
        target: "http",
        "request headers correlation_id={} client_ip={} method={} uri={} request_headers={:?} request_body_size={}",
        correlation_id.as_deref().unwrap_or(""),
        client_ip,
        method,
        uri,
        request_headers,
        request_body_size
    );

    let is_health_like =
        matches!(path.as_str(), "/health" | "/ready" | "/metrics") || (path == "/rpc" && method.as_str().eq_ignore_ascii_case("GET"));

    if is_health_like {
        trace!(
            target: "http",
            "health check correlation_id={} client_ip={} method={} path={} status={} duration_ms={}",
            correlation_id.as_deref().unwrap_or(""),
            client_ip,
            method,
            path,
            status.as_u16(),
            duration.as_millis()
        );
    } else if status.is_server_error() {
        error!(
            target: "http",
            "request failed correlation_id={} client_ip={} method={} path={} status={} duration_ms={} request_body_size={} response_body_size={}",
            correlation_id.as_deref().unwrap_or(""),
            client_ip,
            method,
            path,
            status.as_u16(),
            duration.as_millis(),
            request_body_size,
            response_body_size
        );
    } else if status.is_client_error() {
        warn!(
            target: "http",
            "request rejected correlation_id={} client_ip={} method={} path={} status={} duration_ms={} request_body_size={} response_body_size={}",
            correlation_id.as_deref().unwrap_or(""),
            client_ip,
            method,
            path,
            status.as_u16(),
            duration.as_millis(),
            request_body_size,
            response_body_size
        );
    } else {
        debug!(
            target: "http",
            "request correlation_id={} client_ip={} method={} path={} status={} duration_ms={}",
            correlation_id.as_deref().unwrap_or(""),
            client_ip,
            method,
            path,
            status.as_u16(),
            duration.as_millis()
        );
    }

    debug!(
        target: "http",
        "response headers correlation_id={} status={} response_headers={:?} response_body_size={}",
        correlation_id.as_deref().unwrap_or(""),
        status.as_u16(),
        response_headers,
        response_body_size
    );

    response
}
