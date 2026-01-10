use super::correlation::CorrelationId;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;
use tracing::debug;

fn sanitize_headers(headers: &axum::http::HeaderMap) -> Vec<(String, String)> {
    const REDACT: &[&str] = &["authorization", "x-api-key", "cookie"];
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
                        if out.len() > 128 {
                            out.truncate(128);
                            out.push_str("…");
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
        correlation_id = correlation_id.as_deref().unwrap_or(""),
        client_ip = %client_ip,
        method = %method,
        uri = %uri,
        request_headers = ?request_headers,
        request_body_size,
        "request headers"
    );

    tracing::info!(
        target: "http",
        correlation_id = correlation_id.as_deref().unwrap_or(""),
        client_ip = %client_ip,
        method = %method,
        uri = %uri,
        status = status.as_u16(),
        duration_ms = duration.as_millis(),
        request_body_size,
        response_body_size,
        "request"
    );

    debug!(
        target: "http",
        correlation_id = correlation_id.as_deref().unwrap_or(""),
        status = status.as_u16(),
        response_headers = ?response_headers,
        response_body_size,
        "response headers"
    );

    response
}
