use axum::body::Body;
use axum::http::HeaderValue;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use tracing::debug;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct CorrelationId(pub String);

pub async fn correlation_middleware(mut req: Request<Body>, next: Next) -> Response {
    let header = req.headers().get("x-request-id").and_then(|v| v.to_str().ok());
    let request_id = header.map(|s| s.to_string()).unwrap_or_else(|| Uuid::new_v4().to_string());
    debug!(
        has_x_request_id = header.is_some(),
        x_request_id_len = header.map(|s| s.len()).unwrap_or(0),
        correlation_id_len = request_id.len(),
        "correlation id assigned"
    );

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        req.headers_mut().insert("x-request-id", value);
    }
    req.extensions_mut().insert(CorrelationId(request_id.clone()));

    let mut response = next.run(req).await;
    if let Ok(value) = request_id.parse() {
        response.headers_mut().insert("x-request-id", value);
    } else {
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    }
    response
}
