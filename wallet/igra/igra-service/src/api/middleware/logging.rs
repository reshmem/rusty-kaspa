use super::correlation::CorrelationId;
use axum::body::Body;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;

pub async fn logging_middleware(req: Request<Body>, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let correlation_id = req.extensions().get::<CorrelationId>().map(|id| id.0.clone());
    let start = Instant::now();

    let response = next.run(req).await;

    let duration = start.elapsed();
    let status = response.status();

    tracing::info!(
        target: "http",
        correlation_id = correlation_id.as_deref().unwrap_or(""),
        method = %method,
        uri = %uri,
        status = status.as_u16(),
        duration_ms = duration.as_millis(),
        "request"
    );

    response
}

