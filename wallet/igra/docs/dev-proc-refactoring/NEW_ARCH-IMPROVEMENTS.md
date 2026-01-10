# Architecture Improvements - Optional Enhancements

**Status**: Optional / Low Priority
**Prerequisite**: Core refactoring complete (see `REFACTOR-COMPLETE.md`)

---

## 1. Split Large Handler Files

### 1.1 Split `api/handlers/rpc.rs` (578 lines)

**Current**: Single file handles all JSON-RPC methods.

**Proposed**:
```
igra-service/src/api/handlers/
├── mod.rs
├── health.rs                  # (existing)
├── signing_event.rs           # NEW: signing_event.submit
├── hyperlane.rs               # NEW: hyperlane.* methods
└── types.rs                   # NEW: shared request/response types
```

**Extract to `signing_event.rs`**:
- `handle_signing_event_submit()`
- Lines ~367-402

**Extract to `hyperlane.rs`**:
- `handle_validators_and_threshold()`
- `handle_mailbox_process()`
- `extract_signing_payload()`
- `submit_signing_from_hyperlane()`
- `derive_session_id_hex()`
- All Hyperlane type definitions
- Lines ~50-357, ~404-567

**Extract to `types.rs`**:
- `JsonRpcRequest`, `JsonRpcResponse`, `JsonRpcError`, `JsonRpcErrorBody`
- Lines ~22-48

---

### 1.2 Split `service/coordination.rs` (474 lines)

**Current**: Single file handles coordination loop, ack collection, finalization.

**Proposed**:
```
igra-service/src/service/coordinator/
├── mod.rs                     # Re-exports
├── loop.rs                    # Main subscription loop
├── session.rs                 # Session state management
└── finalization.rs            # collect_and_finalize logic
```

**Extract to `loop.rs`**:
- `run_coordination_loop()`
- Subscription handling
- Message dispatch

**Extract to `session.rs`**:
- `active_sessions` HashSet management
- Session deduplication
- Timeout tracking

**Extract to `finalization.rs`**:
- `collect_and_finalize()`
- Signature aggregation
- Transaction submission

---

## 2. Configuration Externalization

### 2.1 Rate Limit Configuration

**Current** (`middleware/rate_limit.rs:8-9`):
```rust
const DEFAULT_RPS: u32 = 30;
const DEFAULT_BURST: u32 = 60;
```

**Proposed**: Add to `RpcConfig`:
```rust
pub struct RpcConfig {
    pub addr: String,
    pub token: Option<String>,
    pub enabled: bool,
    pub rate_limit_rps: Option<u32>,      // NEW
    pub rate_limit_burst: Option<u32>,    // NEW
}
```

---

### 2.2 Session Expiry Configuration

**Current** (`handlers/rpc.rs:352`):
```rust
expires_at_nanos: audit::now_nanos().saturating_add(10 * 60 * 1_000_000_000),
```

**Proposed**: Add to `RuntimeConfig`:
```rust
pub struct RuntimeConfig {
    pub session_timeout_seconds: u64,
    pub session_expiry_seconds: Option<u64>,  // NEW (default 600)
}
```

---

## 3. Additional Middleware

### 3.1 Request Correlation IDs

**Purpose**: Track requests across logs for debugging.

**Implementation**:
```rust
// middleware/correlation.rs
pub async fn correlation_middleware(req: Request<Body>, next: Next) -> Response {
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Add to request extensions
    req.extensions_mut().insert(RequestId(request_id.clone()));

    let mut response = next.run(req).await;
    response.headers_mut().insert("x-request-id", request_id.parse().unwrap());
    response
}
```

---

### 3.2 Request Logging Middleware

**Purpose**: Structured logging for all requests.

**Implementation**:
```rust
// middleware/logging.rs
pub async fn logging_middleware(req: Request<Body>, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let start = Instant::now();

    let response = next.run(req).await;

    let duration = start.elapsed();
    let status = response.status();

    tracing::info!(
        target: "http",
        method = %method,
        uri = %uri,
        status = %status.as_u16(),
        duration_ms = %duration.as_millis(),
    );

    response
}
```

---

## 4. Handler Improvements

### 4.1 Structured Error Responses

**Current**: Errors return string messages.

**Proposed**: Add error codes enum:
```rust
pub enum RpcErrorCode {
    ParseError = -32700,
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    InvalidParams = -32602,
    InternalError = -32603,
    // Application errors
    Unauthorized = -32001,
    MissingGroupId = -32002,
    HyperlaneNotConfigured = -32003,
    UnknownDomain = -32004,
    SigningFailed = -32005,
    EventReplayed = -32006,
    PolicyViolation = -32007,
}
```

---

### 4.2 Batch RPC Support

**Current**: Single request per HTTP call.

**Proposed**: Support JSON-RPC batch format:
```rust
// Accept either single request or array of requests
pub async fn handle_rpc(
    State(state): State<Arc<RpcState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    // Try parse as array first, then single
    if let Ok(batch) = serde_json::from_str::<Vec<JsonRpcRequest>>(&body) {
        handle_batch(state, headers, batch).await
    } else if let Ok(single) = serde_json::from_str::<JsonRpcRequest>(&body) {
        handle_single(state, headers, single).await
    } else {
        // Parse error
    }
}
```

---

## 5. Testing Infrastructure

### 5.1 API Integration Tests

**Location**: `igra-service/tests/api/`

```
tests/api/
├── mod.rs
├── auth_test.rs           # Token validation tests
├── rate_limit_test.rs     # Rate limiting behavior
├── signing_event_test.rs  # signing_event.submit tests
└── hyperlane_test.rs      # Hyperlane RPC tests
```

---

### 5.2 Handler Unit Tests

**Add to each handler file**:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_signing_event_submit_valid() { ... }

    #[tokio::test]
    async fn test_signing_event_submit_missing_params() { ... }
}
```

---

## Priority Matrix

| Improvement | Impact | Effort | Priority |
|-------------|--------|--------|----------|
| Split rpc.rs | Medium | Low | P3 |
| Split coordination.rs | Medium | Low | P3 |
| Rate limit config | Low | Low | P4 |
| Session expiry config | Low | Low | P4 |
| Correlation IDs | Medium | Low | P3 |
| Request logging | Medium | Low | P3 |
| Error codes enum | Low | Low | P4 |
| Batch RPC support | Low | Medium | P4 |
| API integration tests | High | Medium | P2 |
| Handler unit tests | Medium | Medium | P3 |

**Legend**:
- P2: Should do soon
- P3: Nice to have
- P4: Can defer indefinitely

---

## Implementation Order (If Pursued)

1. **API integration tests** (P2) - Ensures stability before other changes
2. **Split rpc.rs** (P3) - Largest single file
3. **Correlation IDs + logging** (P3) - Improves observability
4. **Split coordination.rs** (P3) - Second largest file
5. **Handler unit tests** (P3) - Confidence in handlers
6. **Config externalization** (P4) - When needed
7. **Error codes / batch RPC** (P4) - Polish

---

**End of Document**
