# LOGS-HEAVEN: File-by-File Logging Implementation Guide

> **Goal:** Transform logs from cryptic noise to operational story

This document provides specific, actionable logging improvements for every relevant file in the codebase.

---

## Table of Contents

1. [Quick Reference](#quick-reference)
2. [Service Layer (igra-service)](#service-layer-igra-service)
3. [Application Layer (igra-core/application)](#application-layer-igra-coreapplication)
4. [Domain Layer (igra-core/domain)](#domain-layer-igra-coredomain)
5. [Infrastructure Layer (igra-core/infrastructure)](#infrastructure-layer-igra-coreinfrastructure)
6. [Implementation Priority](#implementation-priority)

---

## Quick Reference

### Log Level Guidelines

| Level | Use | Example |
|-------|-----|---------|
| `error!` | Operation failed, cannot recover | RPC connection lost permanently |
| `warn!` | Unexpected but recoverable | Proposal rejected, timeout |
| `info!` | Business events, state transitions | Session started, tx finalized |
| `debug!` | Operational details | Hash computed, storage write |
| `trace!` | Wire-level, per-iteration | Each signature byte, loop tick |

### Required Context Fields

Every log should include relevant IDs via spans or fields:

```rust
#[tracing::instrument(
    skip(storage, transport),
    fields(
        session_id = %hex::encode(session_id.as_hash())[..16],
        request_id = %request_id,
    )
)]
```

### Log Message Patterns

```rust
// Entry point
info!(param1 = %val1, param2 = %val2, "starting operation_name");

// Decision branch
info!(decision = "accept", reason = %reason, "proposal validation complete");

// Exit point
info!(result = "success", duration_ms = elapsed.as_millis(), "operation_name complete");

// Error
warn!(error = %err, context = %ctx, "operation_name failed");
```

---

## Service Layer (igra-service)

### 1. `src/api/router.rs`

**Current state:** Minimal logging at bind time
**Lines:** 16-24

**Add startup completion log:**

```rust
// Line 23, after axum::serve()
pub async fn run_json_rpc_server(addr: SocketAddr, state: Arc<RpcState>) -> Result<(), ThresholdError> {
    info!(addr = %addr, "starting HTTP server");  // EXISTING
    let app = build_router(state);
    let listener = TcpListener::bind(addr).await?;
    info!(addr = %addr, "HTTP server ready and accepting connections");  // ADD
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|err| {
            error!(addr = %addr, error = %err, "HTTP server terminated unexpectedly");  // ADD
            ThresholdError::Message(err.to_string())
        })
}
```

---

### 2. `src/api/middleware/logging.rs`

**Current state:** Logs all requests at INFO level
**Lines:** 74-85
**Problem:** Health checks spam logs every second

**Fix - filter health checks:**

```rust
// Replace lines 74-85 with:
let should_log_info = match (uri.path(), method.as_str()) {
    ("/health", "GET") | ("/ready", "GET") => false,
    ("/metrics", "GET") => false,
    _ => true,
};

if should_log_info {
    tracing::info!(
        target: "http",
        correlation_id = correlation_id.as_deref().unwrap_or(""),
        client_ip = %client_ip,
        method = %method,
        uri = %uri,
        status = status.as_u16(),
        duration_ms = duration.as_millis(),
        "request"
    );
} else {
    tracing::trace!(
        target: "http",
        uri = %uri,
        status = status.as_u16(),
        "health check"
    );
}
```

---

### 3. `src/api/handlers/health.rs`

**Current state:** No logging
**Expected file location:** `src/api/handlers/health.rs`

**Add health check context:**

```rust
pub async fn handle_health() -> impl IntoResponse {
    trace!("health check: ok");
    Json(json!({"status": "ok"}))
}

pub async fn handle_ready(State(state): State<Arc<RpcState>>) -> impl IntoResponse {
    // Check actual readiness
    let storage_ok = state.storage.is_ready();
    let transport_ok = state.transport.is_connected();

    if storage_ok && transport_ok {
        trace!(storage = storage_ok, transport = transport_ok, "ready check: ok");
        (StatusCode::OK, Json(json!({"status": "ready"})))
    } else {
        debug!(storage = storage_ok, transport = transport_ok, "ready check: not ready");
        (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"status": "not_ready"})))
    }
}
```

---

### 4. `src/api/handlers/rpc.rs`

**Current state:** Unknown
**Expected location:** `src/api/handlers/rpc.rs`

**Add RPC method logging:**

```rust
pub async fn handle_rpc(
    State(state): State<Arc<RpcState>>,
    Json(request): Json<RpcRequest>,
) -> impl IntoResponse {
    let method = &request.method;
    let request_id = request.id.clone();

    info!(
        method = %method,
        rpc_id = ?request_id,
        "RPC request received"
    );

    let start = Instant::now();
    let result = dispatch_rpc_method(&state, &request).await;
    let duration = start.elapsed();

    match &result {
        Ok(_) => {
            info!(
                method = %method,
                rpc_id = ?request_id,
                duration_ms = duration.as_millis(),
                "RPC request succeeded"
            );
        }
        Err(err) => {
            warn!(
                method = %method,
                rpc_id = ?request_id,
                error = %err,
                duration_ms = duration.as_millis(),
                "RPC request failed"
            );
        }
    }

    result
}
```

---

### 5. `src/service/coordination/loop.rs`

**Current state:** Good logging, but missing idle indicator
**Lines:** 53-60

**Add idle status instead of cryptic timeout:**

```rust
// Replace the timeout handling (currently just warns "iroh gossip receive timeout")
// Add this periodic idle indicator:

let mut last_activity = Instant::now();
const IDLE_LOG_INTERVAL: Duration = Duration::from_secs(60);

while let Some(item) = subscription.next().await {
    // Log idle status periodically
    if last_activity.elapsed() > IDLE_LOG_INTERVAL {
        info!(
            idle_seconds = last_activity.elapsed().as_secs(),
            group_id = %hex::encode(&group_id[..8]),
            peer_id = %local_peer_id,
            "service idle, waiting for signing proposals"
        );
    }

    let envelope = match item {
        Ok(envelope) => {
            last_activity = Instant::now();  // Reset on activity
            envelope
        }
        Err(err) => {
            // Don't log timeout as warning - it's normal
            if err.to_string().contains("timeout") {
                trace!(elapsed = %last_activity.elapsed().as_secs(), "gossip receive timeout (normal)");
            } else {
                warn!(error = %err, "proposal stream error");
            }
            continue;
        }
    };
    // ... rest of loop
}
```

**Add session lifecycle summary at line 253:**

```rust
// After the finalization task completes, add summary
tokio::spawn(async move {
    let session_start = Instant::now();
    let result = std::panic::AssertUnwindSafe(collect_and_finalize(...)).catch_unwind().await;

    clear_session_active(&active, session_id).await;

    let duration = session_start.elapsed();
    match result {
        Ok(Ok(())) => {
            info!(
                session_id = %session_id_hex,
                request_id = %request_id,
                duration_ms = duration.as_millis(),
                outcome = "SUCCESS",
                "=== SESSION COMPLETE ==="
            );
        }
        Ok(Err(err)) => {
            warn!(
                session_id = %session_id_hex,
                request_id = %request_id,
                duration_ms = duration.as_millis(),
                error = %err,
                outcome = "FAILED",
                "=== SESSION COMPLETE ==="
            );
        }
        Err(panic) => {
            error!(
                session_id = %session_id_hex,
                request_id = %request_id,
                panic = ?panic,
                outcome = "PANIC",
                "=== SESSION COMPLETE ==="
            );
        }
    }
});
```

---

### 6. `src/service/coordination/finalization.rs`

**Current state:** Good logging, missing progress percentage
**Lines:** 139-145

**Add progress percentage:**

```rust
// Line 139-145: When logging partial signatures updated
let partials = storage.list_partial_sigs(&request_id)?;
if partials.len() != last_partial_len {
    let progress_pct = (partials.len() * 100) / required;
    info!(
        session_id = %hex::encode(session_id.as_hash()),
        request_id = %request_id,
        collected = partials.len(),
        required = required,
        progress_pct = progress_pct,
        remaining = required.saturating_sub(partials.len()),
        "signature collection progress"
    );
    last_partial_len = partials.len();
}
```

**Add finalization summary at line 218-229:**

```rust
// Enhance the finalization success log
info!(
    session_id = %hex::encode(session_id.as_hash()),
    request_id = %request_id,
    tx_id = %tx_id,
    signatures = partials.len(),
    required = required,
    recipient = %signing_event.destination_address,
    amount_kas = signing_event.amount_sompi as f64 / 100_000_000.0,
    "transaction finalized and submitted"
);
```

---

### 7. `src/service/flow.rs`

**Current state:** Unknown

**Add flow transition logging:**

```rust
impl ServiceFlow {
    pub async fn finalize_and_submit(
        &self,
        request_id: &RequestId,
        pskt: Pskt,
        required: usize,
        pubkeys: &[PublicKey],
        params: &Params,
    ) -> Result<kaspa_hashes::Hash, ThresholdError> {
        info!(
            request_id = %request_id,
            input_count = pskt.inputs.len(),
            output_count = pskt.outputs.len(),
            required_sigs = required,
            "finalizing PSKT"
        );

        let finalized = finalize_pskt(&pskt, pubkeys)?;
        debug!(request_id = %request_id, "PSKT finalized, extracting transaction");

        let tx = extract_transaction(&finalized, params)?;
        let tx_id = tx.id();
        debug!(request_id = %request_id, tx_id = %tx_id, "transaction extracted");

        info!(
            request_id = %request_id,
            tx_id = %tx_id,
            "submitting transaction to network"
        );

        self.rpc().submit_transaction(&tx).await?;

        info!(
            request_id = %request_id,
            tx_id = %tx_id,
            "transaction accepted by network"
        );

        Ok(tx_id)
    }
}
```

---

### 8. `src/service/metrics.rs`

**Add metric registration logging:**

```rust
impl Metrics {
    pub fn new() -> Self {
        debug!("initializing prometheus metrics");
        let metrics = Self {
            sessions_received: Counter::new("igra_sessions_received_total", "...").unwrap(),
            sessions_finalized: Counter::new("igra_sessions_finalized_total", "...").unwrap(),
            // ...
        };
        debug!(
            metric_count = 10,  // count of metrics
            "prometheus metrics registered"
        );
        metrics
    }
}
```

---

### 9. `src/bin/kaspa-threshold-service/setup.rs`

**Current state:** Has logging, missing startup banner
**Lines:** 20-35

**Add startup banner after logging init:**

```rust
pub fn log_startup_banner(config: &AppConfig, peer_id: &PeerId, group_id: &Hash32) {
    let network = match config.iroh.network_id {
        0 => "mainnet",
        1 => "testnet",
        2 => "devnet",
        _ => "unknown",
    };

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║           IGRA Threshold Signing Service                     ║");
    info!("╠══════════════════════════════════════════════════════════════╣");
    info!("║ Peer ID:     {:<45} ║", peer_id);
    info!("║ Group ID:    {:<45} ║", &hex::encode(group_id)[..16]);
    info!("║ Threshold:   {}/{} signers{:<36} ║",
        config.service.pskt.sig_op_count,
        config.group.as_ref().map(|g| g.threshold_n).unwrap_or(0),
        ""
    );
    info!("║ Network:     {:<45} ║", network);
    info!("║ RPC:         {:<45} ║", config.rpc.addr);
    info!("╚══════════════════════════════════════════════════════════════╝");
}
```

---

### 10. `src/api/hyperlane/watcher.rs`

**Add watcher lifecycle logging:**

```rust
pub async fn run_hyperlane_watcher(
    state: Arc<RpcState>,
    dir: PathBuf,
    poll_interval: Duration,
) -> Result<(), ThresholdError> {
    info!(
        watch_dir = %dir.display(),
        poll_interval_ms = poll_interval.as_millis(),
        "starting Hyperlane file watcher"
    );

    let mut processed_count = 0u64;
    let mut error_count = 0u64;

    loop {
        tokio::time::sleep(poll_interval).await;

        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(err) => {
                warn!(error = %err, dir = %dir.display(), "failed to read watch directory");
                continue;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.extension().map(|e| e == "json").unwrap_or(false) {
                continue;
            }

            debug!(file = %path.display(), "processing Hyperlane message file");

            match process_hyperlane_file(&state, &path).await {
                Ok(()) => {
                    processed_count += 1;
                    info!(
                        file = %path.file_name().unwrap_or_default().to_string_lossy(),
                        total_processed = processed_count,
                        "Hyperlane message processed"
                    );
                }
                Err(err) => {
                    error_count += 1;
                    warn!(
                        file = %path.display(),
                        error = %err,
                        total_errors = error_count,
                        "Hyperlane message processing failed"
                    );
                }
            }
        }
    }
}
```

---

## Application Layer (igra-core/application)

> **Overall Assessment:** Application layer has **excellent logging**. Most files use proper spans, log levels, and context fields.

### 11. `src/application/signer.rs`

**Current state:** ✅ Excellent logging with spans
**Lines:** 43-304

Uses `tracing::info_span!` with session_id, request_id, event_id. Logs all validation checks, policy decisions, storage operations.

**Minor improvements:**

```rust
// Line 262-263: Add more context to policy acceptance
info!(
    checks_passed = policy_result.checks_performed.len(),
    daily_volume_check = policy.max_daily_volume_sompi.is_some(),
    destination_check = !policy.allowed_destinations.is_empty(),
    "policy accepted proposal"
);

// Line 295: Enhance acceptance log
info!(
    accept = true,
    validation_checks_passed = 7,
    "proposal accepted - all validation checks passed"
);
```

---

### 12. `src/application/coordinator.rs`

**Current state:** ✅ Excellent logging with spans
**Lines:** 40-328

Uses `tracing::info_span!` for `propose_session`. Logs:
- Proposal storage with hashes
- UTXO selection results (selected_utxos, total_input, fee, change)
- PSKT construction (input_count, output_count, tx_template_hash)
- Transaction extraction (tx_id, mass, input/output counts)
- Submission with retry attempts
- Ack collection progress

**Already implemented well - no changes needed.**

---

### 13. `src/application/event_processor.rs`

**Current state:** ✅ Excellent logging
**Lines:** 38-132

Logs:
- Session/request ID decoding
- Signing event parsing with derivation/signature sources
- Event hash computation
- Message verification (pass/fail with validator counts)
- Audit events for signature validation
- Replay detection warnings
- Final dispatch confirmation

**Already implemented well - no changes needed.**

---

### 14. `src/application/monitoring.rs`

**Current state:** ✅ Good logging
**Lines:** 1-41

`TransactionMonitor` logs:
- Blue score checks with current/accepted/required values
- Confirmation threshold reached
- Sleep intervals at trace level

**Already implemented well - no changes needed.**

---

### 15. `src/application/lifecycle.rs`

**Current state:** ⚠️ Needs logging callbacks

The lifecycle observer trait provides hooks but the `NoopObserver` implementation does nothing. Add logging to track state transitions:

```rust
impl LifecycleObserver for DefaultLifecycleObserver {
    fn on_event_received(&self, event: &SigningEvent, event_hash: &Hash32) {
        debug!(
            event_id = %event.event_id,
            event_hash = %hex::encode(&event_hash[..8]),
            "lifecycle: event received"
        );
    }

    fn on_request_created(&self, request: &SigningRequest) {
        info!(
            request_id = %request.request_id,
            session_id = %hex::encode(request.session_id.as_hash())[..8],
            "lifecycle: request created (state=Pending)"
        );
    }

    fn on_threshold_met(&self, request_id: &RequestId, collected: usize, required: usize) {
        info!(
            request_id = %request_id,
            collected = collected,
            required = required,
            "lifecycle: signature threshold met (state=Approved)"
        );
    }

    fn on_finalized(&self, request_id: &RequestId, tx_id: &TransactionId) {
        info!(
            request_id = %request_id,
            tx_id = %tx_id,
            "lifecycle: transaction finalized (state=Finalized)"
        );
    }

    fn on_failed(&self, request_id: &RequestId, reason: &str) {
        warn!(
            request_id = %request_id,
            reason = %reason,
            "lifecycle: request failed"
        );
    }
}
```

---

## Domain Layer (igra-core/domain)

### 15. `src/domain/request/state_machine.rs`

**Add state transition logging:**

```rust
impl<S: RequestState> TypedSigningRequest<S> {
    fn transition_to<T: RequestState>(self, reason: &str) -> TypedSigningRequest<T> {
        info!(
            request_id = %self.inner.request_id,
            from_state = %std::any::type_name::<S>().split("::").last().unwrap_or("Unknown"),
            to_state = %std::any::type_name::<T>().split("::").last().unwrap_or("Unknown"),
            reason = %reason,
            "request state transition"
        );
        TypedSigningRequest {
            inner: self.inner,
            _state: std::marker::PhantomData,
        }
    }
}

// Example transitions with logging:
impl TypedSigningRequest<Pending> {
    pub fn approve(self, signatures: usize, required: usize) -> TypedSigningRequest<Approved> {
        self.transition_to(&format!("threshold_met: {}/{}", signatures, required))
    }

    pub fn reject(self, reason: &str) -> TypedSigningRequest<Rejected> {
        self.transition_to(&format!("rejected: {}", reason))
    }

    pub fn expire(self) -> TypedSigningRequest<Expired> {
        self.transition_to("session_timeout")
    }
}
```

---

### 16. `src/domain/pskt/builder.rs`

**Add PSKT construction logging:**

```rust
impl PsktBuilder {
    pub fn build(self) -> Result<Pskt, ThresholdError> {
        debug!(
            input_count = self.inputs.len(),
            output_count = self.outputs.len(),
            "building PSKT"
        );

        let total_input = self.inputs.iter().map(|i| i.amount).sum::<u64>();
        let total_output = self.outputs.iter().map(|o| o.amount).sum::<u64>();
        let fee = total_input.saturating_sub(total_output);

        debug!(
            total_input_sompi = total_input,
            total_output_sompi = total_output,
            fee_sompi = fee,
            "PSKT amounts calculated"
        );

        for (i, input) in self.inputs.iter().enumerate() {
            trace!(
                index = i,
                amount_sompi = input.amount,
                "PSKT input"
            );
        }

        for (i, output) in self.outputs.iter().enumerate() {
            trace!(
                index = i,
                address = %output.address,
                amount_sompi = output.amount,
                "PSKT output"
            );
        }

        let pskt = Pskt { inputs: self.inputs, outputs: self.outputs, ... };

        info!(
            input_count = pskt.inputs.len(),
            output_count = pskt.outputs.len(),
            fee_sompi = fee,
            "PSKT built successfully"
        );

        Ok(pskt)
    }
}
```

---

### 17. `src/domain/pskt/multisig.rs`

**Add signature aggregation logging:**

```rust
pub fn apply_partial_sigs(
    kpsbt_blob: &[u8],
    partials: &[PartialSigRecord],
) -> Result<Pskt, ThresholdError> {
    debug!(
        kpsbt_len = kpsbt_blob.len(),
        partial_sig_count = partials.len(),
        "applying partial signatures to PSKT"
    );

    let mut pskt = deserialize_pskt_signer(kpsbt_blob)?;

    let mut sigs_per_input: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();

    for sig in partials {
        trace!(
            input_index = sig.input_index,
            signer = %sig.signer_peer_id,
            sig_len = sig.signature.len(),
            "applying partial signature"
        );

        apply_single_sig(&mut pskt, sig)?;
        *sigs_per_input.entry(sig.input_index).or_default() += 1;
    }

    debug!(
        inputs_with_sigs = sigs_per_input.len(),
        total_sigs_applied = partials.len(),
        "partial signatures applied"
    );

    Ok(pskt)
}

pub fn finalize_multisig(
    pskt: &Pskt,
    required: usize,
    ordered_pubkeys: &[PublicKey],
) -> Result<Pskt, ThresholdError> {
    info!(
        input_count = pskt.inputs.len(),
        required_sigs = required,
        pubkey_count = ordered_pubkeys.len(),
        "finalizing multisig PSKT"
    );

    for (i, input) in pskt.inputs.iter().enumerate() {
        let sig_count = input.partial_sigs.len();
        if sig_count < required {
            warn!(
                input_index = i,
                signatures = sig_count,
                required = required,
                "insufficient signatures for input"
            );
            return Err(ThresholdError::InsufficientSignatures);
        }
        trace!(input_index = i, signatures = sig_count, "input has sufficient signatures");
    }

    let finalized = aggregate_signatures(pskt, required, ordered_pubkeys)?;

    info!(
        input_count = finalized.inputs.len(),
        "PSKT finalization complete"
    );

    Ok(finalized)
}
```

---

### 18. `src/domain/signing/threshold.rs`

**Add signing operation logging:**

```rust
impl SignerBackend for ThresholdSigner {
    fn sign(
        &self,
        kpsbt_blob: &[u8],
        request_id: &RequestId,
    ) -> Result<SigningResult, ThresholdError> {
        debug!(
            request_id = %request_id,
            kpsbt_len = kpsbt_blob.len(),
            "threshold signing operation started"
        );

        let pskt = deserialize_pskt(kpsbt_blob)?;
        let input_count = pskt.inputs.len();

        debug!(
            request_id = %request_id,
            input_count = input_count,
            "signing {} inputs",
            input_count
        );

        let mut signatures = Vec::with_capacity(input_count);

        for (i, input) in pskt.inputs.iter().enumerate() {
            trace!(
                request_id = %request_id,
                input_index = i,
                "signing input"
            );

            let sig = self.keypair.sign(&input.sighash)?;
            signatures.push(InputSignature {
                input_index: i,
                pubkey: self.keypair.public_key().to_bytes().to_vec(),
                signature: sig.to_bytes().to_vec(),
            });
        }

        info!(
            request_id = %request_id,
            input_count = input_count,
            signatures_produced = signatures.len(),
            signer_pubkey = %hex::encode(&self.keypair.public_key().to_bytes()[..8]),
            "threshold signing complete"
        );

        Ok(SigningResult {
            request_id: request_id.clone(),
            input_count,
            signatures_produced: signatures,
            signer_pubkey: self.keypair.public_key().to_bytes().to_vec(),
        })
    }
}
```

---

### 19. `src/domain/policy/enforcer.rs`

**Add policy check logging:**

```rust
impl PolicyEnforcer for DefaultPolicyEnforcer {
    fn evaluate_policy(
        &self,
        event: &SigningEvent,
        policy: &GroupPolicy,
        current_volume: u64,
    ) -> PolicyResult {
        debug!(
            event_id = %event.event_id,
            amount_sompi = event.amount_sompi,
            destination = %event.destination_address,
            current_daily_volume = current_volume,
            "evaluating policy"
        );

        let mut checks = Vec::new();

        // Destination check
        if !policy.allowed_destinations.is_empty() {
            let allowed = policy.allowed_destinations.contains(&event.destination_address);
            checks.push(PolicyCheck {
                check_type: PolicyCheckType::Destination,
                passed: allowed,
                details: format!(
                    "destination {} in allowed list: {}",
                    event.destination_address,
                    allowed
                ),
            });

            if !allowed {
                warn!(
                    event_id = %event.event_id,
                    destination = %event.destination_address,
                    allowed_count = policy.allowed_destinations.len(),
                    "policy check failed: destination not in allowed list"
                );
            }
        }

        // Amount checks
        if let Some(min) = policy.min_amount_sompi {
            let passed = event.amount_sompi >= min;
            checks.push(PolicyCheck {
                check_type: PolicyCheckType::MinAmount,
                passed,
                details: format!("amount {} >= min {}: {}", event.amount_sompi, min, passed),
            });

            if !passed {
                warn!(
                    event_id = %event.event_id,
                    amount = event.amount_sompi,
                    min_required = min,
                    "policy check failed: amount below minimum"
                );
            }
        }

        if let Some(max) = policy.max_amount_sompi {
            let passed = event.amount_sompi <= max;
            checks.push(PolicyCheck {
                check_type: PolicyCheckType::MaxAmount,
                passed,
                details: format!("amount {} <= max {}: {}", event.amount_sompi, max, passed),
            });

            if !passed {
                warn!(
                    event_id = %event.event_id,
                    amount = event.amount_sompi,
                    max_allowed = max,
                    "policy check failed: amount exceeds maximum"
                );
            }
        }

        // Daily volume check
        if let Some(max_daily) = policy.max_daily_volume_sompi {
            let new_volume = current_volume.saturating_add(event.amount_sompi);
            let passed = new_volume <= max_daily;
            checks.push(PolicyCheck {
                check_type: PolicyCheckType::DailyVolume,
                passed,
                details: format!(
                    "daily volume {} + {} = {} <= max {}: {}",
                    current_volume, event.amount_sompi, new_volume, max_daily, passed
                ),
            });

            if !passed {
                warn!(
                    event_id = %event.event_id,
                    current_volume = current_volume,
                    requested_amount = event.amount_sompi,
                    max_daily = max_daily,
                    "policy check failed: would exceed daily volume limit"
                );
            }
        }

        let failed_check = checks.iter().find(|c| !c.passed);
        let allowed = failed_check.is_none();

        if allowed {
            debug!(
                event_id = %event.event_id,
                checks_passed = checks.len(),
                "all policy checks passed"
            );
        }

        PolicyResult {
            allowed,
            checks_performed: checks,
            failed_check: failed_check.cloned(),
        }
    }
}
```

---

### 20. `src/domain/validation/verifier.rs`

**Add verification logging:**

```rust
impl MessageVerifier for CompositeVerifier {
    fn verify(&self, event: &SigningEvent) -> Result<VerificationReport, ThresholdError> {
        debug!(
            event_id = %event.event_id,
            source = ?event.event_source,
            signature_count = event.signatures.len(),
            "verifying message signatures"
        );

        let (validators, threshold) = match event.event_source {
            EventSource::Hyperlane => (&self.hyperlane_validators, self.hyperlane_threshold),
            EventSource::LayerZero => (&self.layerzero_validators, 1),
            _ => {
                debug!(event_id = %event.event_id, source = ?event.event_source, "no validators for source");
                return Ok(VerificationReport {
                    valid: true,
                    source: event.event_source,
                    validator_count: 0,
                    valid_signatures: 0,
                    threshold_required: 0,
                    failure_reason: None,
                });
            }
        };

        debug!(
            event_id = %event.event_id,
            validator_count = validators.len(),
            threshold = threshold,
            "checking against validator set"
        );

        let mut valid_count = 0;
        for (i, sig) in event.signatures.iter().enumerate() {
            let valid = verify_signature(validators, &event.message_hash, sig);
            if valid {
                valid_count += 1;
                trace!(
                    event_id = %event.event_id,
                    sig_index = i,
                    "signature valid"
                );
            } else {
                trace!(
                    event_id = %event.event_id,
                    sig_index = i,
                    "signature invalid or unknown validator"
                );
            }
        }

        let valid = valid_count >= threshold;

        if valid {
            info!(
                event_id = %event.event_id,
                valid_signatures = valid_count,
                threshold = threshold,
                "message verification passed"
            );
        } else {
            warn!(
                event_id = %event.event_id,
                valid_signatures = valid_count,
                threshold = threshold,
                "message verification failed: insufficient valid signatures"
            );
        }

        Ok(VerificationReport {
            valid,
            source: event.event_source,
            validator_count: validators.len(),
            valid_signatures: valid_count,
            threshold_required: threshold,
            failure_reason: if valid { None } else { Some("insufficient_signatures".to_string()) },
        })
    }
}
```

---

## Infrastructure Layer (igra-core/infrastructure)

> **Overall Assessment:** Infrastructure layer has **good to excellent logging**. Most files properly log operations, errors, and state changes.

---

### Transport Layer

#### 21. `src/infrastructure/transport/iroh/client.rs`

**Current state:** ✅ Excellent logging
**Lines:** 1-347

Logs:
- Transport creation with network_id, group_id, bootstrap_nodes
- All publish operations (proposal, ack, partial_sig, finalize) with session_id, request_id
- Retry attempts with topic and byte_len
- Group/session subscription with topic and peer count
- Bootstrap node validation warnings

**Already implemented well - no changes needed.**

---

#### 22. `src/infrastructure/transport/iroh/subscription.rs`

**Current state:** ⚠️ Has the problematic timeout warning
**Lines:** 1-82

**Issue:** Line 33 logs `warn!("iroh gossip receive timeout")` which is confusing in idle state.

**Fix:**
```rust
// Replace line 33-36 with:
Err(_) => {
    // This is normal when no messages are being sent - don't alarm operators
    trace!(timeout_secs = RECEIVE_TIMEOUT.as_secs(), "gossip receive timeout (normal idle)");
    continue;  // Don't yield error, just continue waiting
}
```

---

#### 23. `src/infrastructure/transport/iroh/filtering.rs`

**Current state:** ✅ Excellent logging
**Lines:** 1-244

Logs:
- Rate limit blocks with peer_id, session_id (+ audit event)
- Payload hash mismatches as warnings
- Invalid signatures as warnings
- New message acceptance
- Duplicate message detection
- All payload types recorded at trace level

**Already implemented well - no changes needed.**

---

#### 24. `src/infrastructure/transport/rate_limiter.rs`

**Current state:** ✅ Good logging
**Lines:** 1-156

Logs:
- New peer bucket creation
- Token consumption at trace level
- Cleanup operations with before/after counts

**Already implemented well - no changes needed.**

---

### Storage Layer

#### 25. `src/infrastructure/storage/rocks/engine.rs`

**Current state:** ✅ Excellent logging
**Lines:** 1-705

Logs:
- Database open/close operations
- Schema version checks and migrations
- All CRUD operations at debug/trace level
- Decision state transitions with old/new values
- Volume tracking
- Archive and cleanup operations
- Checkpoint creation

**Already implemented well - no changes needed.**

---

### RPC Layer

#### 26. `src/infrastructure/rpc/grpc.rs`

**Current state:** ✅ Excellent logging
**Lines:** 1-109

Logs:
- Connection with redacted URL
- All RPC calls with timing (elapsed_ms)
- UTXO fetches with address_count, utxo_count
- Transaction submission with mass, tx_id
- Blue score queries

**Already implemented well - no changes needed.**

---

#### 27. `src/infrastructure/rpc/circuit_breaker.rs`

**Current state:** ✅ Good logging
**Lines:** 1-66

Logs:
- Request denials when open
- Cooldown elapsed transitions
- Success resets
- Failure counts approaching threshold
- Circuit breaker opening with failures, threshold, cooldown_ms

**Already implemented well - no changes needed.**

---

#### 28. `src/infrastructure/rpc/retry/mod.rs`

**Current state:** ✅ Good logging
**Lines:** 1-36

Logs retry attempts with:
- attempt number
- remaining attempts
- delay_ms
- error message

**Already implemented well - no changes needed.**

---

### Config Layer

#### 29. `src/infrastructure/config/loader.rs`

**Current state:** ✅ Good logging
**Lines:** 1-424

Logs:
- Config loading with path and profile
- Missing file warnings
- URL redaction for sensitive values

**Minor improvement - add config summary:**
```rust
// At end of postprocess(), add:
debug!(
    node_rpc_url = %redact_url(&config.service.node_rpc_url),
    rpc_enabled = config.rpc.enabled,
    sig_op_count = config.service.pskt.sig_op_count,
    hd_configured = config.service.hd.is_some(),
    group_configured = config.group.is_some(),
    hyperlane_validators = config.hyperlane.validators.len(),
    "configuration loaded summary"
);
```

---

#### 30. `src/infrastructure/config/validation.rs`

**Current state:** ⚠️ No logging
**Lines:** 1-91

**Add validation logging:**
```rust
pub fn validate(&self) -> Result<(), Vec<String>> {
    debug!("validating configuration");
    let mut errors = Vec::new();
    // ... existing checks ...

    if errors.is_empty() {
        info!(checks_passed = 12, "configuration validation passed");
        Ok(())
    } else {
        for err in &errors {
            warn!(validation_error = %err, "configuration validation failed");
        }
        Err(errors)
    }
}
```

---

### Audit Layer

#### 31. `src/infrastructure/audit/mod.rs`

**Current state:** ⚠️ JSON-only, not human-readable
**Lines:** 1-117

**Add human-readable summaries:**

```rust
impl AuditLogger for StructuredAuditLogger {
    fn log(&self, event: AuditEvent) {
        // Machine-readable JSON
        let json = serde_json::to_string(&event).unwrap_or_else(|_| "{\"type\":\"serialize_failed\"}".to_string());
        info!(target: "audit_json", "{}", json);

        // Human-readable summary
        let summary = match &event {
            AuditEvent::EventReceived { event_hash, recipient, amount_sompi, .. } => {
                format!(
                    "AUDIT: Event received - {} KAS to {} (hash:{})",
                    *amount_sompi as f64 / 100_000_000.0,
                    recipient,
                    &event_hash[..16]
                )
            }
            AuditEvent::ProposalValidated { request_id, accepted, reason, .. } => {
                if *accepted {
                    format!("AUDIT: Proposal accepted (request:{})", &request_id[..16])
                } else {
                    format!("AUDIT: Proposal rejected - {} (request:{})", reason.as_deref().unwrap_or("unknown"), &request_id[..16])
                }
            }
            AuditEvent::PartialSignatureCreated { request_id, signer_peer_id, input_count, .. } => {
                format!(
                    "AUDIT: Partial signature created - {} inputs by {} (request:{})",
                    input_count, signer_peer_id, &request_id[..16]
                )
            }
            AuditEvent::TransactionFinalized { request_id, tx_id, signature_count, .. } => {
                format!(
                    "AUDIT: Transaction finalized - tx:{} with {} sigs (request:{})",
                    &tx_id[..16], signature_count, &request_id[..16]
                )
            }
            AuditEvent::TransactionSubmitted { tx_id, blue_score, .. } => {
                format!("AUDIT: Transaction submitted - tx:{} at blue_score:{}", &tx_id[..16], blue_score)
            }
            AuditEvent::SessionTimedOut { request_id, signature_count, threshold_required, .. } => {
                format!(
                    "AUDIT: Session timeout - {}/{} sigs collected (request:{})",
                    signature_count, threshold_required, &request_id[..16]
                )
            }
            AuditEvent::PolicyEnforced { request_id, decision, reason, .. } => {
                format!(
                    "AUDIT: Policy {:?} - {} (request:{})",
                    decision, reason, &request_id[..16]
                )
            }
            _ => format!("AUDIT: {:?}", event),
        };

        info!(target: "audit", "{}", summary);
    }
}
```

---

### 22. `src/infrastructure/storage/rocks/engine.rs`

**Add storage operation logging:**

```rust
impl RocksStorage {
    pub fn insert_request(&self, request: SigningRequest) -> Result<(), ThresholdError> {
        trace!(
            request_id = %request.request_id,
            "storage: inserting request"
        );
        // ... actual insert
        debug!(
            request_id = %request.request_id,
            cf = "requests",
            "storage: request inserted"
        );
        Ok(())
    }

    pub fn get_request(&self, request_id: &RequestId) -> Result<Option<SigningRequest>, ThresholdError> {
        trace!(request_id = %request_id, "storage: getting request");
        let result = // ... actual get
        trace!(
            request_id = %request_id,
            found = result.is_some(),
            "storage: request lookup complete"
        );
        Ok(result)
    }

    pub fn insert_partial_sig(&self, request_id: &RequestId, sig: PartialSigRecord) -> Result<(), ThresholdError> {
        debug!(
            request_id = %request_id,
            input_index = sig.input_index,
            signer = %sig.signer_peer_id,
            "storage: inserting partial signature"
        );
        // ... actual insert
        Ok(())
    }

    pub fn list_partial_sigs(&self, request_id: &RequestId) -> Result<Vec<PartialSigRecord>, ThresholdError> {
        trace!(request_id = %request_id, "storage: listing partial signatures");
        let result = // ... actual list
        trace!(
            request_id = %request_id,
            count = result.len(),
            "storage: partial signatures listed"
        );
        Ok(result)
    }
}
```

---

### 23. `src/infrastructure/rpc/grpc.rs`

**Add RPC call logging:**

```rust
impl NodeRpc for GrpcNodeRpc {
    async fn submit_transaction(&self, tx: &Transaction) -> Result<(), ThresholdError> {
        let tx_id = tx.id();
        debug!(tx_id = %tx_id, "submitting transaction to Kaspa node");

        let start = Instant::now();
        let result = self.client.submit_transaction(tx).await;
        let duration = start.elapsed();

        match &result {
            Ok(()) => {
                info!(
                    tx_id = %tx_id,
                    duration_ms = duration.as_millis(),
                    "transaction submitted successfully"
                );
            }
            Err(err) => {
                warn!(
                    tx_id = %tx_id,
                    error = %err,
                    duration_ms = duration.as_millis(),
                    "transaction submission failed"
                );
            }
        }

        result
    }

    async fn get_utxos_by_addresses(&self, addresses: &[Address]) -> Result<Vec<Utxo>, ThresholdError> {
        debug!(address_count = addresses.len(), "fetching UTXOs by addresses");

        let start = Instant::now();
        let result = self.client.get_utxos_by_addresses(addresses).await;
        let duration = start.elapsed();

        match &result {
            Ok(utxos) => {
                debug!(
                    utxo_count = utxos.len(),
                    duration_ms = duration.as_millis(),
                    "UTXOs fetched"
                );
            }
            Err(err) => {
                warn!(
                    error = %err,
                    duration_ms = duration.as_millis(),
                    "UTXO fetch failed"
                );
            }
        }

        result
    }
}
```

---

### 24. `src/infrastructure/rpc/circuit_breaker.rs`

**Add circuit breaker state logging:**

```rust
impl CircuitBreaker {
    pub fn allow(&self) -> bool {
        let mut state = self.state.lock();

        if let Some(open_until) = state.open_until {
            if Instant::now() < open_until {
                trace!(
                    state = "open",
                    remaining_ms = (open_until - Instant::now()).as_millis(),
                    "circuit breaker: request blocked"
                );
                return false;
            }
            // Transition to half-open
            info!(
                previous_state = "open",
                new_state = "half-open",
                "circuit breaker: transitioning to half-open"
            );
            state.open_until = None;
        }

        true
    }

    pub fn record_success(&self) {
        let mut state = self.state.lock();
        if state.failures > 0 {
            debug!(
                previous_failures = state.failures,
                "circuit breaker: success recorded, resetting failure count"
            );
        }
        state.failures = 0;
        state.open_until = None;
    }

    pub fn record_failure(&self) {
        let mut state = self.state.lock();
        state.failures += 1;

        debug!(
            failures = state.failures,
            threshold = self.threshold,
            "circuit breaker: failure recorded"
        );

        if state.failures >= self.threshold {
            state.open_until = Some(Instant::now() + self.cooldown);
            warn!(
                failures = state.failures,
                cooldown_secs = self.cooldown.as_secs(),
                "circuit breaker: OPENED due to excessive failures"
            );
        }
    }
}
```

---

### 25. `src/infrastructure/transport/iroh/client.rs`

**Add transport operation logging:**

```rust
impl Transport for IrohTransport {
    async fn publish_proposal(&self, session_id: SessionId, proposal: SigningProposal) -> Result<(), ThresholdError> {
        debug!(
            session_id = %hex::encode(session_id.as_hash())[..16],
            request_id = %proposal.request_id,
            "publishing signing proposal to group"
        );

        let message = TransportMessage::SigningEventPropose(proposal);
        let blob = serialize_message(&message)?;

        trace!(
            session_id = %hex::encode(session_id.as_hash())[..16],
            message_size = blob.len(),
            "serialized proposal message"
        );

        self.gossip.publish(self.group_topic, blob).await?;

        info!(
            session_id = %hex::encode(session_id.as_hash())[..16],
            "proposal published to signing group"
        );

        Ok(())
    }

    async fn subscribe_group(&self, group_id: Hash32) -> Result<GroupSubscription, ThresholdError> {
        info!(
            group_id = %hex::encode(&group_id[..8]),
            "subscribing to group gossip topic"
        );

        let subscription = self.gossip.subscribe(group_id).await?;

        debug!(
            group_id = %hex::encode(&group_id[..8]),
            "group subscription active"
        );

        Ok(subscription)
    }

    async fn subscribe_session(&self, session_id: SessionId) -> Result<SessionSubscription, ThresholdError> {
        debug!(
            session_id = %hex::encode(session_id.as_hash())[..16],
            "subscribing to session topic"
        );

        let subscription = self.gossip.subscribe(*session_id.as_hash()).await?;

        trace!(
            session_id = %hex::encode(session_id.as_hash())[..16],
            "session subscription active"
        );

        Ok(subscription)
    }
}
```

---

### 26. `src/infrastructure/config/loader.rs`

**Current state:** Has logging
**Add config summary:**

```rust
fn postprocess(config: &mut AppConfig, data_dir: &Path) -> Result<(), ThresholdError> {
    // ... existing postprocess logic

    // Add config summary log at end
    debug!(
        node_rpc_url = %redact_url(&config.service.node_rpc_url),
        rpc_enabled = config.rpc.enabled,
        rpc_addr = %config.rpc.addr,
        sig_op_count = config.service.pskt.sig_op_count,
        hd_configured = config.service.hd.is_some(),
        group_configured = config.group.is_some(),
        hyperlane_validators = config.hyperlane.validators.len(),
        layerzero_validators = config.layerzero.endpoint_pubkeys.len(),
        "configuration summary"
    );

    Ok(())
}
```

---

## Implementation Priority

### Phase 1: Critical (Do First)

| File | Change | Impact |
|------|--------|--------|
| `middleware/logging.rs` | Filter health checks | Eliminates 90% of noise |
| `coordination/loop.rs` | Add idle indicator | Clarifies "nothing happening" state |
| `setup.rs` | Add startup banner | Immediate context on startup |
| `finalization.rs` | Add session summary | Clear success/failure indication |

### Phase 2: Flow Visibility

| File | Change | Impact |
|------|--------|--------|
| `signer.rs` | Already good | Minor enhancements |
| `coordinator.rs` | Add flow logging | Session initiation clarity |
| `event_processor.rs` | Add event flow | Event ingestion visibility |
| `lifecycle.rs` | Add state transitions | Clear state progression |

### Phase 3: Domain Operations

| File | Change | Impact |
|------|--------|--------|
| `state_machine.rs` | Transition logging | State visibility |
| `pskt/builder.rs` | Build logging | PSKT construction clarity |
| `pskt/multisig.rs` | Signature logging | Aggregation visibility |
| `policy/enforcer.rs` | Check logging | Policy decision clarity |

### Phase 4: Infrastructure

| File | Change | Impact |
|------|--------|--------|
| `audit/mod.rs` | Human summaries | Readable audit trail |
| `storage/rocks/` | Operation logging | Debug storage issues |
| `rpc/grpc.rs` | Call logging | Network visibility |
| `transport/iroh/` | Message logging | P2P visibility |

---

## Validation Checklist

After implementing changes, verify:

- [ ] Startup shows clear banner with peer_id, group_id, network
- [ ] Idle service shows periodic "waiting for proposals" (not warnings)
- [ ] Health checks don't appear in INFO logs
- [ ] Session start shows: recipient, amount, event_id
- [ ] Validation shows: each check result, final decision
- [ ] Signature collection shows: progress (2/3 collected)
- [ ] Finalization shows: tx_id, duration, outcome
- [ ] Session end shows: `=== SESSION COMPLETE ===` with summary
- [ ] Errors show: context, not just error message
- [ ] Audit events have human-readable summaries

---

## Example: Complete Session Log

```
18:20:00 INFO  ╔══════════════════════════════════════════════════════════════╗
18:20:00 INFO  ║           IGRA Threshold Signing Service                     ║
18:20:00 INFO  ║ Peer ID: peer-signer-1 | Threshold: 2/3 | devnet            ║
18:20:00 INFO  ╚══════════════════════════════════════════════════════════════╝
18:20:00 INFO  coordination loop started group_id=abc12345
18:20:00 INFO  HTTP server ready addr=127.0.0.1:18088

18:21:00 INFO  service idle, waiting for signing proposals idle_seconds=60

18:22:15 INFO  signing event received event_id=evt-001 amount=10.0 KAS recipient=kaspa:qz...
18:22:15 INFO  message verification passed valid_sigs=2 threshold=2
18:22:15 INFO  received proposal session_id=def456 request_id=req-001
18:22:15 DEBUG validating proposal expected_group_id=abc123 event_hash=789...
18:22:15 DEBUG policy checks: destination=pass amount=pass daily_volume=pass
18:22:15 INFO  AUDIT: Proposal accepted (request:req-001)
18:22:15 INFO  proposal accepted - all validation checks passed
18:22:15 INFO  signing backend selected backend=threshold
18:22:15 INFO  threshold signing complete input_count=1 signatures=1
18:22:15 INFO  partial signatures submitted session_id=def456

18:22:15 INFO  collecting partial signatures required=2 input_count=1
18:22:16 INFO  signature collection progress collected=1 required=2 progress_pct=50
18:22:16 INFO  signature collection progress collected=2 required=2 progress_pct=100
18:22:16 INFO  lifecycle: signature threshold met (state=Approved)
18:22:16 INFO  finalizing PSKT input_count=1 output_count=2
18:22:16 INFO  submitting transaction to network tx_id=xyz789
18:22:17 INFO  transaction accepted by network tx_id=xyz789
18:22:17 INFO  AUDIT: Transaction finalized - tx:xyz789 with 2 sigs
18:22:17 INFO  lifecycle: transaction finalized (state=Finalized)
18:22:17 INFO  === SESSION COMPLETE === outcome=SUCCESS duration_ms=2150 tx_id=xyz789
```

---

## Final Assessment

### Codebase Logging Quality

| Layer | Status | Files Reviewed | Needs Work |
|-------|--------|----------------|------------|
| **igra-service** | ⚠️ Mixed | 10 | 4 files need fixes |
| **igra-core/application** | ✅ Excellent | 5 | 1 file (lifecycle) |
| **igra-core/infrastructure** | ✅ Good | 11 | 3 minor fixes |

### Key Findings

**Good News:** The `igra-core` codebase already has **production-quality logging**:
- `coordinator.rs` - Full spans, UTXO selection, PSKT build, tx submission
- `signer.rs` - Full spans, all validation checks, policy decisions
- `event_processor.rs` - Message verification, replay detection
- `storage/rocks/engine.rs` - All CRUD, migrations, checkpoints
- `rpc/grpc.rs` - All RPC calls with timing
- `transport/iroh/client.rs` - All publish/subscribe operations
- `transport/iroh/filtering.rs` - Rate limits, dedup, signatures

**Problem Areas:** The noise comes from **3 specific issues**:
1. `middleware/logging.rs` - Health checks logged at INFO
2. `subscription.rs:33` - Gossip timeout logged as WARN
3. Missing startup banner and session summaries

### Minimal Fix (Recommended)

Only **~50 lines of changes** needed:

```bash
# 1. Filter health checks (middleware/logging.rs)
# 2. Change gossip timeout from warn! to trace! (subscription.rs)
# 3. Add startup banner (setup.rs)
# 4. Add session summary log (loop.rs finalization task)
```

This will transform logs from:
```
WARN  iroh gossip receive timeout
INFO  request method=GET path=/rpc status=405
WARN  iroh gossip receive timeout
INFO  request method=GET path=/rpc status=405
```

To:
```
INFO  ║ IGRA Threshold Signing Service | Peer: signer-1 | 2/3 ║
INFO  service idle, waiting for signing proposals
INFO  received proposal amount=10 KAS to kaspa:qz...
INFO  === SESSION COMPLETE === outcome=SUCCESS tx=xyz789
```
