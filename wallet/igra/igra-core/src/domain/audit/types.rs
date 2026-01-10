use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    EventReceived {
        event_hash: String,
        source: String,
        recipient: String,
        amount_sompi: u64,
        timestamp_ns: u64,
    },
    EventSignatureValidated {
        event_hash: String,
        validator_count: usize,
        valid: bool,
        reason: Option<String>,
        timestamp_ns: u64,
    },
    PolicyEnforced {
        request_id: String,
        event_hash: String,
        policy_type: String,
        decision: PolicyDecision,
        reason: String,
        timestamp_ns: u64,
    },
    ProposalValidated {
        request_id: String,
        signer_peer_id: String,
        accepted: bool,
        reason: Option<String>,
        validation_hash: String,
        timestamp_ns: u64,
    },
    PartialSignatureCreated {
        request_id: String,
        signer_peer_id: String,
        input_count: usize,
        timestamp_ns: u64,
    },
    TransactionFinalized {
        request_id: String,
        event_hash: String,
        tx_id: String,
        signature_count: usize,
        threshold_required: usize,
        timestamp_ns: u64,
    },
    TransactionSubmitted {
        request_id: String,
        tx_id: String,
        blue_score: u64,
        timestamp_ns: u64,
    },
    SessionTimedOut {
        request_id: String,
        event_hash: String,
        signature_count: usize,
        threshold_required: usize,
        duration_seconds: u64,
        timestamp_ns: u64,
    },
    ConfigurationChanged {
        change_type: String,
        old_value: Option<String>,
        new_value: String,
        changed_by: String,
        timestamp_ns: u64,
    },
    StorageMutated {
        operation: String,
        key_prefix: String,
        record_count: usize,
        timestamp_ns: u64,
    },
    RateLimitExceeded {
        peer_id: String,
        timestamp_ns: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyDecision {
    Allowed,
    Rejected,
}
