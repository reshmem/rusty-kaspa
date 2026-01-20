use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    EventReceived {
        event_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        external_request_id: Option<String>,
        source: String,
        recipient: String,
        amount_sompi: u64,
        timestamp_nanos: u64,
    },
    EventSignatureValidated {
        event_id: String,
        validator_count: usize,
        valid: bool,
        reason: Option<String>,
        timestamp_nanos: u64,
    },
    PolicyEnforced {
        event_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        external_request_id: Option<String>,
        policy_type: String,
        decision: PolicyDecision,
        reason: String,
        timestamp_nanos: u64,
    },
    ProposalValidated {
        event_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        external_request_id: Option<String>,
        signer_peer_id: String,
        accepted: bool,
        reason: Option<String>,
        validation_hash: String,
        timestamp_nanos: u64,
    },
    ProposalEquivocationDetected {
        event_id: String,
        round: u32,
        proposer_peer_id: String,
        existing_tx_template_hash: String,
        new_tx_template_hash: String,
        timestamp_nanos: u64,
    },
    PartialSignatureCreated {
        event_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        external_request_id: Option<String>,
        signer_peer_id: String,
        input_count: usize,
        timestamp_nanos: u64,
    },
    TransactionFinalized {
        event_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        external_request_id: Option<String>,
        tx_id: String,
        signature_count: usize,
        threshold_required: usize,
        timestamp_nanos: u64,
    },
    TransactionSubmitted {
        event_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        external_request_id: Option<String>,
        tx_id: String,
        blue_score: u64,
        timestamp_nanos: u64,
    },
    SessionTimedOut {
        event_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        external_request_id: Option<String>,
        signature_count: usize,
        threshold_required: usize,
        duration_seconds: u64,
        timestamp_nanos: u64,
    },
    ConfigurationChanged {
        change_type: String,
        old_value: Option<String>,
        new_value: String,
        changed_by: String,
        timestamp_nanos: u64,
    },
    StorageMutated {
        operation: String,
        key_prefix: String,
        record_count: usize,
        timestamp_nanos: u64,
    },
    RateLimitExceeded {
        peer_id: String,
        timestamp_nanos: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyDecision {
    Allowed,
    Rejected,
}
