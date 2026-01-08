use crate::audit::{audit, AuditEvent, PolicyDecision};
use crate::coordination::hashes::{event_hash, validation_hash};
use crate::error::ThresholdError;
use crate::lifecycle::{LifecycleObserver, NoopObserver};
use crate::model::{GroupPolicy, Hash32, RequestDecision, SignerAckRecord, SigningEvent, SigningRequest};
use crate::pskt::multisig as pskt_multisig;
use crate::signing::SignerBackend;
use crate::storage::Storage;
use crate::transport::{SignerAck, Transport};
use crate::types::{PeerId, RequestId, SessionId};
use crate::validation::MessageVerifier;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

pub struct Signer {
    transport: Arc<dyn Transport>,
    storage: Arc<dyn Storage>,
    lifecycle: Arc<dyn LifecycleObserver>,
}

impl Signer {
    pub fn new(transport: Arc<dyn Transport>, storage: Arc<dyn Storage>) -> Self {
        Self { transport, storage, lifecycle: Arc::new(NoopObserver) }
    }

    pub fn with_observer(transport: Arc<dyn Transport>, storage: Arc<dyn Storage>, lifecycle: Arc<dyn LifecycleObserver>) -> Self {
        Self { transport, storage, lifecycle }
    }

    pub fn set_lifecycle_observer(&mut self, observer: Arc<dyn LifecycleObserver>) {
        self.lifecycle = observer;
    }

    pub fn validate_proposal(
        &self,
        request_id: &RequestId,
        session_id: SessionId,
        signing_event: SigningEvent,
        expected_event_hash: Hash32,
        kpsbt_blob: &[u8],
        tx_template_hash: Hash32,
        expected_validation_hash: Hash32,
        coordinator_peer_id: PeerId,
        expires_at_nanos: u64,
        policy: Option<&GroupPolicy>,
        message_verifier: Option<&dyn MessageVerifier>,
    ) -> Result<SignerAck, ThresholdError> {
        let computed_hash = event_hash(&signing_event)?;
        let event_hash_match = computed_hash.ct_eq(&expected_event_hash);
        if !bool::from(event_hash_match) {
            return Ok(SignerAck {
                request_id: request_id.clone(),
                event_hash: expected_event_hash,
                validation_hash: expected_validation_hash,
                accept: false,
                reason: Some("event_hash_mismatch".to_string()),
                signer_peer_id: PeerId::from(""),
            });
        }

        if let Some(verifier) = message_verifier {
            if let Err(err) = verifier.verify(&signing_event) {
                return Ok(SignerAck {
                    request_id: request_id.clone(),
                    event_hash: expected_event_hash,
                    validation_hash: expected_validation_hash,
                    accept: false,
                    reason: Some(err.to_string()),
                    signer_peer_id: PeerId::from(""),
                });
            }
        }

        let signer_pskt = pskt_multisig::deserialize_pskt_signer(kpsbt_blob)?;
        let computed_tx_hash = pskt_multisig::tx_template_hash(&signer_pskt)?;
        let tx_hash_match = computed_tx_hash.ct_eq(&tx_template_hash);
        if !bool::from(tx_hash_match) {
            return Ok(SignerAck {
                request_id: request_id.clone(),
                event_hash: expected_event_hash,
                validation_hash: expected_validation_hash,
                accept: false,
                reason: Some("tx_template_hash_mismatch".to_string()),
                signer_peer_id: PeerId::from(""),
            });
        }

        let per_input_hashes = pskt_multisig::input_hashes(&signer_pskt)?;
        let computed_validation = validation_hash(&expected_event_hash, &tx_template_hash, &per_input_hashes);
        let validation_hash_match = computed_validation.ct_eq(&expected_validation_hash);
        if !bool::from(validation_hash_match) {
            return Ok(SignerAck {
                request_id: request_id.clone(),
                event_hash: expected_event_hash,
                validation_hash: expected_validation_hash,
                accept: false,
                reason: Some("validation_hash_mismatch".to_string()),
                signer_peer_id: PeerId::from(""),
            });
        }

        if let Some(policy) = policy {
            if let Err(err) = self.enforce_policy(&signing_event, policy) {
                crate::audit_policy_enforced!(
                    request_id,
                    expected_event_hash,
                    "group_policy",
                    PolicyDecision::Rejected,
                    err.to_string()
                );
                return Ok(SignerAck {
                    request_id: request_id.clone(),
                    event_hash: expected_event_hash,
                    validation_hash: expected_validation_hash,
                    accept: false,
                    reason: Some(err.to_string()),
                    signer_peer_id: PeerId::from(""),
                });
            }
            crate::audit_policy_enforced!(request_id, expected_event_hash, "group_policy", PolicyDecision::Allowed, "policy_ok");
        }

        self.lifecycle.on_event_received(&signing_event, &expected_event_hash);
        self.storage.insert_event(expected_event_hash, signing_event.clone())?;
        let request = SigningRequest {
            request_id: request_id.clone(),
            session_id,
            event_hash: expected_event_hash,
            coordinator_peer_id,
            tx_template_hash,
            validation_hash: expected_validation_hash,
            decision: RequestDecision::Pending,
            expires_at_nanos,
            final_tx_id: None,
            final_tx_accepted_blue_score: None,
        };
        self.storage.insert_request(request.clone())?;
        self.lifecycle.on_request_created(&request);
        self.storage.insert_proposal(
            request_id,
            crate::model::StoredProposal {
                request_id: request_id.clone(),
                session_id,
                event_hash: expected_event_hash,
                validation_hash: expected_validation_hash,
                signing_event,
                kpsbt_blob: kpsbt_blob.to_vec(),
            },
        )?;

        Ok(SignerAck {
            request_id: request_id.clone(),
            event_hash: expected_event_hash,
            validation_hash: expected_validation_hash,
            accept: true,
            reason: None,
            signer_peer_id: PeerId::from(""),
        })
    }

    pub async fn submit_ack(&self, session_id: SessionId, mut ack: SignerAck, signer_peer_id: PeerId) -> Result<(), ThresholdError> {
        let now_nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
        self.storage.insert_signer_ack(
            &ack.request_id,
            SignerAckRecord {
                signer_peer_id: signer_peer_id.clone(),
                accept: ack.accept,
                reason: ack.reason.clone(),
                timestamp_nanos: now_nanos,
            },
        )?;
        ack.signer_peer_id = signer_peer_id;
        audit(AuditEvent::ProposalValidated {
            request_id: ack.request_id.to_string(),
            signer_peer_id: ack.signer_peer_id.to_string(),
            accepted: ack.accept,
            reason: ack.reason.clone(),
            validation_hash: hex::encode(ack.validation_hash),
            timestamp_ns: now_nanos,
        });
        self.transport.publish_ack(session_id, ack).await
    }

    pub async fn submit_partial_sigs(
        &self,
        session_id: SessionId,
        request_id: &RequestId,
        backend: &dyn SignerBackend,
        kpsbt_blob: &[u8],
    ) -> Result<(), ThresholdError> {
        let signatures = backend.sign(kpsbt_blob)?;
        for sig in signatures {
            self.transport.publish_partial_sig(session_id, request_id, sig.input_index, sig.pubkey, sig.signature).await?;
        }
        Ok(())
    }

    pub async fn sign_and_submit_backend(
        &self,
        session_id: SessionId,
        request_id: &RequestId,
        kpsbt_blob: &[u8],
        backend: &dyn SignerBackend,
    ) -> Result<(), ThresholdError> {
        self.submit_partial_sigs(session_id, request_id, backend, kpsbt_blob).await
    }

    fn enforce_policy(&self, signing_event: &SigningEvent, policy: &GroupPolicy) -> Result<(), ThresholdError> {
        if !policy.allowed_destinations.is_empty() && !policy.allowed_destinations.contains(&signing_event.destination_address) {
            return Err(ThresholdError::DestinationNotAllowed(signing_event.destination_address.clone()));
        }

        if let Some(min_amount) = policy.min_amount_sompi {
            if signing_event.amount_sompi < min_amount {
                return Err(ThresholdError::AmountTooLow { amount: signing_event.amount_sompi, min: min_amount });
            }
        }

        if let Some(max_amount) = policy.max_amount_sompi {
            if signing_event.amount_sompi > max_amount {
                return Err(ThresholdError::AmountTooHigh { amount: signing_event.amount_sompi, max: max_amount });
            }
        }

        if policy.require_reason && !signing_event.metadata.contains_key("reason") {
            return Err(ThresholdError::MemoRequired);
        }

        if let Some(limit) = policy.max_daily_volume_sompi {
            let now = now_nanos();
            let day_start = day_start_nanos(now);
            let total = self.storage.get_volume_since(day_start)?;
            if total.saturating_add(signing_event.amount_sompi) > limit {
                return Err(ThresholdError::VelocityLimitExceeded { current: total, limit });
            }
        }

        Ok(())
    }
}

fn day_start_nanos(now_nanos: u64) -> u64 {
    let nanos_per_day = 24 * 60 * 60 * 1_000_000_000u64;
    (now_nanos / nanos_per_day) * nanos_per_day
}

fn now_nanos() -> u64 {
    if let Ok(value) = std::env::var("KASPA_IGRA_TEST_NOW_NANOS") {
        if let Ok(parsed) = value.trim().parse::<u64>() {
            return parsed;
        }
    }
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
}
