use crate::audit::{audit, AuditEvent, PolicyDecision};
use crate::coordination::hashes::{event_hash, validation_hash};
use crate::coordination::policy::{DefaultPolicyEnforcer, PolicyEnforcer};
use crate::error::ThresholdError;
use crate::lifecycle::{LifecycleObserver, NoopObserver};
use crate::model::{GroupPolicy, Hash32, SignerAckRecord, SigningEvent};
use crate::pskt::multisig as pskt_multisig;
use crate::signing::SignerBackend;
use crate::storage::Storage;
use crate::transport::{SignerAck, Transport};
use crate::types::{PeerId, RequestId, SessionId};
use crate::util::time::current_timestamp_nanos_env;
use crate::validation::MessageVerifier;
use std::sync::Arc;
use subtle::ConstantTimeEq;

pub struct Signer {
    transport: Arc<dyn Transport>,
    storage: Arc<dyn Storage>,
    lifecycle: Arc<dyn LifecycleObserver>,
    policy_enforcer: Arc<dyn PolicyEnforcer>,
}

impl Signer {
    pub fn new(transport: Arc<dyn Transport>, storage: Arc<dyn Storage>) -> Self {
        let policy_enforcer = Arc::new(DefaultPolicyEnforcer::new(storage.clone()));
        Self { transport, storage, lifecycle: Arc::new(NoopObserver), policy_enforcer }
    }

    pub fn with_observer(transport: Arc<dyn Transport>, storage: Arc<dyn Storage>, lifecycle: Arc<dyn LifecycleObserver>) -> Self {
        let policy_enforcer = Arc::new(DefaultPolicyEnforcer::new(storage.clone()));
        Self { transport, storage, lifecycle, policy_enforcer }
    }

    pub fn set_lifecycle_observer(&mut self, observer: Arc<dyn LifecycleObserver>) {
        self.lifecycle = observer;
    }

    pub fn set_policy_enforcer(&mut self, enforcer: Arc<dyn PolicyEnforcer>) {
        self.policy_enforcer = enforcer;
    }

    pub fn validate_proposal(&self, req: ProposalValidationRequest) -> Result<SignerAck, ThresholdError> {
        let computed_hash = event_hash(&req.signing_event)?;
        let event_hash_match = computed_hash.ct_eq(&req.expected_event_hash);
        if !bool::from(event_hash_match) {
            return Ok(SignerAck {
                request_id: req.request_id.clone(),
                event_hash: req.expected_event_hash,
                validation_hash: req.expected_validation_hash,
                accept: false,
                reason: Some("event_hash_mismatch".to_string()),
                signer_peer_id: PeerId::from(""),
            });
        }

        if let Some(verifier) = req.message_verifier.as_ref() {
            if let Err(err) = verifier.verify(&req.signing_event) {
                return Ok(SignerAck {
                    request_id: req.request_id.clone(),
                    event_hash: req.expected_event_hash,
                    validation_hash: req.expected_validation_hash,
                    accept: false,
                    reason: Some(err.to_string()),
                    signer_peer_id: PeerId::from(""),
                });
            }
        }

        let signer_pskt = pskt_multisig::deserialize_pskt_signer(&req.kpsbt_blob)?;
        let computed_tx_hash = pskt_multisig::tx_template_hash(&signer_pskt)?;
        let tx_hash_match = computed_tx_hash.ct_eq(&req.tx_template_hash);
        if !bool::from(tx_hash_match) {
            return Ok(SignerAck {
                request_id: req.request_id.clone(),
                event_hash: req.expected_event_hash,
                validation_hash: req.expected_validation_hash,
                accept: false,
                reason: Some("tx_template_hash_mismatch".to_string()),
                signer_peer_id: PeerId::from(""),
            });
        }

        let per_input_hashes = pskt_multisig::input_hashes(&signer_pskt)?;
        let computed_validation =
            validation_hash(&req.expected_event_hash, &req.tx_template_hash, &per_input_hashes);
        let validation_hash_match = computed_validation.ct_eq(&req.expected_validation_hash);
        if !bool::from(validation_hash_match) {
            return Ok(SignerAck {
                request_id: req.request_id.clone(),
                event_hash: req.expected_event_hash,
                validation_hash: req.expected_validation_hash,
                accept: false,
                reason: Some("validation_hash_mismatch".to_string()),
                signer_peer_id: PeerId::from(""),
            });
        }

        // Validate expiry window
        let now_nanos = current_nanos()?;
        use crate::constants::{MAX_SESSION_DURATION_NS, MIN_SESSION_DURATION_NS};
        let min_expiry = now_nanos.saturating_add(MIN_SESSION_DURATION_NS);
        let max_expiry = now_nanos.saturating_add(MAX_SESSION_DURATION_NS);
        if req.expires_at_nanos < min_expiry || req.expires_at_nanos > max_expiry {
            return Ok(SignerAck {
                request_id: req.request_id.clone(),
                event_hash: req.expected_event_hash,
                validation_hash: req.expected_validation_hash,
                accept: false,
                reason: Some("expires_at_nanos_out_of_bounds".to_string()),
                signer_peer_id: PeerId::from(""),
            });
        }

        if let Some(policy) = req.policy.as_ref() {
            if let Err(err) = self.policy_enforcer.enforce_policy(&req.signing_event, policy) {
                crate::audit_policy_enforced!(
                    req.request_id,
                    req.expected_event_hash,
                    "group_policy",
                    PolicyDecision::Rejected,
                    err.to_string()
                );
                return Ok(SignerAck {
                    request_id: req.request_id.clone(),
                    event_hash: req.expected_event_hash,
                    validation_hash: req.expected_validation_hash,
                    accept: false,
                    reason: Some(err.to_string()),
                    signer_peer_id: PeerId::from(""),
                });
            }
            crate::audit_policy_enforced!(
                req.request_id,
                req.expected_event_hash,
                "group_policy",
                PolicyDecision::Allowed,
                "policy_ok"
            );
        }

        self.lifecycle.on_event_received(&req.signing_event, &req.expected_event_hash);
        self.storage.insert_event(req.expected_event_hash, req.signing_event.clone())?;
        let request = crate::state_machine::TypedSigningRequest::<crate::state_machine::Pending>::new(
            req.request_id.clone(),
            req.session_id,
            req.expected_event_hash,
            req.coordinator_peer_id,
            req.tx_template_hash,
            req.expected_validation_hash,
            req.expires_at_nanos,
        )
        .into_inner();
        self.storage.insert_request(request.clone())?;
        self.lifecycle.on_request_created(&request);
        self.storage.insert_proposal(
            &req.request_id,
            crate::model::StoredProposal {
                request_id: req.request_id.clone(),
                session_id: req.session_id,
                event_hash: req.expected_event_hash,
                validation_hash: req.expected_validation_hash,
                signing_event: req.signing_event,
                kpsbt_blob: req.kpsbt_blob.to_vec(),
            },
        )?;

        Ok(SignerAck {
            request_id: req.request_id.clone(),
            event_hash: req.expected_event_hash,
            validation_hash: req.expected_validation_hash,
            accept: true,
            reason: None,
            signer_peer_id: PeerId::from(""),
        })
    }

    pub async fn submit_ack(&self, session_id: SessionId, mut ack: SignerAck, signer_peer_id: PeerId) -> Result<(), ThresholdError> {
        let now_nanos = current_nanos()?;
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
}

fn current_nanos() -> Result<u64, ThresholdError> {
    current_timestamp_nanos_env(Some("KASPA_IGRA_TEST_NOW_NANOS"))
}

pub struct ProposalValidationRequest {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub signing_event: SigningEvent,
    pub expected_event_hash: Hash32,
    pub kpsbt_blob: Vec<u8>,
    pub tx_template_hash: Hash32,
    pub expected_validation_hash: Hash32,
    pub coordinator_peer_id: PeerId,
    pub expires_at_nanos: u64,
    pub policy: Option<GroupPolicy>,
    pub message_verifier: Option<Arc<dyn MessageVerifier>>,
}

pub struct ProposalValidationRequestBuilder {
    request_id: Option<RequestId>,
    session_id: Option<SessionId>,
    signing_event: Option<SigningEvent>,
    expected_event_hash: Option<Hash32>,
    kpsbt_blob: Option<Vec<u8>>,
    tx_template_hash: Option<Hash32>,
    expected_validation_hash: Option<Hash32>,
    coordinator_peer_id: Option<PeerId>,
    expires_at_nanos: Option<u64>,
    policy: Option<GroupPolicy>,
    message_verifier: Option<Arc<dyn MessageVerifier>>,
}

impl Default for ProposalValidationRequestBuilder {
    fn default() -> Self {
        Self {
            request_id: None,
            session_id: None,
            signing_event: None,
            expected_event_hash: None,
            kpsbt_blob: None,
            tx_template_hash: None,
            expected_validation_hash: None,
            coordinator_peer_id: None,
            expires_at_nanos: None,
            policy: None,
            message_verifier: None,
        }
    }
}

impl ProposalValidationRequestBuilder {
    pub fn new(request_id: RequestId, session_id: SessionId, signing_event: SigningEvent) -> Self {
        Self { request_id: Some(request_id), session_id: Some(session_id), signing_event: Some(signing_event), ..Default::default() }
    }

    pub fn expected_event_hash(mut self, hash: Hash32) -> Self {
        self.expected_event_hash = Some(hash);
        self
    }

    pub fn kpsbt_blob(mut self, blob: &[u8]) -> Self {
        self.kpsbt_blob = Some(blob.to_vec());
        self
    }

    pub fn tx_template_hash(mut self, hash: Hash32) -> Self {
        self.tx_template_hash = Some(hash);
        self
    }

    pub fn expected_validation_hash(mut self, hash: Hash32) -> Self {
        self.expected_validation_hash = Some(hash);
        self
    }

    pub fn coordinator_peer_id(mut self, peer_id: PeerId) -> Self {
        self.coordinator_peer_id = Some(peer_id);
        self
    }

    pub fn expires_at_nanos(mut self, expires_at_nanos: u64) -> Self {
        self.expires_at_nanos = Some(expires_at_nanos);
        self
    }

    pub fn policy(mut self, policy: Option<&GroupPolicy>) -> Self {
        self.policy = policy.cloned();
        self
    }

    pub fn message_verifier(mut self, verifier: Option<Arc<dyn MessageVerifier>>) -> Self {
        self.message_verifier = verifier;
        self
    }

    pub fn build(self) -> Result<ProposalValidationRequest, ThresholdError> {
        Ok(ProposalValidationRequest {
            request_id: self.request_id.ok_or_else(|| ThresholdError::Message("request_id required".into()))?,
            session_id: self.session_id.ok_or_else(|| ThresholdError::Message("session_id required".into()))?,
            signing_event: self.signing_event.ok_or_else(|| ThresholdError::Message("signing_event required".into()))?,
            expected_event_hash: self.expected_event_hash.ok_or_else(|| ThresholdError::Message("expected_event_hash required".into()))?,
            kpsbt_blob: self.kpsbt_blob.ok_or_else(|| ThresholdError::Message("kpsbt_blob required".into()))?,
            tx_template_hash: self.tx_template_hash.ok_or_else(|| ThresholdError::Message("tx_template_hash required".into()))?,
            expected_validation_hash: self
                .expected_validation_hash
                .ok_or_else(|| ThresholdError::Message("expected_validation_hash required".into()))?,
            coordinator_peer_id: self.coordinator_peer_id.ok_or_else(|| ThresholdError::Message("coordinator_peer_id required".into()))?,
            expires_at_nanos: self.expires_at_nanos.ok_or_else(|| ThresholdError::Message("expires_at_nanos required".into()))?,
            policy: self.policy,
            message_verifier: self.message_verifier,
        })
    }
}
