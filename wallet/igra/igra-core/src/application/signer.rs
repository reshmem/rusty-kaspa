use crate::application::lifecycle::{LifecycleObserver, NoopObserver};
use crate::domain::hashes::{event_hash, validation_hash};
use crate::domain::policy::{DefaultPolicyEnforcer, PolicyEnforcer};
use crate::domain::pskt::multisig as pskt_multisig;
use crate::domain::signing::SignerBackend;
use crate::domain::validation::MessageVerifier;
use crate::domain::{GroupPolicy, PartialSigRecord, SignerAckRecord, SigningEvent, StoredProposal};
use crate::foundation::util::time::{current_timestamp_nanos_env, day_start_nanos};
use crate::foundation::{Hash32, PeerId, RequestId, SessionId, ThresholdError};
use crate::infrastructure::audit::{audit, AuditEvent, PolicyDecision};
use crate::infrastructure::storage::Storage;
use crate::infrastructure::transport::iroh::traits::{SignerAck, Transport};
use log::{debug, info, trace, warn};
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
        let policy_enforcer = Arc::new(DefaultPolicyEnforcer::new());
        Self { transport, storage, lifecycle: Arc::new(NoopObserver), policy_enforcer }
    }

    pub fn with_observer(transport: Arc<dyn Transport>, storage: Arc<dyn Storage>, lifecycle: Arc<dyn LifecycleObserver>) -> Self {
        let policy_enforcer = Arc::new(DefaultPolicyEnforcer::new());
        Self { transport, storage, lifecycle, policy_enforcer }
    }

    pub fn set_lifecycle_observer(&mut self, observer: Arc<dyn LifecycleObserver>) {
        self.lifecycle = observer;
    }

    pub fn set_policy_enforcer(&mut self, enforcer: Arc<dyn PolicyEnforcer>) {
        self.policy_enforcer = enforcer;
    }

    pub fn validate_proposal(&self, req: ProposalValidationRequest, local_peer_id: &PeerId) -> Result<SignerAck, ThresholdError> {
        let signer_peer_id = local_peer_id.clone();
        info!(
            "starting proposal validation session_id={} request_id={} event_id={} coordinator_peer_id={} signer_peer_id={} expected_group_id={} proposal_group_id={} expected_event_hash={} expected_validation_hash={} tx_template_hash={} kpsbt_len={} expires_at_nanos={} recipient={} amount_sompi={} event_source={:?} checks_to_run={}",
            hex::encode(req.session_id.as_hash()),
            req.request_id,
            req.signing_event.event_id,
            req.coordinator_peer_id,
            local_peer_id,
            hex::encode(req.expected_group_id),
            hex::encode(req.proposal_group_id),
            hex::encode(req.expected_event_hash),
            hex::encode(req.expected_validation_hash),
            hex::encode(req.tx_template_hash),
            req.kpsbt_blob.len(),
            req.expires_at_nanos,
            req.signing_event.destination_address,
            req.signing_event.amount_sompi,
            req.signing_event.event_source,
            "group_id,event_hash,message_sig,tx_template,validation_hash,clock_skew,policy"
        );

        if req.proposal_group_id != req.expected_group_id {
            warn!(
                "rejecting proposal: group_id_mismatch expected_group_id={} proposal_group_id={}",
                hex::encode(req.expected_group_id),
                hex::encode(req.proposal_group_id)
            );
            return Ok(SignerAck {
                request_id: req.request_id.clone(),
                event_hash: req.expected_event_hash,
                validation_hash: req.expected_validation_hash,
                accept: false,
                reason: Some("group_id_mismatch".to_string()),
                signer_peer_id,
            });
        }

        let computed_hash = event_hash(&req.signing_event)?;
        debug!(
            "computed event hash computed_event_hash={} expected_event_hash={}",
            hex::encode(computed_hash),
            hex::encode(req.expected_event_hash)
        );
        let event_hash_match = computed_hash.ct_eq(&req.expected_event_hash);
        if !bool::from(event_hash_match) {
            warn!(
                "rejecting proposal: event_hash_mismatch computed_event_hash={} expected_event_hash={}",
                hex::encode(computed_hash),
                hex::encode(req.expected_event_hash)
            );
            return Ok(SignerAck {
                request_id: req.request_id.clone(),
                event_hash: req.expected_event_hash,
                validation_hash: req.expected_validation_hash,
                accept: false,
                reason: Some("event_hash_mismatch".to_string()),
                signer_peer_id,
            });
        }

        if let Some(verifier) = req.message_verifier.as_ref() {
            match verifier.verify(&req.signing_event) {
                Ok(report) if report.valid => {
                    debug!(
                        "proposal message verification passed source={:?} validator_count={} valid_signatures={} threshold={}",
                        report.source, report.validator_count, report.valid_signatures, report.threshold_required
                    );
                }
                Ok(report) => {
                    warn!(
                        "rejecting proposal: signature verification failed source={:?} validator_count={} valid_signatures={} threshold={} failure={:?}",
                        report.source,
                        report.validator_count,
                        report.valid_signatures,
                        report.threshold_required,
                        report.failure_reason
                    );
                    return Ok(SignerAck {
                        request_id: req.request_id.clone(),
                        event_hash: req.expected_event_hash,
                        validation_hash: req.expected_validation_hash,
                        accept: false,
                        reason: Some(report.failure_reason.unwrap_or_else(|| "message_verification_failed".to_string())),
                        signer_peer_id,
                    });
                }
                Err(err) => {
                    warn!("rejecting proposal: message verifier error error={}", err);
                    return Ok(SignerAck {
                        request_id: req.request_id.clone(),
                        event_hash: req.expected_event_hash,
                        validation_hash: req.expected_validation_hash,
                        accept: false,
                        reason: Some(err.to_string()),
                        signer_peer_id,
                    });
                }
            }
        }

        let signer_pskt = pskt_multisig::deserialize_pskt_signer(&req.kpsbt_blob)?;
        debug!(
            "PSKT deserialized kpsbt_len={} input_count={} output_count={}",
            req.kpsbt_blob.len(),
            signer_pskt.inputs.len(),
            signer_pskt.outputs.len()
        );
        let computed_tx_hash = pskt_multisig::tx_template_hash(&signer_pskt)?;
        let tx_hash_match = computed_tx_hash.ct_eq(&req.tx_template_hash);
        if !bool::from(tx_hash_match) {
            warn!(
                "rejecting proposal: tx_template_hash_mismatch computed_tx_template_hash={} expected_tx_template_hash={}",
                hex::encode(computed_tx_hash),
                hex::encode(req.tx_template_hash)
            );
            return Ok(SignerAck {
                request_id: req.request_id.clone(),
                event_hash: req.expected_event_hash,
                validation_hash: req.expected_validation_hash,
                accept: false,
                reason: Some("tx_template_hash_mismatch".to_string()),
                signer_peer_id,
            });
        }

        let per_input_hashes = pskt_multisig::input_hashes(&signer_pskt)?;
        let computed_validation = validation_hash(&req.expected_event_hash, &req.tx_template_hash, &per_input_hashes);
        let validation_hash_match = computed_validation.ct_eq(&req.expected_validation_hash);
        if !bool::from(validation_hash_match) {
            warn!(
                "rejecting proposal: validation_hash_mismatch computed_validation_hash={} expected_validation_hash={}",
                hex::encode(computed_validation),
                hex::encode(req.expected_validation_hash)
            );
            return Ok(SignerAck {
                request_id: req.request_id.clone(),
                event_hash: req.expected_event_hash,
                validation_hash: req.expected_validation_hash,
                accept: false,
                reason: Some("validation_hash_mismatch".to_string()),
                signer_peer_id: PeerId::from(""),
            });
        }

        // Validate expiry window with skew tolerance (coordinator/signers may have minor clock drift).
        let now_nanos = current_nanos()?;
        use crate::foundation::constants::MAX_SESSION_DURATION_NS;
        const CLOCK_SKEW_TOLERANCE_NS: u64 = 30 * 1_000_000_000;
        let max_expiry = now_nanos.saturating_add(MAX_SESSION_DURATION_NS).saturating_add(CLOCK_SKEW_TOLERANCE_NS);
        let min_expiry = now_nanos.saturating_sub(CLOCK_SKEW_TOLERANCE_NS);
        debug!(
            "validated expiry window bounds now_nanos={} min_expiry={} max_expiry={} expires_at_nanos={}",
            now_nanos, min_expiry, max_expiry, req.expires_at_nanos
        );

        if req.expires_at_nanos < min_expiry || req.expires_at_nanos > max_expiry {
            debug!("rejecting proposal: expires_at_nanos_out_of_bounds");
            return Ok(SignerAck {
                request_id: req.request_id.clone(),
                event_hash: req.expected_event_hash,
                validation_hash: req.expected_validation_hash,
                accept: false,
                reason: Some("expires_at_nanos_out_of_bounds".to_string()),
                signer_peer_id,
            });
        }

        if let Some(policy) = req.policy.as_ref() {
            let current_volume = if policy.max_daily_volume_sompi.is_some() {
                let day_start = day_start_nanos(req.signing_event.timestamp_nanos);
                self.storage.get_volume_since(day_start)?
            } else {
                0
            };
            debug!(
                "evaluating policy max_daily_volume_set={} current_volume_sompi={}",
                policy.max_daily_volume_sompi.is_some(),
                current_volume
            );
            let policy_result = self.policy_enforcer.evaluate_policy(&req.signing_event, policy, current_volume);
            for check in &policy_result.checks_performed {
                trace!("policy check check_type={:?} passed={} details={}", check.check_type, check.passed, check.details);
            }
            if !policy_result.allowed {
                let failure = policy_result
                    .failed_check
                    .as_ref()
                    .map(|failure| (format!("{:?}", failure.check_type), failure.reason.clone()))
                    .unwrap_or_else(|| ("unknown".to_string(), "policy rejected".to_string()));
                crate::audit_policy_enforced!(
                    req.request_id,
                    req.expected_event_hash,
                    failure.0,
                    PolicyDecision::Rejected,
                    failure.1.clone()
                );
                warn!("policy rejected proposal reason={}", failure.1);
                return Ok(SignerAck {
                    request_id: req.request_id.clone(),
                    event_hash: req.expected_event_hash,
                    validation_hash: req.expected_validation_hash,
                    accept: false,
                    reason: Some(failure.1),
                    signer_peer_id,
                });
            }
            crate::audit_policy_enforced!(
                req.request_id,
                req.expected_event_hash,
                "group_policy",
                PolicyDecision::Allowed,
                "policy_ok"
            );
            info!(
                "policy accepted proposal checks_passed={} daily_volume_check={} destination_check={}",
                policy_result.checks_performed.len(),
                policy.max_daily_volume_sompi.is_some(),
                !policy.allowed_destinations.is_empty()
            );
        }

        self.lifecycle.on_event_received(&req.signing_event, &req.expected_event_hash);
        self.storage.insert_event(req.expected_event_hash, req.signing_event.clone())?;
        debug!("event stored event_hash={}", hex::encode(req.expected_event_hash));
        let request =
            crate::domain::request::state_machine::TypedSigningRequest::<crate::domain::request::state_machine::Pending>::new(
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
        debug!("request stored request_id={}", request.request_id);
        self.lifecycle.on_request_created(&request);
        self.storage.insert_proposal(
            &req.request_id,
            StoredProposal {
                request_id: req.request_id.clone(),
                session_id: req.session_id,
                event_hash: req.expected_event_hash,
                validation_hash: req.expected_validation_hash,
                signing_event: req.signing_event,
                kpsbt_blob: req.kpsbt_blob.to_vec(),
            },
        )?;
        debug!("proposal stored request_id={} kpsbt_len={}", req.request_id, req.kpsbt_blob.len());

        info!("proposal accepted - all validation checks passed accept=true");
        Ok(SignerAck {
            request_id: req.request_id.clone(),
            event_hash: req.expected_event_hash,
            validation_hash: req.expected_validation_hash,
            accept: true,
            reason: None,
            signer_peer_id,
        })
    }

    pub async fn submit_ack(&self, session_id: SessionId, mut ack: SignerAck, signer_peer_id: PeerId) -> Result<(), ThresholdError> {
        info!(
            "submitting signer ack session_id={} request_id={} accept={}",
            hex::encode(session_id.as_hash()),
            ack.request_id,
            ack.accept
        );
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
        signer_peer_id: &PeerId,
    ) -> Result<(), ThresholdError> {
        info!(
            "submitting partial signatures session_id={} request_id={} kpsbt_len={}",
            hex::encode(session_id.as_hash()),
            request_id,
            kpsbt_blob.len()
        );
        let signing_result = backend.sign(kpsbt_blob, request_id)?;
        info!(
            "signing operation completed request_id={} input_count={} signatures_produced={} signer_pubkey={}",
            signing_result.request_id,
            signing_result.input_count,
            signing_result.signatures_produced.len(),
            hex::encode(&signing_result.signer_pubkey)
        );
        let now_nanos = current_nanos()?;
        let signing_request_id = signing_result.request_id.clone();
        for sig in signing_result.signatures_produced {
            let submit = crate::domain::signing::PartialSigSubmit {
                request_id: signing_request_id.clone(),
                input_index: sig.input_index,
                pubkey: sig.pubkey.clone(),
                signature: sig.signature.clone(),
            };
            self.storage.insert_partial_sig(
                request_id,
                PartialSigRecord {
                    signer_peer_id: signer_peer_id.clone(),
                    input_index: submit.input_index,
                    pubkey: submit.pubkey.clone(),
                    signature: submit.signature.clone(),
                    timestamp_nanos: now_nanos,
                },
            )?;
            audit(AuditEvent::PartialSignatureCreated {
                request_id: request_id.to_string(),
                signer_peer_id: signer_peer_id.to_string(),
                input_count: 1,
                timestamp_ns: now_nanos,
            });
            debug!(
                "partial signature stored request_id={} input_index={} signature_len={}",
                request_id,
                submit.input_index,
                submit.signature.len()
            );
            debug!(
                "publishing partial signature session_id={} request_id={} input_index={} pubkey_len={}",
                hex::encode(session_id.as_hash()),
                request_id,
                submit.input_index,
                submit.pubkey.len()
            );
            trace!("publish_partial_sig call request_id={} input_index={}", request_id, submit.input_index);
            self.transport.publish_partial_sig(session_id, request_id, submit.input_index, submit.pubkey, submit.signature).await?;
        }
        info!(
            "partial signatures submitted session_id={} request_id={}",
            hex::encode(session_id.as_hash()),
            request_id
        );
        Ok(())
    }

    pub async fn sign_and_submit_backend(
        &self,
        session_id: SessionId,
        request_id: &RequestId,
        kpsbt_blob: &[u8],
        backend: &dyn SignerBackend,
        signer_peer_id: &PeerId,
    ) -> Result<(), ThresholdError> {
        self.submit_partial_sigs(session_id, request_id, backend, kpsbt_blob, signer_peer_id).await
    }
}

fn current_nanos() -> Result<u64, ThresholdError> {
    current_timestamp_nanos_env(Some("KASPA_IGRA_TEST_NOW_NANOS"))
}

pub struct ProposalValidationRequest {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub signing_event: SigningEvent,
    pub expected_group_id: Hash32,
    pub proposal_group_id: Hash32,
    pub expected_event_hash: Hash32,
    pub kpsbt_blob: Vec<u8>,
    pub tx_template_hash: Hash32,
    pub expected_validation_hash: Hash32,
    pub coordinator_peer_id: PeerId,
    pub expires_at_nanos: u64,
    pub policy: Option<GroupPolicy>,
    pub message_verifier: Option<Arc<dyn MessageVerifier>>,
}

#[derive(Default)]
pub struct ProposalValidationRequestBuilder {
    request_id: Option<RequestId>,
    session_id: Option<SessionId>,
    signing_event: Option<SigningEvent>,
    expected_group_id: Option<Hash32>,
    proposal_group_id: Option<Hash32>,
    expected_event_hash: Option<Hash32>,
    kpsbt_blob: Option<Vec<u8>>,
    tx_template_hash: Option<Hash32>,
    expected_validation_hash: Option<Hash32>,
    coordinator_peer_id: Option<PeerId>,
    expires_at_nanos: Option<u64>,
    policy: Option<GroupPolicy>,
    message_verifier: Option<Arc<dyn MessageVerifier>>,
}

impl ProposalValidationRequestBuilder {
    pub fn new(request_id: RequestId, session_id: SessionId, signing_event: SigningEvent) -> Self {
        Self { request_id: Some(request_id), session_id: Some(session_id), signing_event: Some(signing_event), ..Default::default() }
    }

    pub fn expected_group_id(mut self, expected_group_id: Hash32) -> Self {
        self.expected_group_id = Some(expected_group_id);
        self
    }

    pub fn proposal_group_id(mut self, proposal_group_id: Hash32) -> Self {
        self.proposal_group_id = Some(proposal_group_id);
        self
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
            expected_group_id: self.expected_group_id.ok_or_else(|| ThresholdError::Message("expected_group_id required".into()))?,
            proposal_group_id: self.proposal_group_id.ok_or_else(|| ThresholdError::Message("proposal_group_id required".into()))?,
            expected_event_hash: self
                .expected_event_hash
                .ok_or_else(|| ThresholdError::Message("expected_event_hash required".into()))?,
            kpsbt_blob: self.kpsbt_blob.ok_or_else(|| ThresholdError::Message("kpsbt_blob required".into()))?,
            tx_template_hash: self.tx_template_hash.ok_or_else(|| ThresholdError::Message("tx_template_hash required".into()))?,
            expected_validation_hash: self
                .expected_validation_hash
                .ok_or_else(|| ThresholdError::Message("expected_validation_hash required".into()))?,
            coordinator_peer_id: self
                .coordinator_peer_id
                .ok_or_else(|| ThresholdError::Message("coordinator_peer_id required".into()))?,
            expires_at_nanos: self.expires_at_nanos.ok_or_else(|| ThresholdError::Message("expires_at_nanos required".into()))?,
            policy: self.policy,
            message_verifier: self.message_verifier,
        })
    }
}
