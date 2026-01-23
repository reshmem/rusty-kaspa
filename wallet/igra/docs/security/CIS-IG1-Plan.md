# CIS Critical Security Controls v8 (IG1) Plan for Igra

This document defines a practical **CIS Controls v8 – Implementation Group 1 (IG1)** baseline for Igra.

It is intended to be our first “go-to” security program because it is:

- concrete and checklistable
- achievable for a small team
- easy to map to SOC 2 later (access controls, logging/monitoring, incident response, backups, change management)

This is not a formal CIS reproduction. Instead, it maps **IG1 intent** to our codebase and deployment reality.

---

## 0. Scope and assumptions

### In scope

- `igra-service` runtime (HTTP API, coordination, storage)
- `igra-core` library (crypto/signing logic, config loading, audit model)
- operational scripts under `orchestration/`
- production deployment environment requirements (network, secrets, backups, monitoring)

### Out of scope (for this baseline)

- Organization/HR controls (background checks, training, etc.)
- Full BFT/Byzantine security model changes
- Hardware security modules (HSM) and advanced key custody (future phase)

### Environment note

This repo includes devnet artifacts that contain keys (e.g. `orchestration/devnet/devnet-keys.json`). Those must be treated as **dev-only**, excluded from production scope, and ideally moved to templates.

---

## 1. Control mapping format

For each control area we capture:

- **Intent**: what IG1 expects us to achieve
- **Current evidence**: where we already do it (code/docs)
- **Gaps**: what’s missing for a credible baseline
- **Remediation**: concrete steps (code/config/runbook)
- **Acceptance criteria**: what “done” means

---

## 2. Control areas (IG1-aligned)

### A. Asset inventory (hardware/software/data flows)

**Intent**

- Know what signer nodes and services exist, where they run, and what version they run.
- Know which external dependencies are part of the system boundary (Kaspa node RPC, EVM RPC, Hyperlane agents, etc.).

**Current evidence**

- Devnet orchestration keeps an explicit process topology and PID files:
  - `orchestration/devnet/scripts/run_local_devnet.sh`
  - `orchestration/devnet/scripts/run_local_devnet_with_avail_and_hyperlane.sh`
- Architecture and service composition documented in:
  - `CODE-GUIDELINE.md`
  - `docs/SOC2.md`
  - `Observability.md`
  - `Igra-Obeserver.md`

**Gaps**

- No production-grade “inventory” artifact:
  - list of nodes, endpoints, owners, and deployed versions
- No standardized build/version stamp exposed by `igra-service`

**Remediation**

- Add a simple **inventory file** and keep it updated (initially manual):
  - `docs/security/INVENTORY.md` (hosts, roles, owners, environments)
- Add build metadata output:
  - Log `git_sha`, `crate_version`, and `build_time` at startup.
  - Optionally expose a read-only `GET /version` endpoint (auth-protected or internal-only).

**Acceptance criteria**

- Operators can answer, within minutes:
  - “Which signers are running in prod?”
  - “Which version is deployed?”
  - “Which RPC endpoints and domains are configured?”

---

### B. Secure configuration and hardening

**Intent**

- Services run with secure defaults, least privilege, and minimal exposure.

**Current evidence**

- Log rotation exists for file logging:
  - `igra-core/src/infrastructure/logging/mod.rs`
- Some file permission hygiene in devnet logs:
  - `orchestration/devnet/scripts/run_local_devnet.sh` (chmod 700 on log dir)

**Gaps**

- Auth can be effectively disabled if `rpc.token` is not set (open service risk).
- No enforcement of file permissions for config/keys.
- No documented production hardening checklist (firewall, user, systemd, etc.).

**Remediation**

- Introduce an explicit “deployment mode”:
  - `runtime.environment = dev|staging|prod` (or similar)
- In `prod`:
  - **fail startup** if `rpc.enabled=true` and no token is configured
  - **validate config file permissions** (warn in dev, fail in prod)
- Document a minimal “hardening checklist”:
  - run as non-root user
  - only bind to `127.0.0.1` or internal interface + reverse proxy
  - firewall restrict inbound to relayers/peer set

**Acceptance criteria**

- In `prod` mode, `igra-service` cannot start with an open RPC surface.
- Config files containing secrets are not group/world readable.

---

### C. Identity and access control (authn/z, least privilege)

**Intent**

- Strong authentication for administrative and signing actions.
- Least privilege (operators and services only get what they need).
- Ability to rotate/revoke credentials.

**Current evidence**

- Shared-token auth for RPC endpoints:
  - `igra-service/src/api/middleware/auth.rs`
- Token is redacted in request logging:
  - `igra-service/src/api/middleware/logging.rs`

**Gaps**

- No RBAC/roles: one token grants everything.
- No rotation/revocation mechanism (single long-lived secret).
- Auth failures are not recorded as structured audit events.

**Remediation**

- Add **RBAC**:
  - token → roles (`admin`, `signer`, `monitor`, `auditor`)
  - enforce per-route and per-RPC-method permissions
- Add **token rotation** support:
  - allow multiple active tokens
  - optional expiry timestamps and grace periods
  - reload tokens from file (or SIGHUP) without restart
- Add structured audit events for:
  - auth failures (method, client_ip, request_id)
  - token used role decisions (optional, careful with secrecy)

**Acceptance criteria**

- `monitor` token can read `/health`, `/ready`, `/metrics`, and indexer endpoints, but cannot trigger signing.
- `signer` token can trigger signing but cannot access admin operations.
- There is a documented and tested procedure to rotate tokens with no downtime.

---

### D. Secrets and key management

**Intent**

- Secrets are not committed to source control for production.
- Keys are encrypted at rest and handled carefully in memory and logs.
- There is a defined key lifecycle: generation, storage, rotation (where applicable), recovery.

**Current evidence**

- HD mnemonics are encrypted at rest using XChaCha20Poly1305:
  - `igra-core/src/infrastructure/config/encryption.rs`
  - env var required: `KASPA_IGRA_WALLET_SECRET`
- In-memory secret bytes are zeroized for keypair wrapper:
  - `igra-core/src/foundation/hd.rs`
- Key management/security docs exist:
  - `docs/legacy/security/KEYS_MANAGEMENT.md`
  - `docs/legacy/security/THREAT_MODEL.md`

**Gaps**

- Devnet keys committed in repo (`orchestration/devnet/devnet-keys.json`).
- No policy or tooling for production key storage (vault/HSM is future, but we need a baseline).
- Not all operational logs are guaranteed secret-free (we warn about it in scripts).

**Remediation**

- Replace committed devnet secrets with templates:
  - keep `orchestration/devnet/devnet-keys.template.json` in repo
  - generate real devnet keys locally into ignored paths
- Document production secret handling:
  - where `KASPA_IGRA_WALLET_SECRET` lives
  - how mnemonics are provisioned and protected
  - which operators can access them
- Add “secret scanning” in CI (basic regex + allowlist) to prevent accidental commits.

**Acceptance criteria**

- No production private keys or mnemonics exist in git history for the production branch.
- A new environment can be bootstrapped using documented steps without ad-hoc key copying.

---

### E. Logging, monitoring, and auditability

**Intent**

- Logs support forensic investigation and operational troubleshooting.
- Audit events exist for security-sensitive actions.
- Monitoring detects incidents quickly.

**Current evidence**

- Prometheus metrics:
  - `igra-service/src/service/metrics.rs`
  - `igra-service/src/api/router.rs` (`/metrics`)
- Structured audit events + multiple sinks:
  - `igra-core/src/domain/audit/types.rs`
  - `igra-core/src/infrastructure/audit/mod.rs`
- Observability design:
  - `Observability.md`
  - `Igra-Obeserver.md`

**Gaps**

- Auth failures and HTTP rate-limit denials are not emitted as `AuditEvent`.
- Audit retention/integrity is not guaranteed (rotation is for general logs, not audit semantics).
- No defined alerting baseline for production.

**Remediation**

- Emit audit events for:
  - auth failures (RPC/REST)
  - rate limit exceeded (HTTP)
- Decide audit log retention target (e.g., 90 days hot + archive).
- Add an optional tamper-evidence mode:
  - signed audit lines (HMAC) or hash-chained records (operator-controlled key)
- Define minimal alerts:
  - signer down/unready
  - high auth failure rate
  - delivery stuck/backlog
  - high tx submission failure rate
  - unexpected policy reject spike

**Acceptance criteria**

- Operators can answer: “who triggered signing?” and “what was signed?” from logs alone.
- Audit logs are retained and searchable for a defined period.
- Alerts fire on availability and security anomalies.

---

### F. Network security (segmentation + encryption in transit)

**Intent**

- Expose only necessary services.
- Encrypt and authenticate traffic in transit for production.

**Current evidence**

- Token-based auth exists, and sensitive headers are redacted from logs.

**Gaps**

- HTTP is plaintext by default (no TLS at the service).
- No mTLS story for signer-to-signer/relayer-to-signer traffic.

**Remediation**

- Production deployment pattern:
  - run `igra-service` behind a reverse proxy (TLS termination) or add TLS support directly
  - optionally require mTLS between relayers and signers
- Document allowed inbound/outbound connections:
  - to Kaspa node RPC
  - to EVM RPC (if applicable)
  - to peer transport (iroh)

**Acceptance criteria**

- Production traffic carrying credentials is protected by TLS (at least at the edge).
- Network ACLs restrict ingress to expected peer sets.

---

### G. Backup and recovery

**Intent**

- Backups exist for critical state and are regularly tested.
- Recovery procedure is documented and works.

**Current evidence**

- Storage is RocksDB; devnet scripts manage data under a root dir.

**Gaps**

- No backup policy for:
  - configuration
  - encrypted key material
  - RocksDB state (if needed for faster recovery)
- No restore drill documentation.

**Remediation**

- Write a recovery runbook:
  - `docs/security/RUNBOOK-RECOVERY.md`
- Define backup targets:
  - config dir (without raw secrets if externalized)
  - encrypted mnemonic blobs + required env secrets stored separately (vault)
  - optional periodic RocksDB snapshots
- Define and execute restore drills on a schedule.

**Acceptance criteria**

- A new node can be provisioned and join the signer set using documented steps.
- Restore is tested at least quarterly (or per release early on).

---

### H. Incident response

**Intent**

- Clear procedure for detection, triage, containment, eradication, recovery, and lessons learned.

**Current evidence**

- Some threat modeling and security documents exist:
  - `docs/legacy/security/THREAT_MODEL.md`
  - `docs/legacy/security/SECURITY_AUDIT.md`

**Gaps**

- No concrete incident response runbook tied to our actual components.
- No severity definition and escalation policy.

**Remediation**

- Add:
  - `docs/security/RUNBOOK-INCIDENT-RESPONSE.md`
  - `docs/security/INCIDENT-TEMPLATE.md`
- Define:
  - severity levels (SEV0–SEV3)
  - triggers (auth anomaly, unexpected signing outputs, validator mismatch, stuck deliveries)
  - containment steps (disable RPC, rotate tokens, pause signing, isolate host)

**Acceptance criteria**

- A new engineer can follow the runbook to:
  - identify impact
  - preserve evidence
  - contain blast radius
  - restore service safely

---

### I. Secure development and change management

**Intent**

- Changes are reviewed, tested, and traceable.
- Dependencies are controlled.

**Current evidence**

- Engineering standards exist:
  - `CODE-GUIDELINE.md`
- Structured error guidance reduces operational ambiguity.

**Gaps**

- No explicit policy for:
  - dependency vulnerability scanning in CI
  - signed releases / provenance
  - required review/test gates

**Remediation**

- CI baseline:
  - `cargo fmt --all`
  - `cargo clippy --workspace --tests --benches`
  - `cargo test --workspace`
  - `cargo audit` (or equivalent)
- Release baseline (later):
  - produce build metadata and SBOM
  - sign artifacts

**Acceptance criteria**

- Every production change is reviewable and reproducible.
- Known critical dependency vulnerabilities are caught before release.

---

## 3. Minimal “first implementation” checklist (recommended order)

This ordering optimizes for real risk reduction early:

1) **Secure-by-default RPC**: prod mode requires auth + config permission checks.
2) **RBAC**: separate monitor vs signer vs admin access.
3) **Audit gaps**: auth failures + rate-limit exceeded emitted as audit events.
4) **Secret hygiene**: remove committed secrets; add secret scanning guardrails.
5) **Backups + runbooks**: recovery and incident response documentation.
6) **Monitoring**: dashboards + basic alerts (availability + security anomalies).

---

## 4. Evidence artifacts we should maintain

These are small but high-value “audit-ready” artifacts:

- `docs/security/INVENTORY.md`
- `docs/security/RUNBOOK-RECOVERY.md`
- `docs/security/RUNBOOK-INCIDENT-RESPONSE.md`
- `docs/security/ACCESS-CONTROL.md` (RBAC roles, token rotation)
- `docs/security/BACKUP-POLICY.md`
- `docs/security/CHANGE-MANAGEMENT.md` (CI gates, release procedure)

---

## 5. Notes on mapping to SOC 2 later

Implementing the above yields straightforward SOC 2 evidence:

- Access control (RBAC + token rotation) → CC6.*
- Logging/monitoring/audit retention → CC7.*
- Backup/recovery runbooks → CC7.4/Availability
- Change management / CI gates → CC8.*
- Encryption and key management → CC6.7, confidentiality (when applicable)

