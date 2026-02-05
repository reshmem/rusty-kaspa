# Igra Documentation Index

**Created:** 2026-02-05
**Status:** Phase 1 - Core Structure Complete

---

## Documentation Organization Philosophy

This documentation is organized by **audience** rather than by topic, making it easy for each user type to find exactly what they need without wading through irrelevant information.

### Four Audience Segments

1. **Overview** (`overview/`) - For everyone
   - Product managers, stakeholders, general users
   - Non-technical introduction to Igra

2. **Operators** (`operators/`) - For system administrators and operators
   - DevOps engineers, sysadmins
   - Deployment, configuration, monitoring

3. **Developers** (`developers/`) - For software engineers
   - Contributors, integrators, auditors
   - Architecture, API, code guidelines

4. **DevOps** (`devops/`) - For infrastructure and security engineers
   - Infrastructure teams, security engineers, IT managers
   - Networking, security, operations

---

## Complete Documentation Map

### ✅ **COMPLETED** (Ready to use)

#### Overview Section (For Everyone)
```
overview/
├── ✅ 01-what-is-igra.md          # High-level introduction
├── ✅ 02-use-cases.md              # Real-world scenarios
├── ⏳ 03-how-it-works.md           # Non-technical explanation
└── ⏳ 04-faq.md                    # Common questions
```

#### Operators Section (For Sysadmins)
```
operators/
├── deployment/
│   ├── ✅ 01-quickstart-devnet.md      # 15-min local setup
│   ├── ⏳ 02-deployment-testnet.md     # Multi-machine testnet
│   └── ⏳ 03-deployment-mainnet.md     # Production deployment
│
├── configuration/
│   ├── ⏳ 01-configuration-overview.md # Config system intro
│   ├── ⏳ 02-network-modes.md          # Devnet/testnet/mainnet
│   ├── ⏳ 03-secrets-and-keys.md       # Key management
│   ├── ⏳ 04-hyperlane-config.md       # Hyperlane integration
│   └── ⏳ 05-advanced-configuration.md # Tuning, optimization
│
├── monitoring/
│   ├── ⏳ 01-monitoring-overview.md    # Observability intro
│   ├── ⏳ 02-metrics-reference.md      # Prometheus metrics
│   └── ⏳ 03-alerting.md               # Alert conditions
│
└── troubleshooting/
    ├── ⏳ 01-common-issues.md          # FAQ and quick fixes
    ├── ⏳ 02-debugging-guide.md        # Systematic debugging
    └── ⏳ 03-failure-scenarios.md      # Known failure modes
```

#### Developers Section (For Engineers)
```
developers/
├── architecture/
│   ├── ✅ 01-architecture-overview.md      # System design
│   ├── ⏳ 02-protocol-specification.md     # Formal protocol
│   ├── ⏳ 03-two-phase-coordination.md     # Two-phase details
│   ├── ⏳ 04-crdt-signing.md               # CRDT details
│   ├── ⏳ 05-utxo-coordination-problem.md  # Problem background
│   └── ⏳ 06-codebase-structure.md         # Code organization
│
├── api/
│   ├── ⏳ 01-api-overview.md               # API introduction
│   ├── ⏳ 02-rest-api.md                   # HTTP endpoints
│   ├── ⏳ 03-websocket-api.md              # WebSocket streams
│   └── ⏳ 04-client-libraries.md           # SDK reference
│
├── contributing/
│   ├── ⏳ 01-code-guidelines.md            # Coding standards
│   ├── ⏳ 02-development-setup.md          # Local dev env
│   ├── ⏳ 03-testing-guide.md              # Test strategy
│   ├── ⏳ 04-pull-request-process.md       # PR workflow
│   └── ⏳ 05-release-process.md            # Release procedure
│
└── design/
    ├── ⏳ 01-design-decisions.md           # ADRs
    ├── ⏳ 02-utxo-consolidation.md         # UTXO mgmt design
    └── ⏳ 03-future-enhancements.md        # Roadmap
```

#### DevOps Section (For Infrastructure)
```
devops/
├── infrastructure/
│   ├── ⏳ 01-requirements.md               # Hardware specs
│   ├── ⏳ 02-sizing-guide.md               # Capacity planning
│   └── ⏳ 03-cloud-deployment.md           # AWS/GCP/Azure
│
├── networking/
│   ├── ⏳ 01-networking-overview.md        # Network architecture
│   ├── ⏳ 02-iroh-p2p.md                   # P2P gossip details
│   ├── ⏳ 03-firewall-rules.md             # Ports and rules
│   └── ⏳ 04-discovery-bootstrap.md        # Peer discovery
│
├── security/
│   ├── ⏳ 01-security-overview.md          # Security model
│   ├── ⏳ 02-key-management.md             # Key lifecycle
│   ├── ⏳ 03-passphrase-rotation.md        # Rotation procedure
│   ├── ⏳ 04-timing-attacks.md             # Crypto security
│   └── ⏳ 05-audit-compliance.md           # SOC2, audits
│
└── operations/
    ├── ⏳ 01-operations-runbook.md         # Day-to-day ops
    ├── ⏳ 02-disaster-recovery.md          # DR procedures
    ├── ⏳ 03-backup-procedures.md          # Backup strategy
    └── ⏳ 04-upgrade-procedures.md         # Rolling upgrades
```

---

## Legend

- ✅ **Completed** - Document written and ready for use
- ⏳ **Planned** - Structure defined, content TBD
- 🚧 **In Progress** - Currently being written
- ❌ **Deprecated** - Old content, being replaced

---

## Completion Status

### Phase 1: Core Structure ✅ COMPLETE
**Goal:** Create documentation framework and essential starter docs

**Completed:**
- [x] Documentation organization philosophy
- [x] README.md (main index with audience navigation)
- [x] INDEX.md (this file - comprehensive map)
- [x] overview/01-what-is-igra.md (core introduction)
- [x] overview/02-use-cases.md (8 real-world scenarios)
- [x] operators/deployment/01-quickstart-devnet.md (15-min setup)
- [x] developers/architecture/01-architecture-overview.md (system design)

**Deliverables:**
- 7 completed documents
- 45 planned document placeholders
- Clear audience segmentation
- Navigation paths for each user type

---

### Phase 2: Operators Documentation 🚧 NEXT
**Goal:** Complete all operator-facing documentation

**Priority Documents:**
1. `operators/configuration/01-configuration-overview.md`
2. `operators/configuration/02-network-modes.md`
3. `operators/configuration/03-secrets-and-keys.md`
4. `operators/troubleshooting/01-common-issues.md`
5. `operators/deployment/02-deployment-testnet.md`
6. `operators/deployment/03-deployment-mainnet.md`

**Estimated Effort:** 2-3 days

---

### Phase 3: Developer Documentation ⏳ PLANNED
**Goal:** Complete all developer-facing documentation

**Priority Documents:**
1. `developers/architecture/02-protocol-specification.md` (port from Igra-Protocol.md)
2. `developers/contributing/01-code-guidelines.md` (port from CODE-GUIDELINE.md)
3. `developers/api/02-rest-api.md` (document all endpoints)
4. `developers/architecture/03-two-phase-coordination.md`
5. `developers/architecture/04-crdt-signing.md`

**Estimated Effort:** 3-4 days

---

### Phase 4: DevOps Documentation ⏳ PLANNED
**Goal:** Complete all infrastructure and security documentation

**Priority Documents:**
1. `devops/security/01-security-overview.md`
2. `devops/security/02-key-management.md`
3. `devops/networking/01-networking-overview.md`
4. `devops/operations/01-operations-runbook.md`
5. `devops/infrastructure/01-requirements.md`

**Estimated Effort:** 2-3 days

---

### Phase 5: Polish & Integration ⏳ PLANNED
**Goal:** Complete remaining documents and ensure consistency

**Tasks:**
- Fill all ⏳ placeholders
- Cross-link related documents
- Add diagrams and visuals
- Copy-edit for consistency
- User testing with each audience

**Estimated Effort:** 2-3 days

---

## Source Materials Used

This new documentation consolidates and reorganizes content from:

### Existing Documentation (in `docs/`)
- `Igra-Protocol.md` - Formal protocol specification (67KB)
- `CODE-GUIDELINE.md` - Coding standards (123KB)
- `README-DOCS.md` - Original documentation index
- `docs/configuration-reference.md` - Config file reference
- `docs/quickstart-devnet.md` - Original quickstart
- `docs/secrets-and-keys.md` - Key management basics
- `docs/wip/Automatic-Utxo-Consolidation.md` - UTXO consolidation design

### Codebase Exploration
- **igra-core/src/** - Core implementation
  - application/ - Event processing, two-phase, CRDT
  - domain/ - Models, PSKT building, coordination
  - foundation/ - Types, errors, constants
  - infrastructure/ - RPC, storage, transport

- **igra-service/src/** - Service layer
  - api/ - REST API handlers
  - service/ - Coordination loops, timeout handling
  - transport/ - Iroh gossip integration

---

## Documentation Standards

### File Naming Convention
```
[section]/[subsection]/[number]-[kebab-case-title].md

Examples:
- overview/01-what-is-igra.md
- operators/deployment/01-quickstart-devnet.md
- developers/architecture/03-two-phase-coordination.md
```

### Document Structure Template
```markdown
# Title

**Last Updated:** YYYY-MM-DD
**Audience:** [Target user type]
**Estimated Reading Time:** X minutes

---

## Overview
[Brief summary]

## [Main Content Sections]

---

## Next Steps
- Link to related document 1
- Link to related document 2

---

**Questions?** [Where to get help]
```

### Common Elements
- **Navigation aids** - "What you'll learn", "Prerequisites", "Next steps"
- **Visual hierarchy** - Clear headings, code blocks, tables, diagrams
- **Audience-appropriate depth** - Technical detail matched to reader
- **Actionable content** - Steps, commands, examples
- **Cross-references** - Links to related documentation

---

## Suggested Documentation Division

Based on the igra project analysis, here's why this structure makes sense:

### 1. **Overview** → General understanding
- **Why separate:** Everyone needs to start here regardless of role
- **Content focus:** What, why, when (not how)
- **Reading time:** 20-40 minutes total
- **Goal:** Decision-making (should we use Igra?)

### 2. **Operators** → Practical deployment
- **Why separate:** Operators don't need protocol theory or code internals
- **Content focus:** How to deploy, configure, monitor, troubleshoot
- **Reading time:** 2-4 hours for basic deployment
- **Goal:** Get Igra running safely and maintain it

### 3. **Developers** → Deep technical understanding
- **Why separate:** Engineers need protocol details and code structure
- **Content focus:** Why decisions were made, how protocol works, code organization
- **Reading time:** 8-12 hours for full comprehension
- **Goal:** Contribute code or integrate with Igra

### 4. **DevOps** → Infrastructure and security
- **Why separate:** Infrastructure concerns are distinct from development
- **Content focus:** Networking, security hardening, disaster recovery
- **Reading time:** 4-6 hours
- **Goal:** Run Igra securely at scale in production

---

## Migration from Old Docs

### What Stays in `docs/`
- `legacy/` - Historical development logs (keep for git history)
- `wip/` - Active design documents not yet implemented

### What Moves to `docs2/`
- ✅ Protocol specification → `developers/architecture/02-protocol-specification.md`
- ✅ Code guidelines → `developers/contributing/01-code-guidelines.md`
- ✅ Configuration reference → `operators/configuration/01-configuration-overview.md`
- ✅ Quickstart → `operators/deployment/01-quickstart-devnet.md`
- ✅ Security docs → `devops/security/`

### Deprecation Plan
Once `docs2/` is complete:
1. Add redirect notice to old `docs/README.md`
2. Update all repository references to point to `docs2/`
3. Archive old docs to `docs/archive/`
4. Rename `docs2/` → `docs/` (after backup)

---

## Success Metrics

### Documentation Quality Goals
- [ ] **Completeness:** All 52 planned documents written
- [ ] **Accuracy:** Technical review by 2+ core developers
- [ ] **Usability:** User testing with representative from each audience
- [ ] **Consistency:** Uniform style, tone, and formatting
- [ ] **Maintainability:** Last updated dates, clear ownership

### Audience-Specific Success Criteria

**Overview:**
- [ ] Non-technical stakeholders can explain what Igra does
- [ ] Product managers can identify applicable use cases

**Operators:**
- [ ] New operator can deploy devnet in <30 minutes
- [ ] Production deployment achieves <1% error rate

**Developers:**
- [ ] New contributor can submit first PR within 2 weeks
- [ ] Integration engineers can build client in <1 day

**DevOps:**
- [ ] Infrastructure team can scale to 100+ nodes
- [ ] Security team can complete compliance audit

---

## Contributing to Documentation

### Quick Edits
Small fixes (typos, broken links, clarifications):
1. Edit file directly
2. Commit with message: `docs: fix typo in [file]`
3. No PR required for trivial changes

### New Documents
Adding substantial content:
1. Check if placeholder exists in INDEX.md
2. Follow file naming convention
3. Use document structure template
4. Update INDEX.md completion status
5. Submit PR with `documentation` label

### Review Process
- **Technical accuracy:** Core developer review
- **Clarity:** User testing (if major section)
- **Consistency:** Check against existing docs

---

## Maintenance Schedule

### Regular Updates
- **Weekly:** Fix reported issues (typos, bugs in examples)
- **Monthly:** Update "Last Updated" dates, refresh screenshots
- **Per Release:** Update version numbers, deprecation notices
- **Quarterly:** User feedback review, gaps analysis

### Ownership
- **Overview:** Product/Community lead
- **Operators:** DevOps/SRE team
- **Developers:** Core engineering team
- **DevOps:** Infrastructure/Security team

---

## Roadmap

### Q1 2026 (Current)
- [x] Phase 1: Core structure (COMPLETE)
- [ ] Phase 2: Operators documentation (IN PROGRESS)
- [ ] Phase 3: Developers documentation

### Q2 2026
- [ ] Phase 4: DevOps documentation
- [ ] Phase 5: Polish & integration
- [ ] User testing with beta users
- [ ] Migration from old docs/

### Q3 2026
- [ ] Translate to additional languages (if needed)
- [ ] Video tutorials for key workflows
- [ ] Interactive examples/playground

---

## Contact & Support

### Documentation Issues
- **GitHub Issues:** [File documentation bug/request](https://github.com/kaspanet/rusty-kaspa/issues)
- **Tag:** `documentation` label

### Documentation Team
- **Owner:** TBD (assign core team member)
- **Contributors:** Open to community PRs
- **Reviewers:** Core developers

---

**Last Updated:** 2026-02-05
**Next Review:** 2026-02-12 (weekly during active development)
