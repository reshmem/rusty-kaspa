# Documentation Refactoring Plan - mdBook Migration

**Date:** 2026-01-24
**Current State:** `docs/` is categorized and `book/` exists
**Goal:** Maintain and expand mdBook documentation site
**Estimated Effort:** 2-3 days initial setup + ongoing maintenance

---

## 📋 Related Documentation

**Read in this order:**

1. **This file** (docs/dev/documentation-refactoring-plan.md) - Setup and migration guide
2. **docs/dev/documentation-naming-conventions.md** - Naming standards and developer workflow
3. **docs/dev/documentation-guide.md** - Background and best practices

**For ongoing work:** Use docs/dev/documentation-naming-conventions.md as your team standard

---

## Current Documentation Inventory

### Root Level (Core Files)

```
/Users/user/Source/personal/rusty-kaspa/wallet/igra/
├── AGENTS.md                        # Internal (keep as-is)
├── CODE-GUIDELINE.md                # → Developer guide
└── Igra-Protocol.md                 # → Protocol architecture
```

**Status:** Clean root, minimal files ✅

---

### book/ Directory (mdBook Source)

`book/` is the mdBook source tree (the rendered HTML output is under `book/book/` and is ignored).

---

### docs/ Directory (Active Files)

**Current organization:**

```
docs/
├── config/                          # Network modes, Iroh, Hyperlane
├── dev/                             # Contributor and internal docs (incl. these guides)
├── guide/                           # Quickstart, key derivation
├── ops/                             # Deployment and monitoring
├── protocol/                        # Protocol docs + design decisions
├── security/                        # Security docs + audits
├── wip/                             # Drafts and future designs
└── legacy/                          # Historical (100+ files)
    ├── api/
    ├── architecture/
    ├── security/
    ├── service/
    ├── specs/
    ├── testing/
    └── ... (keep as archive, don't migrate)
```

---

## Documentation Categorization

### Category 1: Getting Started (3 files)

**Files:**
- `docs/guide/quickstart.md` - Quickstart tutorial
- `docs/guide/key-derivation.md` - Key derivation guide
- (NEW) - Installation guide needed

**Priority:** 🔴 **CRITICAL** - Users need this first

**mdBook location:**
```
book/src/getting-started/
├── README.md
├── installation.md (NEW - write this)
├── quickstart.md (from docs/guide/quickstart.md)
└── key-derivation.md (from docs/guide/key-derivation.md)
```

---

### Category 2: Configuration (8 files)

**Files:**
- `docs/config/network-modes.md` - Network mode validation ⭐
- `docs/config/network-modes-verification.md` - Verification report
- `docs/config/network-modes-gaps.md` - Gap analysis
- `docs/config/iroh-discovery.md` - P2P discovery ⭐
- `docs/config/iroh-discovery-review.md` - Review
- `docs/config/iroh-discovery-gaps.md` - Gaps
- `docs/config/iroh-discovery-summary.md` - Summary
- `docs/config/hyperlane.md` - Bridge config ⭐

**Priority:** 🔴 **CRITICAL** - Users need to configure correctly

**mdBook location:**
```
book/src/configuration/
├── README.md (NEW - configuration overview)
├── network-modes.md (from docs/config/network-modes.md) ⭐
├── iroh-p2p.md (from docs/config/iroh-discovery.md) ⭐
├── hyperlane.md (from docs/config/hyperlane.md) ⭐
└── advanced/
    ├── network-mode-verification.md (reference)
    └── iroh-discovery-details.md (reference)
```

**Note:** Keep ⭐ files, use other files as reference/appendix

---

### Category 3: Security (13 files) 🔒

**Files:**
- `docs/security/timing-attacks.md` - Complete analysis ⭐⭐⭐
- `docs/security/timing-attacks-overview.md` - Navigation
- `docs/security/timing-attacks-quick-fix.md` - Quick reference
- `docs/security/timing-attacks-checklist.md` - Tracking
- `docs/security/timing-attacks-library-proof.md` - Library proof
- `docs/security/key-management-audit.md` - Key management audit ⭐⭐
- `docs/security/key-management-extended-audit.md` - Extended audit
- `docs/security/key-management-diagrams.md` - Diagrams
- `docs/security/security-issues-remediation.md` - Security fixes
- `docs/security/security-quick-check.md` - Quick security check
- `docs/security/audits/audit-v1.md` - Audit report(s)
- `docs/security/soc2-compliance.md` - Compliance guide ⭐
- `docs/security/cis-ig1-plan.md` - CIS compliance

**Priority:** 🔴 **CRITICAL** - Security is paramount

**mdBook location:**
```
book/src/security/
├── README.md (NEW - security overview)
├── threat-model.md (extract from multiple docs)
├── cryptography/
│   ├── timing-attacks.md (from docs/security/timing-attacks.md) ⭐⭐⭐
│   ├── library-security.md (from docs/security/timing-attacks-library-proof.md)
│   └── implementation-guide.md (from docs/security/timing-attacks-quick-fix.md)
├── key-management/
│   ├── overview.md (from docs/security/key-management-audit.md) ⭐⭐
│   ├── audit-findings.md (from docs/security/key-management-extended-audit.md)
│   └── diagrams.md (from docs/security/key-management-diagrams.md)
├── network-security.md (from docs/config/network-modes.md)
├── compliance/
│   ├── soc2.md (from docs/security/soc2-compliance.md) ⭐
│   └── cis.md (from docs/security/cis-ig1-plan.md)
├── audit-reports.md (from docs/security/audits/audit-v1.md)
└── best-practices.md (NEW - security checklist)
```

---

### Category 4: Protocol Design (11 files)

**Files:**
- `Igra-Protocol.md` - Main architecture ⭐⭐⭐
- `docs/protocol/two-phase-consensus.md` - Two-phase consensus ⭐⭐⭐
- `docs/protocol/two-phase-implementation.md` - Implementation guide
- `docs/protocol/two-phase-review.md` - Expert review
- `docs/protocol/two-phase-algo-v1.md` - Algorithm v1
- `docs/protocol/two-phase-algo-current.md` - Current algorithm
- `docs/protocol/design-decisions/utxo-consensus-problem.md` - UTXO consensus issue
- `docs/protocol/anti-entropy.md` - Anti-entropy protocol
- `docs/protocol/design-decisions/failure-modes.md` - Failure analysis
- `docs/protocol/design-decisions/privacy-analysis.md` - Privacy analysis
- `docs/protocol/design-decisions/event-id-design.md` - Event ID design

**Priority:** 🟡 **IMPORTANT** - For developers and auditors

**mdBook location:**
```
book/src/protocol/
├── README.md (NEW - protocol overview)
├── architecture.md (from Igra-Protocol.md) ⭐⭐⭐
├── two-phase-consensus/
│   ├── overview.md (from docs/protocol/two-phase-consensus.md) ⭐⭐⭐
│   ├── implementation.md (from docs/protocol/two-phase-implementation.md)
│   └── expert-review.md (from docs/protocol/two-phase-review.md)
├── crdt-gossip.md (extract from Igra-Protocol.md)
├── pskt.md (extract from Igra-Protocol.md)
├── anti-entropy.md (from docs/protocol/anti-entropy.md)
├── failure-modes.md (from docs/protocol/design-decisions/failure-modes.md)
└── design-decisions/
    ├── utxo-consensus.md (from docs/protocol/design-decisions/utxo-consensus-problem.md)
    └── privacy.md (from docs/protocol/design-decisions/privacy-analysis.md)
```

---

### Category 5: Developer Guides (11 files)

**Files:**
- `CODE-GUIDELINE.md` (root) - Code standards ⭐⭐⭐
- `docs/dev/code-quality-audit.md` - Quality audit
- `docs/dev/code-quality-report.md` - Progress tracking
- `docs/dev/refactoring-audit-2026.md` - Refactoring audit
- `docs/dev/refactoring-todos.md` - TODO tracking
- `docs/dev/refactor-general.md` - Refactoring guide
- `docs/dev/hex-encoding-refactor.md` - Hex refactor
- `docs/dev/hex-refactor.md` - Hex refactor details
- `docs/dev/hex-refactor-completion.md` - Completion report
- `docs/dev/followup-todos.md` - Follow-up items
- `docs/dev/todo-fixes.md` - General TODOs

**Priority:** 🟡 **IMPORTANT** - For contributors

**mdBook location:**
```
book/src/developer/
├── README.md (NEW - developer guide intro)
├── code-guidelines.md (from CODE-GUIDELINE.md) ⭐⭐⭐
├── architecture.md (extract from Igra-Protocol.md)
├── building.md (NEW - build instructions)
├── testing.md (NEW - testing guide)
├── contributing.md (NEW - contribution guide)
└── reference/
    ├── code-quality.md (from docs/dev/code-quality-audit.md)
    └── refactoring-history.md (from docs/dev/refactoring-audit-2026.md)
```

**Note:** Keep TODO/progress files as-is (working documents, not published docs)

---

### Category 6: Operations (4 files)

**Files:**
- `docs/ops/deployment-devnet.md` - Devnet setup
- `docs/ops/monitoring.md` - Monitoring
- `docs/ops/observer-setup.md` - Observer setup
- `docs/guide/key-derivation.md` - Key derivation (could also be getting-started)

**Priority:** 🟢 **NICE TO HAVE** - For operators

**mdBook location:**
```
book/src/operations/
├── README.md (NEW - operations overview)
├── deployment/
│   ├── devnet.md (from docs/ops/deployment-devnet.md)
│   ├── testnet.md (NEW - from orchestration/testnet/)
│   └── mainnet.md (NEW - write this)
├── monitoring.md (from docs/ops/monitoring.md)
└── troubleshooting.md (NEW - compile from common issues)
```

---

### Category 7: Advanced Topics (4 files)

**Files:**
- `docs/wip/v2-*.md` - Future design (3 files)
- `docs/security/key-manager-design.md` - KeyManager design
- `docs/security/key-management-refactor.md` - Refactoring plan
- `docs/security/key-management-todos.md` - TODOs
- `docs/security/raw-privkey-feature.md` - RawPrivKey feature

**Priority:** 🟢 **OPTIONAL** - Future features

**mdBook location:**
```
book/src/advanced/
├── README.md (NEW - advanced topics intro)
├── frost-integration.md (future)
├── hsm-support.md (future)
└── design-notes/
    └── v2-design.md (from docs/wip/v2-design.md)
```

---

### Category 8: Reference/Archive (Keep Separate)

**Files:**
- `docs/legacy/` - Historical (100+ files) - **KEEP AS ARCHIVE**
- `docs/security/audits/audit-v1.md` - Audit report (keep for reference)
- `docs/dev/crdt-gossip-fixes.md` - Historical fix log

**Action:** Don't migrate to book, keep in git for historical reference

**Add to book:**
```markdown
## Historical Documentation

For historical development logs, refactoring steps, and archived documentation,
see the [`docs/legacy/`](https://github.com/kaspanet/rusty-kaspa/tree/master/wallet/igra/docs/legacy) directory.
```

---

## Recommended mdBook Structure (Based on Current Files)

### Proposed SUMMARY.md

```markdown
# Summary

[Introduction](intro.md)

---

# Getting Started

- [What is Igra?](getting-started/what-is-igra.md)
- [Installation](getting-started/installation.md)
- [Quick Start Tutorial](getting-started/quickstart.md)
  - [Key Derivation](getting-started/key-derivation.md)

---

# Configuration

- [Configuration Overview](configuration/README.md)
- [Network Modes](configuration/network-modes.md)
  - [Mainnet Security](configuration/mainnet-security.md)
  - [Testnet Configuration](configuration/testnet.md)
  - [Devnet Configuration](configuration/devnet.md)
- [Iroh P2P Discovery](configuration/iroh-discovery.md)
- [Hyperlane Bridge](configuration/hyperlane.md)
- [Secret Management](configuration/secrets.md)

---

# Protocol Design

- [Architecture Overview](protocol/architecture.md)
- [Two-Phase Consensus](protocol/two-phase/README.md)
  - [Algorithm Specification](protocol/two-phase/algorithm.md)
  - [Implementation Guide](protocol/two-phase/implementation.md)
  - [Expert Review](protocol/two-phase/expert-review.md)
- [CRDT State Synchronization](protocol/crdt-gossip.md)
- [PSKT (Partially Signed Kaspa Transactions)](protocol/pskt.md)
- [Anti-Entropy Protocol](protocol/anti-entropy.md)
- [Design Decisions](protocol/design-decisions/README.md)
  - [UTXO Consensus](protocol/design-decisions/utxo-consensus.md)
  - [Privacy Considerations](protocol/design-decisions/privacy.md)
  - [Failure Modes](protocol/design-decisions/failure-modes.md)

---

# Security

- [Security Overview](security/README.md)
- [Threat Model](security/threat-model.md)
- [Cryptography](security/cryptography/README.md)
  - [Timing Attack Analysis](security/cryptography/timing-attacks.md)
  - [Library Security Proof](security/cryptography/library-security.md)
  - [Side-Channel Resistance](security/cryptography/side-channels.md)
  - [Implementation Checklist](security/cryptography/implementation-checklist.md)
- [Key Management](security/key-management/README.md)
  - [Audit Findings](security/key-management/audit.md)
  - [Best Practices](security/key-management/best-practices.md)
  - [Key Storage](security/key-management/storage.md)
- [Network Security](security/network-security.md)
- [Compliance](security/compliance/README.md)
  - [SOC2](security/compliance/soc2.md)
  - [CIS IG1](security/compliance/cis-ig1.md)
- [Audit Reports](security/audit-reports.md)
- [Responsible Disclosure](security/disclosure.md)

---

# Developer Guide

- [Development Setup](developer/setup.md)
- [Building from Source](developer/building.md)
- [Code Guidelines](developer/code-guidelines.md)
- [Architecture Deep Dive](developer/architecture.md)
  - [Domain Layer](developer/domain.md)
  - [Application Layer](developer/application.md)
  - [Infrastructure Layer](developer/infrastructure.md)
- [Testing Guide](developer/testing.md)
- [Contributing](developer/contributing.md)
- [Code Quality](developer/code-quality.md)

---

# Operations

- [Deployment Guide](operations/deployment/README.md)
  - [Devnet Setup](operations/deployment/devnet.md)
  - [Testnet Setup](operations/deployment/testnet.md)
  - [Mainnet Setup](operations/deployment/mainnet.md)
- [Monitoring & Observability](operations/monitoring.md)
- [Logging](operations/logging.md)
- [Troubleshooting](operations/troubleshooting.md)
- [Backup & Recovery](operations/backup.md)

---

# Advanced Topics

- [FROST MPC Integration](advanced/frost.md)
- [HSM Support](advanced/hsm.md)
- [Performance Tuning](advanced/performance.md)
- [V2 Design](advanced/v2-design.md)

---

# Appendix

- [Glossary](appendix/glossary.md)
- [FAQ](appendix/faq.md)
- [Changelog](appendix/changelog.md)
- [References](appendix/references.md)
- [Legacy Documentation](appendix/legacy.md)
```

---

## Migration Strategy

### Phase 1: Bootstrap (Day 1 - 4 hours)

**Goal:** Get basic mdBook structure working and deployed

#### Step 1: Install Tools (10 minutes)

```bash
# Install mdBook and plugins
cargo install mdbook
cargo install mdbook-toc
cargo install mdbook-mermaid
cargo install mdbook-linkcheck

# Verify
mdbook --version
```

---

#### Step 2: Initialize Structure (15 minutes)

```bash
cd /Users/user/Source/personal/rusty-kaspa/wallet/igra

# Create book directory
mkdir book
cd book

# Initialize
mdbook init

# Answer prompts:
# Title: Igra Threshold Signing Documentation
# Authors: Igra Core Team
# Create .gitignore: Yes
```

If `book/` already exists in the repo, you can skip initialization and jump to Step 7 (`mdbook build` / `mdbook serve`).

---

#### Step 3: Configure book.toml (15 minutes)

**File:** `book/book.toml`

**Replace contents with:**

```toml
[book]
title = "Igra Threshold Signing Documentation"
description = "Distributed threshold signature coordination for Kaspa blockchain"
authors = ["Igra Core Team"]
language = "en"
multilingual = false
src = "src"

[build]
build-dir = "book"
create-missing = true

[output.html]
default-theme = "rust"
preferred-dark-theme = "navy"
git-repository-url = "https://github.com/kaspanet/rusty-kaspa"
git-repository-icon = "fa-github"
edit-url-template = "https://github.com/kaspanet/rusty-kaspa/edit/master/wallet/igra/book/src/{path}"
site-url = "/rusty-kaspa/igra/"

[output.html.search]
enable = true
limit-results = 30
use-boolean-and = true
boost-title = 2
boost-hierarchy = 1
boost-paragraph = 1
expand = true

[output.html.code]
theme = "ayu"

[output.html.fold]
enable = true
level = 2

[output.html.print]
enable = true

[preprocessor.toc]
command = "mdbook-toc"
renderer = ["html"]

[preprocessor.mermaid]
command = "mdbook-mermaid"
```

---

#### Step 4: Create Minimal SUMMARY.md (30 minutes)

**File:** `book/src/SUMMARY.md`

**Replace with minimal version to start:**

```markdown
# Summary

[Introduction](intro.md)

---

# Getting Started

- [Installation](getting-started/installation.md)
- [Quick Start](getting-started/quickstart.md)

---

# Configuration

- [Network Modes](configuration/network-modes.md)
- [Iroh P2P Discovery](configuration/iroh-discovery.md)
- [Hyperlane Bridge](configuration/hyperlane.md)

---

# Security

- [Security Overview](security/README.md)
- [Timing Attack Analysis](security/timing-attacks.md)
- [Key Management](security/key-management.md)
- [Network Security](security/network-security.md)

---

# Protocol

- [Architecture](protocol/architecture.md)
- [Two-Phase Consensus](protocol/two-phase.md)

---

# Developer

- [Code Guidelines](developer/code-guidelines.md)
- [Building from Source](developer/building.md)

---

# Appendix

- [Glossary](appendix/glossary.md)
- [FAQ](appendix/faq.md)
```

---

#### Step 5: Create Initial Content (2 hours)

**Create these files (minimal versions):**

**File:** `book/src/intro.md`

```markdown
# Igra Threshold Signing Documentation

Welcome to the Igra documentation!

> **🔒 Security Notice:** Igra handles threshold signatures for Kaspa blockchain.
> Misconfiguration can lead to loss of funds. Read the [Security Guide](security/README.md)
> before production deployment.

## What is Igra?

Igra is a distributed threshold signature coordination system for Kaspa blockchain.
It enables multiple parties to collaboratively sign transactions using M-of-N
threshold cryptography, without any single party holding the complete private key.

## Key Features

- **Threshold Signatures:** Configurable M-of-N quorum (2-of-3, 3-of-5, etc.)
- **Byzantine Tolerance:** CRDT-based state synchronization
- **Two-Phase Consensus:** Prevents UTXO selection divergence
- **Production Security:** Mainnet-grade validation (network modes)
- **Cross-Chain Bridge:** Hyperlane integration (Kaspa ↔ EVM)
- **P2P Discovery:** Pkarr DHT, relay support (NAT traversal)

## Quick Links

- 🚀 [Get Started](getting-started/installation.md) - Install and run your first node
- 🔧 [Configuration](configuration/network-modes.md) - Network modes and settings
- 🔒 [Security](security/README.md) - Threat model, cryptography, best practices
- 📖 [Protocol](protocol/architecture.md) - How Igra works internally
- 👨‍💻 [Developer](developer/code-guidelines.md) - Contributing to Igra

## Documentation Sections

1. **Getting Started** - Installation, quick start tutorial
2. **Configuration** - Network modes, Iroh P2P, Hyperlane, secrets
3. **Security** - Timing attacks, key management, compliance, audits
4. **Protocol** - Architecture, two-phase consensus, CRDT, PSKT
5. **Developer** - Code guidelines, building, contributing
6. **Operations** - Deployment, monitoring, troubleshooting
7. **Appendix** - Glossary, FAQ, changelog

## Version Information

- **Current Version:** 0.5.0 (adjust as needed)
- **Rust Version:** 1.75+
- **Last Updated:** 2026-01-24

## Support

- **Issues:** [GitHub Issues](https://github.com/kaspanet/rusty-kaspa/issues)
- **Security:** security@kaspa.org (adjust as needed)
- **Discord:** [Kaspa Discord](https://discord.gg/kaspa) (adjust as needed)

---

**Ready to get started?** → [Installation Guide](getting-started/installation.md)
```

---

**File:** `book/src/getting-started/installation.md`

```markdown
# Installation

## Prerequisites

- **Rust:** 1.75 or later (`rustc --version`)
- **Kaspa Node:** Local kaspad instance
- **OS:** Linux (recommended), macOS, or Windows
- **RAM:** 2 GB minimum
- **Disk:** 10 GB minimum (mainnet)

## Install from Source

\`\`\`bash
# Clone rusty-kaspa repository
git clone https://github.com/kaspanet/rusty-kaspa.git
cd rusty-kaspa/wallet/igra

# Build release binary
cargo build --release --bin kaspa-threshold-service

# Verify installation
./target/release/kaspa-threshold-service --version
# Expected: kaspa-threshold-service 0.5.0
\`\`\`

## Directory Structure

After building, you'll have:

\`\`\`
rusty-kaspa/wallet/igra/
├── target/release/
│   └── kaspa-threshold-service    # Main binary
├── igra-core/                     # Core library
├── igra-service/                  # Service runtime
└── book/                          # This documentation
\`\`\`

## Next Steps

- [Quick Start Tutorial](quickstart.md) - Run your first signing
- [Configuration Guide](../configuration/network-modes.md) - Set up for your network
- [Security Best Practices](../security/README.md) - Before production

## Troubleshooting

**Build fails with "rustc version too old":**
\`\`\`bash
rustup update stable
\`\`\`

**Build fails with missing dependencies:**
\`\`\`bash
# On Ubuntu/Debian
sudo apt-get install build-essential pkg-config libssl-dev

# On macOS
xcode-select --install
\`\`\`
```

---

**Create directory structure:**

```bash
cd book/src

# Create directories
mkdir -p getting-started
mkdir -p configuration
mkdir -p security/{cryptography,key-management,compliance}
mkdir -p protocol/{two-phase,design-decisions}
mkdir -p developer/reference
mkdir -p operations/deployment
mkdir -p advanced/design-notes
mkdir -p appendix

# Create placeholder README files
touch getting-started/quickstart.md
touch configuration/{network-modes.md,iroh-discovery.md,hyperlane.md}
touch security/README.md
touch protocol/{architecture.md,two-phase.md}
touch developer/code-guidelines.md
touch developer/building.md
touch appendix/{glossary.md,faq.md}
```

---

#### Step 6: Copy Key Documentation (1 hour)

**Copy your best docs (start with these 8):**

```bash
cd /Users/user/Source/personal/rusty-kaspa/wallet/igra/book/src

# 1. Configuration docs (already excellent)
cp ../../docs/config/network-modes.md configuration/network-modes.md
cp ../../docs/config/iroh-discovery.md configuration/iroh-discovery.md
cp ../../docs/config/hyperlane.md configuration/hyperlane.md

# 2. Security docs (comprehensive)
cp ../../docs/security/timing-attacks.md security/cryptography/timing-attacks.md
cp ../../docs/security/timing-attacks-library-proof.md security/cryptography/library-security.md
cp ../../docs/security/key-management-audit.md security/key-management/audit.md
cp ../../docs/security/soc2-compliance.md security/compliance/soc2.md

# 3. Protocol docs
cp ../../Igra-Protocol.md protocol/architecture.md
cp ../../docs/protocol/two-phase-consensus.md protocol/two-phase.md

# 4. Developer docs
cp ../../CODE-GUIDELINE.md developer/code-guidelines.md

# 5. Getting started
cp ../../docs/guide/quickstart.md getting-started/quickstart.md
```

**Light editing needed:**
- Update internal links (adjust paths for new location)
- Add breadcrumb navigation
- Standardize headers

---

#### Step 7: Build and Test (10 minutes)

```bash
cd /Users/user/Source/personal/rusty-kaspa/wallet/igra/book

# Build
mdbook build

# Preview locally
mdbook serve --open

# Opens http://localhost:3000
# Navigate and verify structure
```

**Expected:**
- ✅ Left sidebar shows table of contents
- ✅ Search box works
- ✅ Navigation works (chapter to chapter)
- ⚠️ Some broken links (fix incrementally)

---

#### Step 8: Deploy to GitHub Pages (30 minutes)

**File:** `.github/workflows/deploy-docs.yml` (create new)

```yaml
name: Deploy Documentation

on:
  push:
    branches: [master, devel]
    paths:
      - 'wallet/igra/book/**'
      - '.github/workflows/deploy-docs.yml'
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup mdBook
        uses: peaceiris/actions-mdbook@v1
        with:
          mdbook-version: '0.4.40'

      - name: Install mdBook plugins
        run: |
          cargo install mdbook-toc mdbook-mermaid mdbook-linkcheck || true

      - name: Build book
        run: |
          cd wallet/igra/book
          mdbook build

      - name: Upload artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: wallet/igra/book/book

  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
```

**Enable GitHub Pages:**
1. Go to repo Settings → Pages
2. Source: GitHub Actions
3. Save

**Commit and push:**
```bash
git add book/ .github/workflows/deploy-docs.yml
git commit -m "docs: initialize mdBook documentation structure"
git push
```

**Result:** Docs auto-deploy at https://[org].github.io/rusty-kaspa/ (wait 2-5 min for first deploy)

---

### Phase 2: Content Migration (Day 2 - 4 hours)

**Migrate remaining priority docs:**

#### Priority 1: Security (Complete Coverage)

```bash
cd book/src/security

# Copy all timing attack docs
cp ../../../docs/security/timing-attacks-quick-fix.md cryptography/quick-fix.md
cp ../../../docs/security/timing-attacks-checklist.md cryptography/implementation-checklist.md

	# Copy key management
	cp ../../../docs/security/key-management-extended-audit.md key-management/extended-audit.md
	cp ../../../docs/security/key-management-diagrams.md key-management/diagrams.md

# Copy compliance
cp ../../../docs/security/cis-ig1-plan.md compliance/cis-ig1.md

# Create security overview
cat > README.md << 'EOF'
# Security

Igra is a threshold signing system handling real funds. Security is paramount.

## Critical Security Documents

- [Timing Attack Analysis](cryptography/timing-attacks.md) ⚠️ **READ BEFORE MAINNET**
- [Key Management Audit](key-management/audit.md)
- [Network Security](network-security.md)

## Security Checklist

Before deploying to mainnet:
- [ ] Read [Timing Attack Analysis](cryptography/timing-attacks.md)
- [ ] Implement constant-time fixes
- [ ] Read [Network Mode Security](network-security.md)
- [ ] Configure network mode correctly
- [ ] Review [Key Management Best Practices](key-management/best-practices.md)
- [ ] Set up encrypted secrets file
- [ ] Enable audit logging

## Reporting Security Issues

See [Responsible Disclosure](disclosure.md) for how to report vulnerabilities.
EOF
```

---

#### Priority 2: Protocol (Technical Depth)

```bash
cd book/src/protocol

# Copy protocol docs
cp ../../../docs/protocol/anti-entropy.md anti-entropy.md
cp ../../../docs/protocol/design-decisions/failure-modes.md design-decisions/failure-modes.md
cp ../../../docs/protocol/design-decisions/utxo-consensus-problem.md design-decisions/utxo-consensus.md
cp ../../../docs/protocol/design-decisions/privacy-analysis.md design-decisions/privacy.md

# Two-phase protocol
mkdir -p two-phase
cp ../../../docs/protocol/two-phase-implementation.md two-phase/implementation.md
cp ../../../docs/protocol/two-phase-review.md two-phase/expert-review.md

# Extract CRDT and PSKT sections from Igra-Protocol.md
# (manual editing needed - split into separate files)
```

---

#### Priority 3: Developer Guide

```bash
cd book/src/developer

# Copy code quality docs
cp ../../../docs/dev/code-quality-audit.md reference/code-quality.md

# Create new files (write these):
cat > building.md << 'EOF'
# Building from Source

## Quick Build

\`\`\`bash
cd rusty-kaspa/wallet/igra
cargo build --release
\`\`\`

## Build Targets

**Main service:**
\`\`\`bash
cargo build --release --bin kaspa-threshold-service
\`\`\`

**Devnet tools:**
\`\`\`bash
cargo build --release --bin devnet-keygen
cargo build --release --bin devnet-balance
\`\`\`

## Development Build (faster, no optimizations)

\`\`\`bash
cargo build --bin kaspa-threshold-service
\`\`\`

## Run Tests

\`\`\`bash
# All tests
cargo test --workspace --all-features

# Specific package
cargo test --package igra-core

# Specific test
cargo test --package igra-core network_mode
\`\`\`

## Linting

\`\`\`bash
# Format code
cargo fmt --all

# Run clippy
cargo clippy --workspace --tests --benches

# Run all checks
./check  # (if available)
\`\`\`
EOF
```

---

#### Step 9: Light Editing for Consistency (1 hour)

**Fix internal links in migrated files:**

```bash
# Example: In configuration/network-modes.md
# Old: See [Key Management](../docs/security/key-management-audit.md)
# New: See [Key Management](../security/key-management/audit.md)
```

**Use find-and-replace:**
```bash
# In each migrated file, update common link patterns
# This is manual work but necessary for navigation
```

---

#### Step 10: Add .gitignore (2 minutes)

**File:** `book/.gitignore`

```
book/
```

**Note:** Ignore generated HTML (will be built by GitHub Actions)

---

### Phase 3: Expand Coverage (Day 3 - 4 hours)

**Add remaining content:**

#### Operations Guide

```bash
cd book/src/operations

# Copy deployment docs
cp ../../../docs/ops/deployment-devnet.md deployment/devnet.md
cp ../../../docs/ops/monitoring.md monitoring.md

# Create mainnet deployment guide (NEW - high priority)
cat > deployment/mainnet.md << 'EOF'
# Mainnet Deployment Guide

> **⚠️ CRITICAL:** Mainnet deployment requires strict security validation.
> Read [Network Mode Security](../../configuration/network-modes.md) first.

## Prerequisites

- [ ] Read all security documentation
- [ ] Set up encrypted secrets file
- [ ] Configure local Kaspa RPC node
- [ ] Set proper file permissions (0600/0700)
- [ ] Disable debug logging
- [ ] Enable audit logging

## Configuration

See [Network Modes](../../configuration/network-modes.md) for mainnet requirements.

## Security Checklist

Before starting mainnet service:
- [ ] `service.network = "mainnet"` in config
- [ ] `node_rpc_url = "grpc://127.0.0.1:16110"` (local only)
- [ ] `use_encrypted_secrets = true`
- [ ] `IGRA_SECRETS_PASSPHRASE` env var set
- [ ] File permissions verified (0600 for secrets, 0700 for data dir)
- [ ] `--network mainnet` flag used
- [ ] `threshold_m >= 2`
- [ ] Audit logging enabled

## First Start

\`\`\`bash
# Validate configuration
kaspa-threshold-service --network mainnet --config config.toml --validate-only

# If validation passes, start service
kaspa-threshold-service --network mainnet --config config.toml
\`\`\`

## Monitoring

See [Monitoring Guide](../monitoring.md) for production monitoring setup.
EOF
```

---

#### Developer Guide Expansion

```bash
cd book/src/developer

# Create architecture deep dive (extract from Igra-Protocol.md)
cat > architecture.md << 'EOF'
# Architecture Overview

Igra follows a clean architecture pattern with clear layer separation.

## Crate Structure

\`\`\`
igra/
├── igra-core/          # Core library (no I/O)
│   ├── domain/         # Business logic
│   ├── application/    # Orchestration
│   ├── infrastructure/ # I/O implementations
│   └── foundation/     # Shared primitives
│
└── igra-service/       # Runtime binary
    ├── api/            # HTTP handlers
    ├── service/        # Main loops
    └── bin/            # Binary entry points
\`\`\`

## Layer Responsibilities

See [Code Guidelines](code-guidelines.md) for detailed layer rules.

## Data Flow

\`\`\`mermaid
graph TD
    A[Hyperlane Message] --> B[Event Processor]
    B --> C[Two-Phase Coordinator]
    C --> D[PSKT Builder]
    D --> E[Signing Backend]
    E --> F[CRDT Gossip]
    F --> G[Signature Aggregation]
    G --> H[Transaction Submission]
\`\`\`

For detailed protocol design, see [Protocol](../protocol/architecture.md).
EOF
```

---

### Phase 4: Polish and Deploy (Ongoing)

**After initial migration:**

- [ ] Fix all broken links (`mdbook-linkcheck`)
- [ ] Add code examples (runnable)
- [ ] Add diagrams (Mermaid)
- [ ] Create FAQ (compile common questions)
- [ ] Create glossary (define terms)
- [ ] Proofread all content
- [ ] Get team review
- [ ] Iterate based on feedback

---

## File Migration Mapping (Current State → mdBook)

### Current docs/ Files → Book Location

**Use this table for migration:**

| Current File | Category | mdBook Location | Priority |
|--------------|----------|-----------------|----------|
| `docs/guide/quickstart.md` | Getting Started | `getting-started/quickstart.md` | 🔴 HIGH |
| `docs/config/network-modes.md` | Configuration | `configuration/network-modes.md` | 🔴 HIGH |
| `docs/config/iroh-discovery.md` | Configuration | `configuration/iroh-discovery.md` | 🔴 HIGH |
| `docs/config/hyperlane.md` | Configuration | `configuration/hyperlane.md` | 🔴 HIGH |
| `docs/security/timing-attacks.md` | Security | `security/cryptography/timing-attacks.md` | 🔴 HIGH |
| `docs/security/key-management-audit.md` | Security | `security/key-management/audit.md` | 🔴 HIGH |
| `docs/security/soc2-compliance.md` | Security | `security/compliance/soc2.md` | 🔴 HIGH |
| `Igra-Protocol.md` | Protocol | `protocol/architecture.md` | 🔴 HIGH |
| `docs/protocol/two-phase-consensus.md` | Protocol | `protocol/two-phase.md` | 🔴 HIGH |
| `CODE-GUIDELINE.md` | Developer | `developer/code-guidelines.md` | 🔴 HIGH |
| `docs/config/network-modes-verification.md` | Configuration | `configuration/network-modes-verification.md` | 🟡 MEDIUM |
| `docs/config/network-modes-gaps.md` | Configuration | `configuration/network-modes-gaps.md` | 🟡 MEDIUM |
| `docs/config/iroh-discovery-review.md` | Configuration | `configuration/iroh-review.md` | 🟡 MEDIUM |
| `docs/security/key-management-extended-audit.md` | Security | `security/key-management/extended-audit.md` | 🟡 MEDIUM |
| `docs/protocol/two-phase-implementation.md` | Protocol | `protocol/two-phase/implementation.md` | 🟡 MEDIUM |
| `docs/ops/deployment-devnet.md` | Operations | `operations/deployment/devnet.md` | 🟡 MEDIUM |
| `docs/ops/monitoring.md` | Operations | `operations/monitoring.md` | 🟡 MEDIUM |
| `docs/dev/code-quality-audit.md` | Developer | `developer/reference/quality.md` | 🟢 LOW |
| `docs/security/audits/audit-v1.md` | Security | `security/audit-reports/audit-v1.md` | 🟢 LOW |
| `docs/guide/key-derivation.md` | Getting Started | `getting-started/key-derivation.md` | 🟢 LOW |

**Note:** Files marked 🔴 HIGH = migrate in Phase 1, 🟡 MEDIUM = Phase 2, 🟢 LOW = Phase 3

---

### Files to Keep As-Is (Don't Migrate)

**Working documents (not published docs):**
- `docs/dev/refactoring-todos.md` - Internal tracking
- `docs/dev/followup-todos.md` - Internal tracking
- `docs/dev/todo-fixes.md` - Internal tracking
- `docs/dev/code-quality-report.md` - Status report
- All `*-GAPS.md` files (internal analysis, link from main docs)
- All `*-VERIFICATION.md` files (internal reports, link from main docs)
- All `*-REVIEW.md` files (internal reviews, link from main docs)

**Action:** Keep in docs/ for team reference, don't include in book

**Alternative:** Add "Internal Documentation" appendix that links to these

---

## Team Workflow

### For Documentation Authors

**When writing new docs:**

1. **Create in book/src/ (not docs/)**
   ```bash
   vim book/src/operations/new-feature.md
   ```

2. **Add to SUMMARY.md**
   ```markdown
   - [New Feature](operations/new-feature.md)
   ```

3. **Preview locally**
   ```bash
   mdbook serve
   # Check at http://localhost:3000
   ```

4. **Commit and push**
   ```bash
   git add book/src/operations/new-feature.md book/src/SUMMARY.md
   git commit -m "docs: add new feature documentation"
   git push
   # Auto-deploys via GitHub Actions
   ```

---

### For Code Contributors

**When changing code:**

**If public API changes:**
- [ ] Update relevant doc in `book/src/`
- [ ] Update code examples
- [ ] Test examples still compile

**If configuration changes:**
- [ ] Update `configuration/*.md`
- [ ] Update example configs
- [ ] Update validation rules doc

**If security-relevant:**
- [ ] Update `security/*.md`
- [ ] Update threat model
- [ ] Note in changelog

---

### Review Process

**Documentation PRs should include:**

```markdown
## Documentation Checklist

- [ ] Links verified (mdbook-linkcheck)
- [ ] Code examples compile
- [ ] Tested locally (mdbook serve)
- [ ] Added to SUMMARY.md
- [ ] Cross-references updated
- [ ] Version/date updated
```

---

## Quick Reference Commands

### Daily Development

```bash
# Start live preview (edit and auto-refresh)
cd book && mdbook serve

# Check for broken links
mdbook-linkcheck src/

# Build final HTML
mdbook build

# Test that examples compile
cd ../examples && cargo test --all
```

---

### Deployment

```bash
# GitHub Actions deploys automatically on push to master/devel

# Manual deploy (if needed)
cd book
mdbook build
# Copy book/book/ to web server
```

---

### Maintenance

```bash
# Find outdated content (older than 6 months)
find book/src -name "*.md" -mtime +180

# Find broken links
mdbook-linkcheck src/

# Find missing images
grep -r "!\[.*\](" book/src/ | while read line; do
  # Check if referenced images exist
done
```

---

## Success Criteria

### Phase 1 Complete When:

- [x] mdBook installed and configured
- [x] Basic SUMMARY.md created (10+ pages)
- [x] Top 10 docs migrated
- [x] GitHub Pages deployed
- [x] Team can view at https://[url]

### Phase 2 Complete When:

- [ ] All 🔴 HIGH priority docs migrated (20 files)
- [ ] All internal links work
- [ ] Code examples tested
- [ ] Search works
- [ ] Team feedback incorporated

### Phase 3 Complete When:

- [ ] All active docs migrated (51 files)
- [ ] Diagrams added (Mermaid)
- [ ] FAQ and glossary complete
- [ ] Operations guide complete
- [ ] Ready for external users

---

## Timeline

**Week 1:**
- Day 1: Phase 1 (bootstrap) - 4 hours
- Day 2: Phase 2 (migrate priority docs) - 4 hours
- Day 3: Phase 3 (expand coverage) - 4 hours
- Day 4: Polish and review - 4 hours
- Day 5: Team review and iterate - 2 hours

**Total:** ~18 hours over 5 days

**Deliverable:** Professional documentation site with 30-40 pages

---

## Common Tasks

### Adding a New Page

```bash
# 1. Create markdown file
vim book/src/protocol/new-feature.md

# 2. Add to SUMMARY.md
vim book/src/SUMMARY.md
# Add: - [New Feature](protocol/new-feature.md)

# 3. Verify builds
mdbook build
```

---

### Moving a Page

```bash
# 1. Move file
mv book/src/old-location.md book/src/new-location.md

# 2. Update SUMMARY.md
vim book/src/SUMMARY.md

# 3. Find and update all references
grep -r "old-location.md" book/src/
# Update each reference to new-location.md
```

---

### Splitting a Large Document

```bash
# Example: Split Igra-Protocol.md into chapters

# 1. Extract sections
vim Igra-Protocol.md
# Copy "Architecture" section

# 2. Create new files
vim book/src/protocol/architecture.md
# Paste content

vim book/src/protocol/crdt-gossip.md
# Paste CRDT section

# 3. Create index page
vim book/src/protocol/README.md
# Link to all subsections

# 4. Update SUMMARY.md
```

---

## Troubleshooting

### Issue: "mdbook: command not found"

**Fix:**
```bash
cargo install mdbook
# Add ~/.cargo/bin to PATH
```

---

### Issue: "Broken links detected"

**Fix:**
```bash
# Find broken links
mdbook-linkcheck src/

# Fix each broken link
# Update paths or create missing files
```

---

### Issue: "GitHub Pages not deploying"

**Check:**
1. Settings → Pages → Source = "GitHub Actions"
2. Actions tab → Check workflow status
3. Workflow file is in `.github/workflows/`
4. Branch protection doesn't block Actions

---

## Next Actions for Your Team

### Before Starting: Consider Renaming (Optional but Recommended)

**Option A: Rename first (1-2 hours), then migrate**
- Use bulk rename script from docs/dev/documentation-naming-conventions.md
- Benefits: Consistent naming from day 1, easier to maintain
- See: docs/dev/documentation-naming-conventions.md Section 17 (Bulk Rename Commands)

**Option B: Migrate as-is, rename gradually**
- Start mdBook with current names
- Rename files as you touch them
- Benefits: Faster initial setup, less disruption

**Recommendation:** Option A if you have 1-2 hours extra time

---

### Immediate (Today - 1 hour)

**Developer 1:**
- [ ] Read docs/dev/documentation-naming-conventions.md (15 min) ← **NEW**
- [ ] Decide: Rename now or later? (5 min)
- [ ] Run commands from Phase 1, Steps 1-3 (install + init) (20 min)
- [ ] Configure book.toml (10 min)
- [ ] Create SUMMARY.md (minimal version) (10 min)
- [ ] Test local preview: `mdbook serve` (5 min)

**Result:** Basic mdBook running locally

---

### This Week (4-8 hours)

**Developer 1:**
- [ ] Migrate 10 priority docs (Phase 1, Step 6)
- [ ] Create intro.md and getting-started/
- [ ] Fix major broken links
- [ ] Deploy to GitHub Pages (Phase 1, Step 8)

**Developer 2 (optional):**
- [ ] Create FAQ (compile common questions)
- [ ] Create glossary (define terms)
- [ ] Add code examples

**Result:** Usable documentation site (20+ pages)

---

### This Month (12-16 hours)

**Whole team:**
- [ ] Migrate all 51 active docs
- [ ] Review and edit for consistency
- [ ] Add diagrams (Mermaid)
- [ ] Add runnable examples
- [ ] Polish and proofread

**Result:** Comprehensive documentation site (50+ pages)

---

## Deliverables

### Minimal Viable Documentation (Week 1)

**Must have (10 pages):**
1. Introduction
2. Installation
3. Quick Start
4. Network Modes (security)
5. Iroh Discovery (P2P)
6. Timing Attack Guide (security)
7. Key Management (security)
8. Protocol Architecture
9. Code Guidelines
10. FAQ

**Deployment:** https://[org].github.io/rusty-kaspa/igra/

---

### Complete Documentation (Month 1)

**Should have (40+ pages):**
- All configuration options documented
- All security guides migrated
- Complete protocol specification
- Developer onboarding guide
- Operations deployment guides
- Troubleshooting guide
- Glossary and FAQ

**Quality:** Production-ready for external users

---

## Questions & Answers

### Q: "Should we migrate all 51 docs?"

**A:** No, migrate selectively:
- ✅ Migrate: User guides, security, protocol, configuration (30 files)
- ⚠️ Link only: Verification reports, gap analyses (10 files)
- ❌ Skip: Internal TODO lists, refactoring logs (11 files)

---

### Q: "What about docs/legacy/?"

**A:** Keep as archive, don't migrate:
- Contains 100+ historical files
- Mostly development logs and old specs
- Valuable for git history but not current users
- Add note in book: "See docs/legacy/ for historical documentation"

---

### Q: "Do we keep docs/ folder?"

**A:** Yes, for now:
- Working documents that aren't published
- Gap analyses and verification reports
- Internal tracking (TODOs, progress)
- Eventually: Move all published docs to book/src/, keep only internal docs in docs/

---

### Q: "How do we handle updates?"

**A:** Docs as code:
- Documentation changes via PR (same as code)
- Review for accuracy (not just spelling)
- Auto-deploy on merge to master
- Version docs with releases

---

## Final Recommendations

### Start Small, Iterate

**Week 1:** Get basic mdBook working (10 pages)
**Week 2-3:** Migrate priority content (30 pages)
**Month 2:** Polish and expand (50+ pages)

**Don't try to migrate everything at once** - start with high-priority user-facing docs.

---

### Focus on Users First

**Priority order:**
1. **Security** (prevent loss of funds)
2. **Getting Started** (help new users)
3. **Configuration** (prevent misconfigurations)
4. **Protocol** (for developers/auditors)
5. **Developer** (for contributors)

---

### Automate Where Possible

- ✅ Use GitHub Actions (auto-deploy)
- ✅ Use mdbook-linkcheck (catch broken links)
- ✅ Use mdbook-toc (auto table of contents)
- ✅ Use CI to test code examples

---

**Your docs are well-organized now. Time to make them beautiful and searchable with mdBook!** 📖

**Next Step:** Run the commands from Phase 1, Step 1-8 (4 hours to deployed docs)
