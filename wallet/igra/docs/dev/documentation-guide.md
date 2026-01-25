# Documentation Best Practices for Igra - Complete Guide

**Date:** 2026-01-24
**Status:** Implementation Guide
**Estimated Effort:** 1 day (4-6 hours for basic setup)

---

## 🚀 Quick Start for Your Team

**YOUR DOCUMENTATION WORKFLOW (3 FILES):**

### For Setting Up mdBook (First Time)
1. **docs/dev/documentation-refactoring-plan.md** ← **START HERE**
   - Complete setup instructions (4 hours to deployed docs)
   - File migration mapping
   - Phase-by-phase commands

### For Naming & Organizing Docs (Ongoing)
2. **docs/dev/documentation-naming-conventions.md** ← **TEAM STANDARDS**
   - How to name files (kebab-case, category directories)
   - When to create docs (design → implementation → published)
   - Where to put files (directory structure)
   - How docs "graduate" to book (lifecycle)

### For Background & Best Practices (Reference)
3. **docs/dev/documentation-guide.md** (this file)
   - What is mdBook vs GitBook
   - Best practices for crypto project documentation
   - Long-term strategy

---

**Time to complete:**
- Setup (one-time): 4 hours (`docs/dev/documentation-refactoring-plan.md`)
- Per new feature: 1-2 hours documentation (`docs/dev/documentation-naming-conventions.md`)
- Ongoing: Follow standards (both guides)

**Questions?** See Section 3 (mdBook vs GitBook) or Section 6 (Setup Guide)

---

## Executive Summary (Updated: 2026-01-24)

**Current State:** `docs/` is categorized and `book/` contains an mdBook skeleton

**Situation:** The remaining work is to expand navigation, keep links consistent, and deploy via CI

**Solution:** Continue with **mdBook** (Rust-native) for the documentation site

**Why mdBook:**
- ✅ Rust ecosystem standard (official Rust documentation tool)
- ✅ Zero-cost hosting (GitHub Pages)
- ✅ Single command setup (`cargo install mdbook`)
- ✅ Built-in search, syntax highlighting, navigation
- ✅ Used by: Rust Book, Tokio, async-book, many Rust projects
- ✅ **Your docs are already mdBook-ready** (just need structure)

**Alternative:** GitBook (more features, requires paid plan for private repos)

**Recommendation:** Use mdBook (free, Rust-native), your content is ready for migration

**⭐ ACTION:** See **docs/dev/documentation-refactoring-plan.md** for step-by-step instructions tailored to your current file organization.

---

## Table of Contents

1. [What is mdBook (rustbook)?](#1-what-is-mdbook-rustbook)
2. [What is GitBook?](#2-what-is-gitbook)
3. [Comparison: mdBook vs GitBook](#3-comparison-mdbook-vs-gitbook)
4. [Documentation Structure for Blockchain Projects](#4-documentation-structure-for-blockchain-projects)
5. [Recommended Structure for Igra](#5-recommended-structure-for-igra)
6. [Step-by-Step: Setting Up mdBook](#6-step-by-step-setting-up-mdbook)
7. [Organizing Your Existing Documentation](#7-organizing-your-existing-documentation)
8. [Best Practices](#8-best-practices)
9. [Deployment Options](#9-deployment-options)
10. [Examples from Rust Ecosystem](#10-examples-from-rust-ecosystem)

---

## 1. What is mdBook (rustbook)?

### Overview

**mdBook** is a command-line tool to create books from markdown files.

**Key Features:**
- 📖 Converts markdown → beautiful HTML documentation
- 🔍 Built-in search (JavaScript-based)
- 🎨 Syntax highlighting (code blocks)
- 📱 Responsive design (mobile-friendly)
- 🔗 Automatic navigation (sidebar, chapters)
- 🚀 Static site generation (deploy anywhere)

**Used by:**
- The Rust Programming Language book (https://doc.rust-lang.org/book/)
- Tokio documentation
- async-book
- Rust by Example
- 1000+ Rust projects

### How It Works

```
Input (Markdown files):         mdBook Processing:              Output (Static HTML):
┌──────────────────┐           ┌──────────────┐                ┌──────────────────┐
│ src/             │           │              │                │ book/            │
│  ├─ SUMMARY.md   │──────────>│   mdBook     │───────────────>│  ├─ index.html   │
│  ├─ intro.md     │           │   Compiler   │                │  ├─ intro.html   │
│  ├─ chapter1.md  │           │              │                │  ├─ chapter1.html│
│  └─ chapter2.md  │           └──────────────┘                │  └─ search.js    │
└──────────────────┘                                           └──────────────────┘
```

**Example:**
```bash
# Install
cargo install mdbook

# Create new book
mdbook init my-docs

# Build HTML
mdbook build

# Serve locally (with live reload)
mdbook serve
# Opens http://localhost:3000
```

### File Structure

```
my-docs/
├── book.toml          # Configuration file
├── src/               # Markdown source files
│   ├── SUMMARY.md     # Table of contents (defines structure)
│   ├── intro.md       # Introduction
│   ├── chapter1/
│   │   ├── README.md
│   │   └── section1.md
│   └── chapter2/
│       └── README.md
└── book/              # Generated HTML (git ignore this)
    ├── index.html
    ├── chapter1.html
    └── ...
```

**Key File: SUMMARY.md**
```markdown
# Summary

[Introduction](intro.md)

# User Guide

- [Getting Started](user-guide/getting-started.md)
- [Configuration](user-guide/configuration.md)
  - [Network Modes](user-guide/configuration/network-modes.md)
  - [Security Settings](user-guide/configuration/security.md)

# Developer Guide

- [Architecture](dev-guide/architecture.md)
- [API Reference](dev-guide/api.md)

# Security

- [Threat Model](security/threat-model.md)
- [Audit Reports](security/audits.md)
```

**SUMMARY.md defines your entire documentation structure** (like a book's table of contents)

---

## 2. What is GitBook?

### Overview

**GitBook** is a modern documentation platform (SaaS + open source)

**Key Features:**
- 📖 Beautiful UI (more polished than mdBook)
- 🔍 Advanced search (fuzzy search, filters)
- 👥 Collaboration (comments, suggestions, multiple authors)
- 🔐 Access control (private docs, team permissions)
- 📊 Analytics (page views, search queries)
- 🔗 Integrations (GitHub sync, Slack, etc.)
- 🌐 Multi-language support
- 📝 WYSIWYG editor (non-technical users)

**Used by:**
- Stripe (API documentation)
- Docker (product docs)
- Kubernetes (community docs)
- Many blockchain projects (Polygon, Avalanche, etc.)

### How It Works

```
Option 1: GitBook Cloud (SaaS)
┌──────────────┐          ┌──────────────┐          ┌──────────────┐
│   GitHub     │  Sync    │   GitBook    │  Hosts   │   Users      │
│   (markdown) │ ───────> │   Platform   │ ───────> │   (Web UI)   │
└──────────────┘          └──────────────┘          └──────────────┘

Option 2: Self-Hosted (Legacy Open Source)
┌──────────────┐          ┌──────────────┐          ┌──────────────┐
│   Markdown   │  Build   │   GitBook    │  Deploy  │   Your       │
│   Files      │ ───────> │   CLI        │ ───────> │   Server     │
└──────────────┘          └──────────────┘          └──────────────┘
```

**Pricing:**
- Free: Public documentation only
- **Personal ($6.70/month):** 1 private space
- **Team ($12.50/user/month):** Team collaboration, SSO
- **Enterprise:** Custom pricing

**Note:** GitBook v2 (legacy CLI) is deprecated. New GitBook is SaaS-first.

---

## 3. Comparison: mdBook vs GitBook

### Feature Matrix

| Feature | mdBook | GitBook (SaaS) | Winner |
|---------|--------|----------------|--------|
| **Cost** | Free (OSS) | Free (public) / $6.70/mo (private) | mdBook |
| **Hosting** | Self-host (GitHub Pages, etc.) | GitBook hosts | GitBook (easier) |
| **Setup Time** | 10 minutes | 5 minutes | GitBook |
| **Rust Integration** | Native (cargo install) | External | mdBook |
| **Search** | Basic (client-side JS) | Advanced (server-side) | GitBook |
| **Collaboration** | Git-based (PR workflow) | Built-in (comments, suggestions) | GitBook |
| **Access Control** | None (public or self-host) | Built-in (teams, SSO) | GitBook |
| **Offline Access** | Easy (static HTML) | Requires export | mdBook |
| **Customization** | Full control (themes, plugins) | Limited (presets) | mdBook |
| **Analytics** | None (add your own) | Built-in | GitBook |
| **API Docs** | Manual | Manual | Tie |
| **Version Control** | Git (native) | Git sync | mdBook |
| **Open Source** | Yes (MIT) | No (SaaS) | mdBook |
| **Community** | Rust ecosystem | Large (multi-language) | Tie |

---

### When to Use mdBook

**Choose mdBook if:**
- ✅ You're building Rust projects (native integration)
- ✅ You want free hosting (GitHub Pages)
- ✅ You want full control (themes, plugins, hosting)
- ✅ You prefer git-based workflow (PRs for doc changes)
- ✅ You need offline documentation (static HTML)
- ✅ You want zero vendor lock-in

**Examples:**
- Internal documentation (developers only)
- Open-source projects (public docs)
- Technical specifications (Rust-focused)

---

### When to Use GitBook

**Choose GitBook if:**
- ✅ You need private documentation (team-only)
- ✅ You want advanced search (server-side indexing)
- ✅ You need collaboration features (comments, multi-author)
- ✅ You want analytics (page views, user tracking)
- ✅ You have non-technical contributors (WYSIWYG editor)
- ✅ You need access control (team permissions, SSO)

**Examples:**
- Customer-facing documentation
- Product documentation (multi-team collaboration)
- Enterprise knowledge base

---

### Recommendation for Igra

**Phase 1 (Now):** Use **mdBook**
- Free and open source
- Perfect for technical Rust documentation
- GitHub Pages hosting (zero cost)
- Rust ecosystem standard

**Phase 2 (Later):** Migrate to GitBook if needed
- When you need private docs for enterprise customers
- When non-developers need to edit docs
- When you need advanced collaboration

**Hybrid Approach:**
- mdBook for developer docs (open source)
- GitBook for customer docs (private, polished)

---

## 4. Documentation Structure for Blockchain Projects

### Industry Best Practices

**Typical structure for blockchain/crypto projects:**

```
documentation/
├── 1. Overview
│   ├── What is [Project]?
│   ├── Key Features
│   ├── Use Cases
│   └── Roadmap
│
├── 2. Getting Started
│   ├── Installation
│   ├── Quick Start Guide
│   ├── Configuration
│   └── First Transaction
│
├── 3. User Guide
│   ├── Running a Node
│   ├── CLI Reference
│   ├── Configuration Options
│   └── Network Modes
│
├── 4. Developer Guide
│   ├── Architecture Overview
│   ├── Building from Source
│   ├── Development Setup
│   ├── Contributing Guidelines
│   └── Code Style Guide
│
├── 5. Protocol Specification
│   ├── Consensus Protocol
│   ├── Cryptographic Primitives
│   ├── P2P Networking
│   └── Storage Format
│
├── 6. API Reference
│   ├── JSON-RPC API
│   ├── gRPC API
│   ├── WebSocket Events
│   └── Code Examples
│
├── 7. Security
│   ├── Threat Model
│   ├── Security Assumptions
│   ├── Audit Reports
│   ├── Responsible Disclosure
│   └── Best Practices
│
├── 8. Operations
│   ├── Deployment Guide
│   ├── Monitoring & Metrics
│   ├── Backup & Recovery
│   └── Troubleshooting
│
└── 9. Appendices
    ├── Glossary
    ├── FAQ
    ├── Change Log
    └── References
```

**Examples:**
- **Ethereum:** https://ethereum.org/en/developers/docs/
- **Polkadot:** https://wiki.polkadot.network/
- **Cosmos SDK:** https://docs.cosmos.network/
- **Solana:** https://docs.solana.com/

---

## 5. Recommended Structure for Igra

### Proposed Documentation Organization

Based on your current files (100+ markdown files), here's the recommended structure:

```
igra-book/
├── book.toml                          # mdBook config
├── src/
│   ├── SUMMARY.md                     # Table of contents (YOU DEFINE THIS)
│   │
│   ├── intro.md                       # What is Igra? (NEW)
│   │
│   ├── 01-getting-started/
│   │   ├── README.md                  # Getting Started overview
│   │   ├── installation.md            # How to install
│   │   ├── configuration.md           # Basic config (from docs/guide/quickstart.md)
│   │   └── first-signing.md           # Quickstart tutorial
│   │
│   ├── 02-user-guide/
│   │   ├── README.md                  # User Guide overview
│   │   ├── network-modes.md           # From docs/config/network-modes.md
│   │   ├── running-node.md            # How to run kaspa-threshold-service
│   │   ├── cli-reference.md           # CLI flags and options
│   │   └── troubleshooting.md         # Common issues
│   │
│   ├── 03-configuration/
│   │   ├── README.md                  # Configuration overview
│   │   ├── service-config.md          # service.* settings
│   │   ├── iroh-p2p.md                # From docs/config/iroh-discovery.md
│   │   ├── hyperlane.md               # From docs/config/hyperlane.md
│   │   └── secrets.md                 # From docs/security/key-management-audit.md
│   │
│   ├── 04-protocol/
│   │   ├── README.md                  # Protocol overview
│   │   ├── architecture.md            # From Igra-Protocol.md
│   │   ├── two-phase.md               # From docs/protocol/two-phase-consensus.md
│   │   ├── crdt-gossip.md             # CRDT state synchronization
│   │   ├── pskt.md                    # Partially Signed Kaspa Transactions
│   │   └── security-model.md          # Threat model, assumptions
│   │
│   ├── 05-developer/
│   │   ├── README.md                  # Developer guide overview
│   │   ├── architecture.md            # System architecture
│   │   ├── building.md                # Build from source
│   │   ├── code-guidelines.md         # From CODE-GUIDELINE.md
│   │   ├── testing.md                 # Test strategy
│   │   └── contributing.md            # How to contribute
│   │
│   ├── 06-api/
│   │   ├── README.md                  # API overview
│   │   ├── json-rpc.md                # JSON-RPC endpoints
│   │   ├── events.md                  # WebSocket events
│   │   └── examples.md                # Code examples
│   │
│   ├── 07-security/
│   │   ├── README.md                  # Security overview
│   │   ├── threat-model.md            # From docs/legacy/security/THREAT_MODEL.md
│   │   ├── cryptography.md            # From docs/security/timing-attacks.md
│   │   ├── key-management.md          # From docs/security/key-management-audit.md
│   │   ├── network-security.md        # From docs/config/network-modes.md
│   │   ├── audit-reports.md           # From docs/security/audits/audit-v1.md
│   │   └── responsible-disclosure.md  # Security contact
│   │
│   ├── 08-operations/
│   │   ├── README.md                  # Operations overview
│   │   ├── deployment.md              # Deployment guide
│   │   ├── monitoring.md              # Metrics and logging
│   │   ├── backup.md                  # Backup and recovery
│   │   └── maintenance.md             # Upgrade procedures
│   │
│   ├── 09-advanced/
│   │   ├── README.md                  # Advanced topics
│   │   ├── frost-integration.md       # Future: FROST MPC
│   │   ├── hsm-support.md             # Future: HSM backends
│   │   └── performance.md             # Performance tuning
│   │
│   └── 10-appendix/
│       ├── glossary.md                # Terms and definitions
│       ├── faq.md                     # Frequently asked questions
│       ├── changelog.md               # Version history
│       ├── references.md              # External links
│       └── legacy-docs.md             # Link to legacy/ directory
│
└── theme/                             # Optional: Custom CSS/JS
    ├── custom.css
    └── favicon.png
```

---

## 6. Step-by-Step: Setting Up mdBook

### Phase 1: Install mdBook (5 minutes)

```bash
# Install mdBook
cargo install mdbook

# Verify installation
mdbook --version
# Expected: mdbook v0.4.40

# Optional plugins (recommended)
cargo install mdbook-toc           # Auto table-of-contents
cargo install mdbook-mermaid       # Diagrams
cargo install mdbook-linkcheck     # Validate links
```

---

### Phase 2: Initialize Book Structure (10 minutes)

```bash
# From your igra root directory
cd /Users/user/Source/personal/rusty-kaspa/wallet/igra

# Create docs directory
mkdir -p book
cd book

# Initialize mdBook
mdbook init

# Answer prompts:
# Title: Igra Threshold Signing Documentation
# Do you want a .gitignore? Yes
# Create book in: . (current directory)

# Result:
# book/
# ├── book.toml
# ├── src/
# │   ├── SUMMARY.md
# │   └── chapter_1.md
# └── .gitignore
```

---

### Phase 3: Configure book.toml (10 minutes)

**File:** `book/book.toml`

```toml
[book]
title = "Igra Threshold Signing Documentation"
description = "Distributed threshold signing system for Kaspa blockchain"
authors = ["Igra Core Team"]
language = "en"
multilingual = false
src = "src"

[output.html]
default-theme = "rust"
preferred-dark-theme = "navy"
git-repository-url = "https://github.com/kaspanet/rusty-kaspa"
git-repository-icon = "fa-github"
edit-url-template = "https://github.com/kaspanet/rusty-kaspa/edit/master/wallet/igra/book/src/{path}"

# Add search
[output.html.search]
enable = true
limit-results = 30
use-boolean-and = true
boost-title = 2
boost-hierarchy = 1
boost-paragraph = 1
expand = true

# Code syntax highlighting
[output.html.code]
theme = "ayu"

# Table of contents
[output.html.fold]
enable = true
level = 2

# Print support
[output.html.print]
enable = true

# Plugins
[preprocessor.toc]
command = "mdbook-toc"
renderer = ["html"]

[preprocessor.mermaid]
command = "mdbook-mermaid"

[preprocessor.linkcheck]
command = "mdbook-linkcheck"
```

---

### Phase 4: Create Table of Contents (30 minutes)

**File:** `book/src/SUMMARY.md`

```markdown
# Summary

[Introduction](intro.md)

---

# Getting Started

- [What is Igra?](getting-started/what-is-igra.md)
- [Installation](getting-started/installation.md)
- [Quick Start](getting-started/quickstart.md)
- [Configuration Basics](getting-started/configuration.md)

---

# User Guide

- [Running the Service](user-guide/running.md)
  - [Network Modes](user-guide/network-modes.md)
  - [Command-Line Options](user-guide/cli-reference.md)
- [Configuration Reference](user-guide/configuration/README.md)
  - [Service Settings](user-guide/configuration/service.md)
  - [Iroh P2P](user-guide/configuration/iroh.md)
  - [Hyperlane Bridge](user-guide/configuration/hyperlane.md)
  - [Secret Management](user-guide/configuration/secrets.md)
- [Troubleshooting](user-guide/troubleshooting.md)

---

# Protocol Design

- [Architecture Overview](protocol/architecture.md)
- [Two-Phase Consensus](protocol/two-phase.md)
- [CRDT State Synchronization](protocol/crdt-gossip.md)
- [PSKT (Partially Signed Kaspa Transactions)](protocol/pskt.md)
- [Signature Collection](protocol/signatures.md)

---

# Developer Guide

- [Development Setup](developer/setup.md)
- [Building from Source](developer/building.md)
- [Code Organization](developer/architecture.md)
  - [Domain Layer](developer/domain.md)
  - [Application Layer](developer/application.md)
  - [Infrastructure Layer](developer/infrastructure.md)
- [Code Guidelines](developer/code-guidelines.md)
- [Testing](developer/testing.md)
- [Contributing](developer/contributing.md)

---

# API Reference

- [JSON-RPC API](api/json-rpc.md)
  - [Signing Endpoints](api/signing.md)
  - [Event Endpoints](api/events.md)
  - [Hyperlane Endpoints](api/hyperlane.md)
- [WebSocket Events](api/websocket.md)
- [Code Examples](api/examples.md)

---

# Security

- [Threat Model](security/threat-model.md)
- [Cryptography](security/cryptography.md)
  - [Timing Attack Analysis](security/timing-attacks.md)
  - [Library Security](security/libraries.md)
- [Key Management](security/key-management.md)
- [Network Security](security/network-security.md)
- [Audit Reports](security/audits.md)
- [Security Best Practices](security/best-practices.md)
- [Responsible Disclosure](security/disclosure.md)

---

# Operations

- [Deployment Guide](operations/deployment.md)
  - [Devnet Setup](operations/devnet.md)
  - [Testnet Setup](operations/testnet.md)
  - [Mainnet Setup](operations/mainnet.md)
- [Monitoring](operations/monitoring.md)
- [Logging](operations/logging.md)
- [Backup & Recovery](operations/backup.md)
- [Incident Response](operations/incidents.md)

---

# Advanced Topics

- [FROST MPC Integration](advanced/frost.md)
- [HSM Support](advanced/hsm.md)
- [Performance Tuning](advanced/performance.md)
- [Custom Backends](advanced/custom-backends.md)

---

# Appendix

- [Glossary](appendix/glossary.md)
- [FAQ](appendix/faq.md)
- [Changelog](appendix/changelog.md)
- [References](appendix/references.md)
```

---

### Phase 5: Create Content Files (2-4 hours)

**Option A: Start Fresh (Best)**

Create new, clean documentation:

```bash
cd book/src

# Create intro
cat > intro.md << 'EOF'
# Igra Threshold Signing Documentation

Welcome to the Igra documentation!

## What is Igra?

Igra is a distributed threshold signature coordination system for Kaspa blockchain.
It enables multiple parties to collaboratively sign transactions without any single
party having access to the complete private key.

## Key Features

- **Threshold Signatures:** 2-of-3, 3-of-5, or any M-of-N configuration
- **Byzantine Tolerance:** CRDT-based state synchronization
- **Cross-Chain Bridge:** Hyperlane integration for Kaspa ↔ EVM
- **Production Ready:** Mainnet-grade security validation

## Getting Started

- [Installation Guide](getting-started/installation.md)
- [Quick Start Tutorial](getting-started/quickstart.md)
- [Configuration Basics](getting-started/configuration.md)

## Documentation Structure

This documentation is organized into sections:

1. **Getting Started** - Installation and first steps
2. **User Guide** - Running and configuring Igra
3. **Protocol Design** - How Igra works internally
4. **Developer Guide** - Contributing to Igra
5. **API Reference** - Programming interfaces
6. **Security** - Threat model, audits, best practices
7. **Operations** - Deployment and maintenance
8. **Advanced Topics** - FROST, HSM, performance
9. **Appendix** - Glossary, FAQ, references
EOF

# Create getting-started directory
mkdir -p getting-started
```

---

**Option B: Import Existing Docs (Faster)**

Reuse your existing markdown files:

```bash
cd book/src

# Copy and organize existing docs
mkdir -p security
cp ../../docs/security/timing-attacks.md security/timing-attacks.md
cp ../../docs/config/network-modes.md security/network-security.md
cp ../../docs/security/key-management-audit.md security/key-management.md

mkdir -p protocol
cp ../../Igra-Protocol.md protocol/architecture.md
cp ../../docs/protocol/two-phase-consensus.md protocol/two-phase.md

mkdir -p user-guide/configuration
cp ../../docs/config/iroh-discovery.md user-guide/configuration/iroh.md

# etc.
```

**Advantage:** Reuse existing high-quality content
**Disadvantage:** Need to edit for consistency (cross-references, formatting)

---

### Phase 6: Build and Preview (2 minutes)

```bash
# From book/ directory
mdbook build

# Serve with live reload
mdbook serve --open

# Opens http://localhost:3000 in browser
# Edit files in src/ → browser auto-refreshes
```

**Expected:**
- Left sidebar: Table of contents (from SUMMARY.md)
- Right sidebar: Page table of contents (headers)
- Top bar: Search box
- Main content: Rendered markdown

---

### Phase 7: Deploy to GitHub Pages (15 minutes)

**Option A: Automated (Recommended)**

**File:** `.github/workflows/docs.yml` (create new)

```yaml
name: Deploy Documentation

on:
  push:
    branches: [master, main]
    paths:
      - 'book/**'
      - '.github/workflows/docs.yml'

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install mdBook
        run: |
          mkdir bin
          curl -sSL https://github.com/rust-lang/mdBook/releases/download/v0.4.40/mdbook-v0.4.40-x86_64-unknown-linux-gnu.tar.gz | tar -xz --directory=bin
          echo "$(pwd)/bin" >> $GITHUB_PATH

      - name: Install mdBook plugins
        run: |
          cargo install mdbook-toc mdbook-mermaid mdbook-linkcheck

      - name: Build book
        run: |
          cd book
          mdbook build

      - name: Deploy to GitHub Pages
        uses: peaceiris/actions-gh-pages@v3
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: ./book/book
          cname: docs.igra.kaspa.org  # Optional: custom domain
```

**Enable GitHub Pages:**
1. Go to repo Settings → Pages
2. Source: Deploy from a branch
3. Branch: gh-pages (created by workflow)
4. Save

**Result:** Documentation auto-deploys on every push to master

**URL:** https://[your-org].github.io/rusty-kaspa/wallet/igra/

---

**Option B: Manual Deploy**

```bash
# Build book
cd book
mdbook build

# Generated HTML is in book/book/
# Copy to gh-pages branch manually
git checkout --orphan gh-pages
git rm -rf .
cp -r book/book/* .
git add .
git commit -m "docs: deploy documentation"
git push origin gh-pages
```

---

## 7. Organizing Your Existing Documentation

### Current State Analysis

**Your documentation (100+ files):**

```
Current Location → Recommended Location (in book/src/)
─────────────────────────────────────────────────────────

Root Level (Active):
├── docs/security/timing-attacks.md → security/timing-attacks.md
├── docs/config/network-modes.md → security/network-security.md
├── docs/config/iroh-discovery.md → user-guide/configuration/iroh.md
├── Igra-Protocol.md → protocol/architecture.md
├── CODE-GUIDELINE.md → developer/code-guidelines.md
└── docs/guide/quickstart.md → getting-started/quickstart.md

docs/ (Active):
├── docs/protocol/two-phase-consensus.md → protocol/two-phase.md
├── docs/security/key-management-audit.md → security/key-management.md
├── docs/config/hyperlane.md → user-guide/configuration/hyperlane.md
├── docs/security/audits/audit-v1.md → security/audit-reports.md
└── docs/security/soc2-compliance.md → security/compliance.md

docs/legacy/ (Archive):
├── Keep as-is for historical reference
└── Don't include in book (too many, outdated)

orchestration/ (Operational):
├── devnet/README.md → operations/devnet.md
├── testnet/README.md → operations/testnet.md
└── scripts/ → operations/scripts/ (reference only)
```

---

### Migration Strategy

**Phase 1: Core Documentation (Week 1)**

**Priority 1 (Must Have):**
- [ ] Introduction (NEW - write this)
- [ ] Getting Started (adapt docs/guide/quickstart.md)
- [ ] Configuration (docs/config/network-modes.md + docs/config/iroh-discovery.md)
- [ ] Protocol (Igra-Protocol.md + docs/protocol/two-phase-consensus.md)
- [ ] Security (docs/security/timing-attacks.md + docs/security/key-management-audit.md)

**Effort:** 4-8 hours (mostly copy-paste + light editing)

---

**Phase 2: Developer & API Docs (Week 2)**

**Priority 2 (Should Have):**
- [ ] Developer Guide (CODE-GUIDELINE.md)
- [ ] Architecture Deep Dive (extract from Igra-Protocol.md)
- [ ] API Reference (extract from legacy/api/)
- [ ] Testing Guide (NEW - document test strategy)

**Effort:** 8-12 hours (some new content needed)

---

**Phase 3: Operations & Advanced (Week 3)**

**Priority 3 (Nice to Have):**
- [ ] Deployment Guide (orchestration/devnet/README.md)
- [ ] Monitoring (NEW - document metrics)
- [ ] Advanced Topics (FROST integration plan)
- [ ] FAQ and Glossary (NEW)

**Effort:** 4-8 hours

---

## 8. Best Practices

### 8.1 Content Organization

**Follow these principles:**

#### Principle 1: Progressive Disclosure

```
Level 1: What (High-level overview)
    ↓
Level 2: How (Practical guides)
    ↓
Level 3: Why (Design rationale)
    ↓
Level 4: Deep Dive (Implementation details)
```

**Example for "Network Modes":**
```
Level 1: "Igra supports mainnet, testnet, and devnet"
Level 2: "Use --network mainnet flag"
Level 3: "Network mode determines security validation strictness"
Level 4: "Mainnet enforces file permissions via Unix mode bits..."
```

---

#### Principle 2: Task-Oriented Structure

**Organize by what users want to DO:**

**Good:**
```
- How to run a devnet node
- How to configure threshold M-of-N
- How to troubleshoot RPC connection errors
```

**Bad:**
```
- The AppConfig struct
- CRDT merge algorithm
- RocksDB column families
```

**Exception:** Developer docs can be code-oriented

---

#### Principle 3: Consistency

**Use consistent formatting:**

**Code blocks:**
```markdown
Use ```rust for Rust code
Use ```toml for config files
Use ```bash for shell commands
```

**Headings:**
```markdown
# Chapter (H1)
## Section (H2)
### Subsection (H3)
#### Detail (H4)
```

**Notes:**
```markdown
> **Note:** Important information
> **Warning:** Potential issue
> **Security:** Security-critical information
```

**File references:**
```markdown
See `igra-core/src/domain/crdt/event_state.rs:102` for implementation.
```

---

### 8.2 Writing Style

#### For User Documentation

**Be clear and direct:**
```markdown
✅ GOOD:
## Running a Devnet Node

Start a local development node:

\`\`\`bash
cargo run --bin kaspa-threshold-service -- --network devnet
\`\`\`

The service binds to port 11205 by default.

❌ BAD:
## Node Execution

The binary entry point `kaspa-threshold-service` can be invoked
with various command-line parameters to instantiate a service
instance configured for the devnet network topology...
```

**Use active voice:**
- ✅ "Configure the network mode"
- ❌ "The network mode should be configured"

**Use examples:**
Every concept needs a concrete example.

---

#### For Developer Documentation

**Be precise and comprehensive:**

**Good:**
```markdown
## EventCrdt Merge Algorithm

The CRDT merge operation combines signature sets from two peers:

\`\`\`rust
pub fn merge(&mut self, other: &EventCrdt) -> usize {
    // Validate compatibility
    if !self.event_id.ct_eq(&other.event_id) {
        return 0;  // Reject incompatible CRDT
    }

    // Merge signature sets (G-Set semantics)
    let mut changes = 0;
    for (key, record) in &other.signatures {
        if self.signatures.insert(*key, record.clone()).is_none() {
            changes += 1;
        }
    }

    changes
}
\`\`\`

**Invariants:**
- CRDTs with different `event_id` never merge (safety)
- Signature set grows monotonically (G-Set property)
- Merge is commutative and idempotent

**Time Complexity:** O(n) where n = signatures in other
**Space Complexity:** O(n) growth per merge
```

**Include diagrams:**
- Sequence diagrams for protocols
- Architecture diagrams for system design
- State machines for workflows

---

### 8.3 Code Examples

**Make examples runnable:**

```markdown
## Example: Signing a Transaction

\`\`\`rust
use igra_core::application::pskt_signing::sign_pskt_with_app_config;
use igra_core::infrastructure::config::AppConfig;

#[tokio::main]
async fn main() -> Result<(), ThresholdError> {
    // Load configuration
    let config = AppConfig::load("config.toml")?;

    // Sign PSKT
    let result = sign_pskt_with_app_config(
        &kpsbt_blob,
        &config,
        &key_manager,
        &audit_logger,
    ).await?;

    println!("Signed {} inputs", result.signatures.len());
    Ok(())
}
\`\`\`

**Run this example:**

\`\`\`bash
cargo run --example sign-pskt
\`\`\`
```

**Every API should have:**
1. Complete working example
2. Expected output
3. How to run it

---

### 8.4 Diagrams and Visuals

**Tools for diagrams:**

#### Mermaid (Built into mdBook)

```markdown
\`\`\`mermaid
sequenceDiagram
    participant Coordinator
    participant Signer1
    participant Signer2

    Coordinator->>Signer1: ProposalBroadcast
    Coordinator->>Signer2: ProposalBroadcast
    Signer1->>Coordinator: Ack
    Signer2->>Coordinator: Ack
    Coordinator->>All: CommitBroadcast
\`\`\`
```

**Renders as interactive diagram in HTML**

---

#### ASCII Diagrams (For Simple Cases)

```markdown
\`\`\`
┌─────────────────────────────────────────────┐
│             Service Flow                    │
└─────────────────────────────────────────────┘
                    │
    ┌───────────────┼───────────────┐
    │               │               │
    ▼               ▼               ▼
┌────────┐    ┌──────────┐    ┌──────────┐
│  API   │    │ Gossip   │    │ Hyperlane│
│ Server │    │ Handler  │    │ Watcher  │
└────────┘    └──────────┘    └──────────┘
\`\`\`
```

**Good for:** Architecture overviews, data flow

---

#### External Tools (For Complex Diagrams)

**For complex architecture:**
- **Excalidraw** (https://excalidraw.com) - Hand-drawn style
- **draw.io** (https://draw.io) - Professional diagrams
- **PlantUML** - UML diagrams from text

**Export as PNG/SVG:**
```markdown
![System Architecture](images/architecture.svg)
```

---

### 8.5 Documentation Maintenance

**Keep docs in sync with code:**

#### Strategy 1: Docs in PR

**Require documentation updates in PRs:**

```markdown
## PR Checklist

- [ ] Code changes implemented
- [ ] Tests added/updated
- [ ] **Documentation updated** (if public API changed)
- [ ] Changelog updated
```

---

#### Strategy 2: Docs as Code

**Treat docs like code:**
- Review for accuracy (not just spelling)
- Test code examples (compile and run)
- Version docs with releases
- Archive old versions

---

#### Strategy 3: Living Documents

**Different doc types age differently:**

| Doc Type | Lifetime | Update Frequency | Example |
|----------|----------|------------------|---------|
| **Tutorial** | Long | Rarely | Getting Started |
| **Reference** | Long | With code changes | API docs |
| **Architecture** | Medium | Major refactors | Protocol design |
| **Troubleshooting** | Short | Add as issues found | FAQ |
| **Changelog** | Forever | Every release | CHANGELOG.md |

**Best practice:** Date stamp documents, archive outdated content

---

## 9. Deployment Options

### Option 1: GitHub Pages (Free, Recommended)

**Pros:**
- ✅ Free for public repos
- ✅ Automatic HTTPS
- ✅ Custom domain support
- ✅ GitHub Actions integration

**Setup:**
```bash
# Already shown in Phase 7
# Result: https://[org].github.io/[repo]/
```

---

### Option 2: Read the Docs (Free for Open Source)

**Pros:**
- ✅ Free for open source
- ✅ Version control (multiple versions side-by-side)
- ✅ PDF/EPUB export
- ✅ Search analytics

**Setup:**
1. Sign up at https://readthedocs.org
2. Connect GitHub repo
3. Add `.readthedocs.yml` config
4. Builds automatically on push

**Example:** https://igra.readthedocs.io

---

### Option 3: Self-Hosted (Full Control)

**Pros:**
- ✅ Complete control
- ✅ No external dependencies
- ✅ Can add auth (nginx basic auth)

**Setup:**
```bash
# Build static HTML
mdbook build

# Copy to web server
scp -r book/book/* user@docs.igra.io:/var/www/html/

# Or use Docker:
docker run -d -p 80:80 -v $(pwd)/book/book:/usr/share/nginx/html nginx
```

---

### Option 4: GitBook Cloud (Paid)

**Pros:**
- ✅ Beautiful UI
- ✅ Advanced search
- ✅ Collaboration tools
- ✅ Analytics

**Cons:**
- ❌ $6.70/month for private docs
- ❌ Vendor lock-in

**Setup:**
1. Sign up at https://gitbook.com
2. Connect GitHub repo
3. GitBook auto-imports markdown
4. Configure permissions

---

## 10. Examples from Rust Ecosystem

### The Rust Book (Gold Standard)

**Source:** https://github.com/rust-lang/book
**Built with:** mdBook
**URL:** https://doc.rust-lang.org/book/

**Structure:**
```
src/
├── SUMMARY.md               # Table of contents
├── ch01-00-getting-started.md
├── ch02-00-guessing-game.md
├── ch03-00-common-concepts.md
├── ch03-01-variables-and-mutability.md
├── ch03-02-data-types.md
└── ...

book.toml                    # Config
```

**Best practices they use:**
- Clear chapter numbering (ch01, ch02)
- Progressive complexity (basics → advanced)
- Runnable code examples
- Extensive cross-references
- Print-friendly layout

---

### Tokio Documentation

**Source:** https://github.com/tokio-rs/website
**Built with:** mdBook
**URL:** https://tokio.rs/tokio/tutorial

**Structure:**
```
tutorial/
├── hello-tokio.md           # Start here
├── spawning.md              # Core concept
├── shared-state.md          # Practical pattern
└── channels.md              # Advanced
```

**Best practices:**
- Tutorial-first (not reference-first)
- Complete working examples
- Links to API docs (docs.rs)
- Common patterns documented

---

### Solana Documentation

**Source:** https://github.com/solana-labs/solana
**Built with:** GitBook
**URL:** https://docs.solana.com

**Structure:**
```
docs/
├── introduction/
├── architecture/
├── developing/
│   ├── on-chain/
│   └── clients/
├── running-validator/
└── api/
```

**Best practices:**
- Role-based organization (users, developers, validators)
- Extensive diagrams
- API playground (interactive examples)
- Multi-language support

---

## 11. Specific Recommendations for Igra

### Immediate Actions (This Week)

#### 1. Set Up mdBook (1 hour)

```bash
# Install
cargo install mdbook mdbook-toc mdbook-mermaid

# Initialize
cd /Users/user/Source/personal/rusty-kaspa/wallet/igra
mkdir book
cd book
mdbook init

# Configure book.toml (use config from Section 6, Phase 3)

# Test
mdbook serve --open
```

---

#### 2. Create Core Structure (2 hours)

**Must-have pages (create these first):**

```bash
cd src

# Introduction
cat > intro.md << 'EOF'
# Igra Documentation

Distributed threshold signing for Kaspa blockchain.

[Get Started →](getting-started/installation.md)
EOF

# Getting Started
mkdir getting-started
cp ../../docs/guide/quickstart.md getting-started/quickstart.md

# Security (your best docs)
mkdir security
cp ../../docs/security/timing-attacks.md security/timing-attacks.md
cp ../../docs/config/network-modes.md security/network-security.md

# Protocol
mkdir protocol
cp ../../Igra-Protocol.md protocol/architecture.md
cp ../../docs/protocol/two-phase-consensus.md protocol/two-phase.md

# Update SUMMARY.md (minimal version for now)
```

---

#### 3. Deploy to GitHub Pages (30 minutes)

```bash
# Add GitHub Action (from Section 9, Option 1)
mkdir -p ../../.github/workflows
cat > ../../.github/workflows/docs.yml << 'EOF'
# (Copy config from Section 9)
EOF

# Commit and push
git add book/ .github/workflows/docs.yml
git commit -m "docs: add mdBook documentation structure"
git push

# Enable GitHub Pages in repo settings
```

**Result:** Documentation live at https://[org].github.io/rusty-kaspa/

---

### Long-Term Strategy (3-6 Months)

#### Phase 1: Essential Documentation (Month 1)

Focus on **user-facing content:**
- Installation and setup
- Configuration guide
- Troubleshooting
- Basic API reference

**Target audience:** Operators and integrators

---

#### Phase 2: Developer Documentation (Month 2-3)

Focus on **contributor-facing content:**
- Architecture deep-dive
- Code guidelines
- Contributing guide
- Testing guide

**Target audience:** Open-source contributors

---

#### Phase 3: Advanced Topics (Month 4-6)

Focus on **specialized content:**
- Protocol specification (for auditors)
- Security deep-dives (for security teams)
- Performance tuning (for large deployments)
- Custom integrations (for enterprise)

**Target audience:** Power users and auditors

---

### Documentation Quality Checklist

**Before publishing, verify:**

- [ ] **Accuracy:** All code examples compile and run
- [ ] **Completeness:** No broken links (use mdbook-linkcheck)
- [ ] **Clarity:** Tested with someone unfamiliar with codebase
- [ ] **Consistency:** Same formatting, terminology throughout
- [ ] **Currency:** Dated, version-specific (e.g., "As of v0.5.0")
- [ ] **Cross-references:** Link between related sections
- [ ] **Search:** Key terms findable via search
- [ ] **Mobile:** Readable on phone/tablet

---

## 12. Documentation for Security-Critical Projects

### Special Considerations for Blockchain/Crypto

**Your project handles real money → documentation is security-critical**

#### 1. Security-First Organization

**Highlight security early:**

```markdown
# Igra Documentation

> **Security Notice:** Igra is a threshold signing system for Kaspa mainnet.
> Misconfiguration can lead to loss of funds. Read the [Security Guide](security/)
> before deploying to production.

## Quick Links
- 🔒 [Security Best Practices](security/best-practices.md) ← START HERE
- 📖 [Getting Started](getting-started/installation.md)
- 🛠️ [Configuration](user-guide/configuration/)
```

---

#### 2. Explicit Security Warnings

**Use prominent warnings:**

```markdown
> **⚠️ CRITICAL:** Never use `--network devnet` in production. Devnet mode
> disables security validation and allows environment variable secrets.
>
> For mainnet, use:
> \`\`\`bash
> kaspa-threshold-service --network mainnet --config config.toml
> \`\`\`

> **🔐 SECURITY:** Mainnet requires encrypted secrets file (`secrets.bin`)
> with proper permissions (0600). See [Key Management](security/key-management.md)
> for details.
```

---

#### 3. Configuration Examples with Annotations

**Annotate every security-relevant setting:**

```markdown
## Mainnet Configuration Example

\`\`\`toml
[service]
# REQUIRED: Explicit network confirmation (prevents test config accidents)
network = "mainnet"

# REQUIRED: Local RPC only (prevents MITM attacks)
node_rpc_url = "grpc://127.0.0.1:16110"

# REQUIRED: Encrypted secrets (file-based, not env vars)
use_encrypted_secrets = true

# REQUIRED: Audit logging (forensic trail)
key_audit_log_path = "/var/log/igra/key-audit.log"

[group]
# SECURITY: Minimum M=2 for mainnet (single signer is insecure)
threshold_m = 2
threshold_n = 3
\`\`\`

**Security rationale:** See [Network Security](security/network-security.md)
```

---

#### 4. Threat Model Documentation

**Every security feature needs rationale:**

```markdown
## Why Local RPC Only?

**Threat:** Remote Kaspa RPC endpoint

**Attack Scenario:**
1. Attacker controls remote RPC node
2. Lies about UTXO state
3. Threshold signs transaction sending funds to attacker
4. Loss of funds

**Mitigation:** Mainnet requires local RPC by default

**Override:** Use `--allow-remote-rpc` flag (explicitly acknowledge risk)

**See also:** [RPC Security Model](security/rpc-security.md)
```

---

#### 5. Audit Trail Documentation

**Document what gets logged and why:**

```markdown
## Key Audit Logging

Every secret access is logged to `key-audit.log`:

\`\`\`json
{
  "timestamp": "2026-01-24T12:34:56.789Z",
  "request_id": "req_abc123",
  "event": "SecretAccess",
  "secret_name": "igra.hd.wallet_secret",
  "operation": "Get",
  "result": "Success"
}
\`\`\`

**What is logged:**
- ✅ Timestamp (forensic timeline)
- ✅ Request ID (correlate with signing events)
- ✅ Secret name (which key was accessed)
- ✅ Operation result (success/failure)

**What is NOT logged:**
- ❌ Secret values (never logged)
- ❌ Derived keys (never logged)
- ❌ Passphrases (never logged)

**Retention:** Keep audit logs for minimum 90 days (compliance)

**See also:** [Audit Trail Specification](security/audit-trail.md)
```

---

## 13. Practical Implementation Plan for Igra (Updated)

**⚠️ IMPORTANT:** See **docs/dev/documentation-refactoring-plan.md** for detailed step-by-step instructions based on your current file organization.

### Current State Summary

**Your files (as of 2026-01-24):**
- ✅ **Root:** 4 files (clean!)
- ✅ **docs/:** 51 active files (well-organized!)
- ✅ **docs/legacy/:** ~100 archived files (historical)
- ✅ **Excellent content quality**

**What you need:** mdBook structure for navigation and deployment

---

### Quick Start (Recommended Path)

**Use docs/dev/documentation-refactoring-plan.md which provides:**

1. **Current inventory** - All 55 files categorized
2. **Migration mapping** - Where each file goes in book/
3. **Priority order** - 🔴 HIGH (10 files) → 🟡 MEDIUM (15 files) → 🟢 LOW (30 files)
4. **Complete SUMMARY.md** - Ready to use
5. **Step-by-step commands** - Copy-paste to execute
6. **Timeline** - 3 days to complete documentation site

---

### Implementation Timeline (Revised)

**Day 1: Bootstrap (4 hours)**
- Install mdBook tools (10 min)
- Initialize structure (15 min)
- Configure book.toml (15 min)
- Create SUMMARY.md (30 min)
- Migrate 10 priority docs (2 hours)
- Deploy to GitHub Pages (30 min)
- Test and verify (20 min)

**Deliverable:** Live documentation site with 15+ pages

---

**Day 2: Expand (4 hours)**
- Migrate 15 important docs (2 hours)
- Fix broken links (1 hour)
- Create FAQ and glossary (1 hour)

**Deliverable:** Comprehensive coverage (30+ pages)

---

**Day 3: Polish (4 hours)**
- Review all content for consistency (2 hours)
- Add code examples and diagrams (1 hour)
- Team review and iterate (1 hour)

**Deliverable:** Production-ready documentation (40+ pages)

---

### Week 2-3: Expand Coverage

**Add:**
- Developer guide (CODE-GUIDELINE.md)
- API reference (legacy/api/)
- Operations guide (orchestration/)
- Advanced topics

**Deliverable:** Comprehensive documentation (30-40 pages)

---

### Week 4: Polish

**Improvements:**
- Add diagrams (Mermaid)
- Add code examples (runnable)
- Add FAQ
- Add glossary
- Proofread and edit

**Deliverable:** Production-quality documentation

---

## 14. Quick Start Template for Igra

### Minimal book.toml

```toml
[book]
title = "Igra Threshold Signing"
authors = ["Igra Core Team"]
language = "en"
src = "src"

[output.html]
default-theme = "rust"
git-repository-url = "https://github.com/kaspanet/rusty-kaspa"
git-repository-icon = "fa-github"

[output.html.search]
enable = true

[preprocessor.toc]
command = "mdbook-toc"

[preprocessor.mermaid]
command = "mdbook-mermaid"
```

---

### Minimal SUMMARY.md

```markdown
# Summary

[Introduction](intro.md)

# Getting Started

- [Installation](getting-started/installation.md)
- [Quick Start](getting-started/quickstart.md)

# Configuration

- [Network Modes](configuration/network-modes.md)
- [Security Settings](configuration/security.md)

# Security

- [Timing Attacks](security/timing-attacks.md)
- [Key Management](security/key-management.md)

# Protocol

- [Architecture](protocol/architecture.md)
- [Two-Phase Consensus](protocol/two-phase.md)
```

---

### Minimal Intro Page

```markdown
# Igra Threshold Signing Documentation

Igra is a distributed threshold signature coordination system for Kaspa blockchain.

## What is Igra?

Igra enables multiple parties to collaboratively sign Kaspa transactions using
threshold cryptography, without any single party possessing the complete private key.

## Key Features

- **M-of-N Threshold:** Configurable quorum (2-of-3, 3-of-5, etc.)
- **Byzantine Tolerant:** CRDT-based state synchronization
- **Production Ready:** Mainnet-grade security validation
- **Cross-Chain:** Hyperlane bridge support (Kaspa ↔ EVM)

## Quick Links

- [🚀 Get Started](getting-started/installation.md)
- [🔧 Configuration](configuration/network-modes.md)
- [🔒 Security](security/timing-attacks.md)
- [📖 Protocol](protocol/architecture.md)

## Documentation Sections

1. **Getting Started** - Install and run your first node
2. **Configuration** - Network modes, security settings, P2P
3. **Security** - Threat model, cryptography, audit reports
4. **Protocol** - How Igra works (two-phase, CRDT, PSKT)
5. **Developer** - Contributing, code guidelines, architecture
6. **API** - JSON-RPC, WebSocket events
7. **Operations** - Deployment, monitoring, troubleshooting

## Support

- **GitHub Issues:** https://github.com/kaspanet/rusty-kaspa/issues
- **Security:** security@igra.kaspa.org
- **Community:** [Discord/Telegram]
```

---

## 15. Tools and Workflows

### Recommended Toolchain

```bash
# Core tool
cargo install mdbook

# Essential plugins
cargo install mdbook-toc         # Auto table-of-contents
cargo install mdbook-mermaid     # Diagrams
cargo install mdbook-linkcheck   # Broken link detection

# Optional (nice to have)
cargo install mdbook-pdf         # PDF export
cargo install mdbook-katex       # Math formulas (for crypto docs)
cargo install mdbook-graphviz    # GraphViz diagrams
```

---

### Development Workflow

```bash
# 1. Start live server (terminal 1)
cd book
mdbook serve

# 2. Edit markdown files (terminal 2)
vim src/security/timing-attacks.md

# 3. Browser auto-refreshes (no manual reload)

# 4. Check for broken links
mdbook-linkcheck src/

# 5. Build final version
mdbook build

# 6. Commit and push
git add book/
git commit -m "docs: update security section"
git push
# GitHub Action deploys automatically
```

---

### Editor Setup

**VS Code (Recommended):**

**Extensions:**
- Markdown All in One
- Markdown Preview Enhanced
- markdownlint

**Settings (`.vscode/settings.json`):**
```json
{
  "markdown.preview.breaks": true,
  "markdown.preview.fontSize": 14,
  "[markdown]": {
    "editor.wordWrap": "on",
    "editor.quickSuggestions": true
  },
  "markdownlint.config": {
    "MD013": false,  // Line length (mdBook handles this)
    "MD033": false   // Inline HTML (useful for notes)
  }
}
```

---

## 16. Documentation Anti-Patterns to Avoid

### ❌ Anti-Pattern 1: Scattered Files

**Bad:**
```
/docs/security/timing-attacks.md
/docs/security/timing-attacks-quick-fix.md
/docs/security/SECURITY-FIXES-REQUIRED.md
/docs/legacy/security/SECURITY_AUDIT.md
```

**Good:**
```
book/src/security/
├── README.md (overview, links to all security docs)
├── timing-attacks.md (comprehensive guide)
├── audit-reports.md (historical audits)
└── best-practices.md (security checklist)
```

**Solution:** Single canonical location per topic

---

### ❌ Anti-Pattern 2: No Navigation

**Bad:**
- 100 markdown files
- No index
- No cross-references
- Users must grep to find content

**Good:**
- SUMMARY.md defines structure
- Every page has "Next →" link
- Breadcrumbs show location
- Search finds content

**Solution:** Use mdBook's navigation

---

### ❌ Anti-Pattern 3: Outdated Content

**Bad:**
```markdown
Last Updated: 2023-06-15  (3 years old!)
```

**Good:**
```markdown
Last Updated: 2026-01-24
Version: v0.5.0
Status: ✅ Current
```

**Solution:** Date-stamp docs, archive old versions, review quarterly

---

### ❌ Anti-Pattern 4: Missing Context

**Bad:**
```markdown
## Configuration

Set `threshold_m` to 2.
```

**Good:**
```markdown
## Threshold Configuration

The threshold determines how many signers (M) are required out of total (N).

**Example:** For 2-of-3 threshold:
\`\`\`toml
[group]
threshold_m = 2  # Required signers
threshold_n = 3  # Total signers
\`\`\`

**Security:** Mainnet requires M ≥ 2 (single signer is insecure).

**See also:**
- [Security Model](../security/threat-model.md)
- [Network Modes](network-modes.md)
```

**Solution:** Always explain WHY, not just HOW

---

## 17. Maintenance and Updates

### Documentation Review Schedule

**Quarterly (Every 3 Months):**
- [ ] Review all docs for accuracy
- [ ] Update version numbers
- [ ] Check all code examples still work
- [ ] Fix broken links
- [ ] Archive outdated content

**Per Release:**
- [ ] Update changelog
- [ ] Update version numbers
- [ ] Document breaking changes
- [ ] Update configuration examples

**Per Security Issue:**
- [ ] Update threat model
- [ ] Document vulnerability
- [ ] Update best practices
- [ ] Publish security advisory

---

### Documentation Metrics

**Track these metrics:**

| Metric | Tool | Target |
|--------|------|--------|
| Broken links | mdbook-linkcheck | 0 |
| Page views | GitHub Pages analytics | Track growth |
| Search queries | Log analysis | Identify gaps |
| Time on page | Analytics | > 2 min avg |
| Bounce rate | Analytics | < 40% |

---

## 18. Migration Plan for Your Current Docs

### Your Current Situation (Updated: 2026-01-24)

**You have 55 active markdown files (well-organized!):**
- ✅ Excellent technical content
- ✅ Good categorization (moved to docs/)
- ✅ Clean root directory (4 core files)
- ⚠️ Needs mdBook structure for navigation
- ❌ Not deployed/hosted yet

**Current organization:**
```
Root Level (4 core files):
├── AGENTS.md (internal)
├── CODE-GUIDELINE.md (developer guide) ⭐
├── docs/dev/documentation-guide.md (this file)
└── Igra-Protocol.md (protocol architecture) ⭐⭐⭐

docs/ (active files, well-categorized):
├── Getting Started: docs/guide/quickstart.md, docs/guide/key-derivation.md
├── Configuration: docs/config/network-modes.md, docs/config/iroh-discovery.md, docs/config/hyperlane.md ⭐⭐⭐
├── Security: docs/security/timing-attacks*.md, docs/security/key-management-*.md, docs/security/soc2-compliance.md ⭐⭐⭐
├── Protocol: docs/protocol/two-phase-*.md, docs/protocol/design-decisions/utxo-consensus-problem.md ⭐⭐
├── Development: docs/dev/* (code quality, refactors, TODOs)
├── Operations: docs/ops/deployment-devnet.md, docs/ops/monitoring.md
└── CIS baseline: docs/security/cis-ig1-plan.md
    ├── v2/ (Design-2-*.md - future plans)
    └── legacy/ (100+ historical files - archive)
```

**Status:** ✅ Good organization, ready for mdBook migration

---

### Recommended Migration Approach (Updated for Current State)

**Your docs are already well-organized!** Migration is simpler than originally estimated.

**Recommended: Structured Copy (Best for current state)**

**Pros:**
- Clean mdBook structure
- Reuse existing high-quality content
- Minimal editing needed (files already organized)

**Cons:**
- Need to create directory structure
- Need to update internal links

**Process:**
1. Set up mdBook structure (30 min)
2. Copy docs according to category (2 hours)
3. Update SUMMARY.md (30 min)
4. Fix broken links (1 hour)
5. Deploy to GitHub Pages (30 min)

**Effort:** 1 day (4-6 hours)

---

### Migration Priority List (Based on Current Files)

**🔴 Priority 1: Critical User-Facing (Migrate First - Day 1)**

These 10 docs are essential for users:

1. **Introduction** (NEW - write 30 min)
2. **docs/guide/quickstart.md** → `getting-started/quickstart.md`
3. **docs/config/network-modes.md** → `configuration/network-modes.md` ⭐⭐⭐
4. **docs/config/iroh-discovery.md** → `configuration/iroh-discovery.md` ⭐⭐⭐
5. **docs/config/hyperlane.md** → `configuration/hyperlane.md` ⭐⭐
6. **docs/security/timing-attacks.md** → `security/cryptography/timing-attacks.md` ⭐⭐⭐
7. **docs/security/key-management-audit.md** → `security/key-management/audit.md` ⭐⭐⭐
8. **Igra-Protocol.md** → `protocol/architecture.md` ⭐⭐⭐
9. **docs/protocol/two-phase-consensus.md** → `protocol/two-phase.md` ⭐⭐⭐
10. **CODE-GUIDELINE.md** → `developer/code-guidelines.md` ⭐⭐⭐

**Effort:** 2-3 hours (mostly copy, light editing)

---

**🟡 Priority 2: Important Reference (Migrate Second - Day 2)**

These 15 docs provide important detail:

11. **docs/security/soc2-compliance.md** → `security/compliance/soc2.md`
12. **docs/security/timing-attacks-library-proof.md** → `security/cryptography/library-security.md`
13. **docs/security/key-management-extended-audit.md** → `security/key-management/extended-audit.md`
14. **docs/protocol/two-phase-implementation.md** → `protocol/two-phase/implementation.md`
15. **docs/ops/deployment-devnet.md** → `operations/deployment/devnet.md`
16. **docs/ops/monitoring.md** → `operations/monitoring.md`
17. **docs/protocol/anti-entropy.md** → `protocol/anti-entropy.md`
18. **docs/protocol/design-decisions/utxo-consensus-problem.md** → `protocol/design-decisions/utxo-consensus.md`
19. **docs/protocol/design-decisions/failure-modes.md** → `protocol/design-decisions/failure-modes.md`
20. **docs/protocol/design-decisions/privacy-analysis.md** → `protocol/design-decisions/privacy.md`
21. **docs/dev/code-quality-audit.md** → `developer/reference/quality.md`
22. **docs/security/audits/audit-v1.md** → `security/audit-reports/audit-v1.md`
23. **docs/guide/key-derivation.md** → `getting-started/key-derivation.md`
24. **docs/security/cis-ig1-plan.md** → `security/compliance/cis-ig1.md`
25. **docs/protocol/design-decisions/event-id-design.md** → `protocol/design-decisions/event-id.md`

**Effort:** 2-3 hours

---

**🟢 Priority 3: Supporting Material (Link, Don't Migrate)**

These files are internal/reference - link from main docs but don't migrate:

- `docs/config/network-modes-verification.md` - Link from network-modes.md
- `docs/config/network-modes-gaps.md` - Link from network-modes.md
- `docs/config/iroh-discovery-review.md` - Link from iroh-discovery.md
- `docs/config/iroh-discovery-gaps.md` - Link from iroh-discovery.md
- `docs/config/iroh-discovery-summary.md` - Link from iroh-discovery.md
- `docs/security/timing-attacks-overview.md` - Link from timing-attacks.md
- `docs/security/timing-attacks-quick-fix.md` - Include in timing-attacks.md as section
- `docs/security/timing-attacks-checklist.md` - Link from timing-attacks.md
- `docs/protocol/two-phase-review.md` - Include as subsection
- `docs/dev/refactoring-*.md` (tracking) - Internal history and planning
- `docs/dev/todo-fixes.md`, `docs/dev/followup-todos.md` - Internal tracking
- `docs/dev/code-quality-report.md` - Internal status report

**Action:** Add "Internal Documentation" appendix with links to these files

---

**❌ Don't Migrate (Archive Only):**

- `docs/legacy/` (100+ files) - Historical, keep for reference
- `v2/` design docs - Future plans, not current
- `two-phase-algo/` - Empty directory (can delete)

---

### Your Updated Migration Strategy

**Based on current organization, here's the streamlined approach:**

**Step 1 (Day 1 - 4 hours):** Bootstrap
- Install mdBook
- Create structure (SUMMARY.md)
- Migrate 10 priority docs
- Deploy to GitHub Pages

**Step 2 (Day 2 - 4 hours):** Expand
- Migrate 15 important docs
- Fix broken links
- Add FAQ and glossary

**Step 3 (Day 3 - 4 hours):** Polish
- Review all content
- Add diagrams
- Test all examples
- Team review

**Deliverable:** Professional documentation site with 40+ pages in 3 days

---

## 19. Example: Your First mdBook Page

### Create Getting Started

**File:** `book/src/getting-started/installation.md`

```markdown
# Installation

This guide shows you how to install and run Igra threshold signing service.

## Prerequisites

- Rust 1.75+ (`rustc --version`)
- Kaspa node (kaspad)
- Linux/macOS (recommended) or Windows

## Install from Source

\`\`\`bash
# Clone repository
git clone https://github.com/kaspanet/rusty-kaspa.git
cd rusty-kaspa/wallet/igra

# Build release binary
cargo build --release --bin kaspa-threshold-service

# Verify installation
./target/release/kaspa-threshold-service --version
\`\`\`

## Quick Start (Devnet)

\`\`\`bash
# Generate devnet keys
cargo run --release --bin devnet-keygen > devnet-config.json

# Create configuration
cat > config.toml << 'EOF'
[service]
network = "devnet"
node_rpc_url = "grpc://127.0.0.1:16210"
data_dir = ".igra-devnet"
EOF

# Start service
cargo run --release --bin kaspa-threshold-service -- \
    --network devnet \
    --config config.toml
\`\`\`

**Expected output:**
\`\`\`
[INFO] kaspa-threshold-service starting network=devnet
[INFO] iroh endpoint bound endpoint_id=peer-a1b2c3...
[INFO] service started rpc_port=8080
\`\`\`

## Next Steps

- [Configure for Testnet](../configuration/testnet.md)
- [Configure for Mainnet](../configuration/mainnet.md)
- [Security Best Practices](../security/best-practices.md)
```

---

## 20. Final Recommendations (Updated for Current State)

### For Igra Specifically

**YOUR DOCS ARE ALREADY WELL-ORGANIZED!** Migration is straightforward.

**⭐ SEE docs/dev/documentation-refactoring-plan.md FOR DETAILED INSTRUCTIONS ⭐**

---

**Immediate (This Week - 1 Day):**

**Use the step-by-step guide in docs/dev/documentation-refactoring-plan.md:**

1. ✅ **Phase 1, Steps 1-8** (4 hours total)
   - Install mdBook tools (10 min)
   - Initialize structure (15 min)
   - Configure book.toml (15 min)
   - Create SUMMARY.md from template (30 min)
   - Copy 10 priority docs (2 hours) ← **Most important files already identified**
   - Build and test locally (10 min)
   - Deploy to GitHub Pages (30 min)
   - Verify deployment (10 min)

**Deliverable:** https://[org].github.io/rusty-kaspa/igra/ (live docs, 15+ pages)

---

**Short-Term (This Month - 2-3 Days):**

**Continue with docs/dev/documentation-refactoring-plan.md:**

- Phase 2: Migrate 15 important docs (4 hours)
- Phase 3: Migrate remaining docs (4 hours)
- Phase 4: Polish and review (4 hours)

**Deliverable:** Complete documentation (40+ pages, professional quality)

---

**Long-Term (Ongoing):**
- Maintain docs as code (PR workflow)
- Add tutorials and examples
- Keep FAQ updated
- Quarterly content review
- Consider GitBook for customer-facing docs (if needed)

---

### Key Files for Your Team

**For implementation:**
1. **docs/dev/documentation-refactoring-plan.md** ← **START HERE**
   - Current file inventory (all 55 files categorized)
   - Step-by-step migration commands
   - File mapping table (current → book location)
   - Timeline and effort estimates

2. **docs/dev/documentation-guide.md** (this file)
   - Background on mdBook vs GitBook
   - Best practices for crypto project docs
   - Long-term strategy

**Division of work:**
- **Developer 1:** Run `docs/dev/documentation-refactoring-plan.md` Phase 1 (bootstrap)
- **Developer 2:** Write new content (intro, installation, FAQ)
- **Both:** Review and polish (Phase 4)

---

### Current File Organization (Actual State)

```
Your files are at:
├── / (root)
│   ├── CODE-GUIDELINE.md ⭐⭐⭐
│   └── Igra-Protocol.md ⭐⭐⭐
│
└── /docs
    ├── Configuration (8 files) ⭐⭐⭐
    │   ├── docs/config/network-modes.md
    │   ├── docs/config/iroh-discovery.md
    │   └── docs/config/hyperlane.md
    ├── Security (11 files) ⭐⭐⭐
    │   ├── docs/security/timing-attacks.md
    │   ├── docs/security/key-management-audit.md
    │   └── docs/security/soc2-compliance.md
    ├── Protocol (10 files) ⭐⭐
    │   ├── docs/protocol/two-phase-consensus.md
    │   └── docs/protocol/design-decisions/utxo-consensus-problem.md
    ├── Developer (10 files) ⭐⭐
    │   └── docs/dev/code-quality-audit.md
    ├── Operations (4 files) ⭐
    │   ├── docs/ops/deployment-devnet.md
    │   └── docs/ops/monitoring.md
    └── Subdirectories
        ├── docs/security/cis-ig1-plan.md
        ├── docs/wip/ (future design)
        └── legacy/ (archive - don't migrate)

Total active: 51 files (manageable!)
```

**See docs/dev/documentation-refactoring-plan.md for complete file-by-file mapping.**

---

### Documentation as a Product

**Treat documentation as:**
- ✅ **First-class deliverable** (not afterthought)
- ✅ **User interface** (for developers, it's the UI)
- ✅ **Marketing tool** (good docs attract users)
- ✅ **Support reducer** (good docs = fewer questions)
- ✅ **Security control** (documents secure usage)

**For a security-critical project like Igra, documentation quality = security quality**

---

## Conclusion

**mdBook is the right choice for Igra:**
- ✅ Free and open source
- ✅ Rust ecosystem standard
- ✅ Easy to set up (1 hour)
- ✅ GitHub Pages deployment (zero cost)
- ✅ Perfect for technical documentation

**Action Plan:**
1. **This week:** Set up mdBook, migrate top 5 docs, deploy
2. **This month:** Migrate all active docs, add examples
3. **This quarter:** Polish, expand, iterate

**Time investment:** 2-3 days upfront, 2-4 hours/month maintenance

**Result:** Professional, searchable, maintainable documentation that helps users deploy Igra securely

---

**Start now:** `cargo install mdbook && mdbook init`

**Questions?** See examples:
- Rust Book: https://doc.rust-lang.org/book/
- mdBook Guide: https://rust-lang.github.io/mdBook/
- Tokio Tutorial: https://tokio.rs/tokio/tutorial

---

**End of Guide**

**Status:** Ready to implement
**Recommended Tool:** mdBook
**Estimated Effort:** 2-3 days initial setup, 2-4 hours/month maintenance
