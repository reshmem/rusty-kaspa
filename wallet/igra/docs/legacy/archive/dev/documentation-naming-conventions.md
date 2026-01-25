# Documentation Naming Conventions & Organization

**Date:** 2026-01-24
**Status:** Team Standards
**Applies To:** All documentation created during design, development, and production phases

**Repository state:** As of 2026-01-24, the `docs/` tree has been reorganized to match the category directories described in this document (`docs/config`, `docs/security`, `docs/protocol`, `docs/dev`, `docs/ops`, `docs/guide`, `docs/wip`).

---

## Executive Summary

**Problem:** Inconsistent naming makes it hard to find docs and migrate to mdBook later

**Solution:** Standardized naming conventions + clear lifecycle workflow

**Key Principles:**
1. **Descriptive names** over abbreviations
2. **Lifecycle suffixes** indicate document status
3. **Consistent casing** (kebab-case for files)
4. **Clear categories** via directory structure

**Result:** Easy to find docs, easy to migrate to book, easy to maintain

---

## Table of Contents

1. [File Naming Conventions](#1-file-naming-conventions)
2. [Document Lifecycle](#2-document-lifecycle)
3. [Directory Organization](#3-directory-organization)
4. [Renaming Current Docs](#4-renaming-current-docs)
5. [Developer Workflow](#5-developer-workflow)
6. [Migration to mdBook](#6-migration-to-mdbook)
7. [Examples and Templates](#7-examples-and-templates)

---

## 1. File Naming Conventions

### 1.1 Basic Rules

**Format:** `topic[-subtopic][-lifecycle].md` (category comes from the directory)

**Rules:**
- ✅ Use kebab-case (lowercase with hyphens)
- ✅ Be descriptive (no abbreviations except well-known: API, RPC, PSKT)
- ✅ Include lifecycle suffix (see Section 2)
- ✅ Put the file in the correct category directory (helps sorting)
- ❌ No spaces, underscores, or mixed case
- ❌ No version numbers in filename (use git tags)

---

### 1.2 Naming Pattern

```
[topic]-[subtopic]-[lifecycle].md

Examples:
✅ docs/security/timing-attacks.md                 (primary doc)
✅ docs/security/timing-attacks-quick-fix.md       (reference)
✅ docs/config/network-modes.md                    (primary doc)
✅ docs/config/network-modes-verification.md       (verification report)
✅ docs/protocol/two-phase-consensus.md            (primary doc)
✅ docs/protocol/two-phase-implementation.md       (implementation guide)
```

---

### 1.3 Category Directories

Use these directories as the first-level categories:

| Category | Directory | Example |
|----------|-----------|---------|
| Getting started | `docs/guide/` | `docs/guide/quickstart.md` |
| Configuration | `docs/config/` | `docs/config/network-modes.md` |
| Security | `docs/security/` | `docs/security/key-management-audit.md` |
| Protocol | `docs/protocol/` | `docs/protocol/two-phase-consensus.md` |
| Protocol decisions | `docs/protocol/design-decisions/` | `docs/protocol/design-decisions/utxo-consensus-problem.md` |
| Operations | `docs/ops/` | `docs/ops/deployment-devnet.md` |
| Developer | `docs/dev/` | `docs/dev/code-quality-audit.md` |
| Work in progress | `docs/wip/` | `docs/wip/v2-design.md` |
| Archive | `docs/legacy/` | (keep original names) |

---

### 1.4 Lifecycle Suffixes

**Indicates document maturity/purpose:**

| Suffix | Meaning | Migrate to Book? | Example |
|--------|---------|------------------|---------|
| *(none)* | Primary/canonical doc | ✅ YES | `timing-attacks.md` |
| `-guide` | How-to guide | ✅ YES | `quickstart-guide.md` |
| `-spec` | Formal specification | ✅ YES | `two-phase-spec.md` |
| `-implementation` | Implementation guide | ✅ YES (as subsection) | `two-phase-implementation.md` |
| `-design` | Design proposal | ⚠️ MAYBE | `design-frost-integration.md` |
| `-review` | Review/analysis | ❌ NO (link only) | `two-phase-review.md` |
| `-verification` | Verification report | ❌ NO (link only) | `network-modes-verification.md` |
| `-gaps` | Gap analysis | ❌ NO (link only) | `iroh-discovery-gaps.md` |
| `-checklist` | Implementation tracking | ❌ NO (reference) | `timing-attacks-checklist.md` |
| `-audit` | Audit report | ✅ YES | `key-management-audit.md` |
| `-wip` | Work in progress | ❌ NO (temporary) | `design-v2-architecture-wip.md` |
| `-notes` | Development notes | ❌ NO (internal) | `refactoring-notes.md` |
| `-todo` | TODO tracking | ❌ NO (internal) | `crdt-gossip-todo.md` |
| `-draft` | Draft version | ❌ NO (becomes primary when done) | `guide-installation-draft.md` |

---

### 1.5 Bad Names vs Good Names

**❌ BAD (Current state examples):**
```
TWO-PHASE-PROTOCOL.md                    (ALL CAPS, no category)
TIMING-ATTACK-ANALYSIS.md                (ALL CAPS, no category)
NetworkMode-Security.md                  (MixedCase, no category)
Iroh-Discovery.md                        (No category, capitalized)
Code-Quality-Progress-Report.md          (Too specific, mixed case)
FOLLOWUP-TODO-FIXES.md                   (ALL CAPS, vague)
Igra-Obeserver.md                        (Typo!)
```

**✅ GOOD (Proposed renames):**
```
docs/protocol/two-phase-consensus.md
docs/security/timing-attacks.md
docs/config/network-modes.md
docs/config/iroh-discovery.md
docs/dev/code-quality-report.md
docs/dev/followup-todos.md
docs/ops/monitoring.md
```

---

## 2. Document Lifecycle

### 2.1 Lifecycle Stages

```
1. DESIGN PHASE (Exploration)
   ├── design-[topic]-proposal.md        (Initial idea)
   ├── design-[topic]-alternatives.md    (Options analysis)
   └── design-[topic]-decision.md        (Final decision)
          │
          ▼
2. IMPLEMENTATION PHASE (Active Development)
   ├── [topic]-wip.md                    (Work in progress)
   ├── [topic]-implementation.md         (How to implement)
   ├── [topic]-checklist.md              (Tracking)
   └── [topic]-notes.md                  (Dev notes)
          │
          ▼
3. REVIEW PHASE (Quality Assurance)
   ├── [topic]-review.md                 (Code/design review)
   ├── [topic]-verification.md           (Verification report)
   ├── [topic]-gaps.md                   (Gap analysis)
   └── [topic]-testing.md                (Test report)
          │
          ▼
4. PUBLISHED PHASE (Production Documentation)
   ├── [topic].md                        (Primary doc)
   ├── [topic]-guide.md                  (User guide)
   ├── [topic]-spec.md                   (Formal spec)
   └── [topic]-audit.md                  (Audit report)
          │
          ▼
5. ARCHIVED PHASE (Historical Reference)
   └── docs/legacy/[category]/[topic].md (Historical)
```

---

### 2.2 Document Lifecycle Rules

**Design Phase Documents:**
- **Location:** `docs/design/` or `docs/wip/`
- **Naming:** `design-[topic]-*.md`
- **Status header:** `Status: DRAFT - For Discussion`
- **Migrate to book:** ⚠️ Only after implementation complete

**Implementation Phase Documents:**
- **Location:** `docs/` (root of category)
- **Naming:** `[topic]-implementation.md`
- **Status header:** `Status: IMPLEMENTATION IN PROGRESS`
- **Migrate to book:** ✅ As subsection of main doc

**Review Phase Documents:**
- **Location:** `docs/` (alongside main doc)
- **Naming:** `[topic]-review.md`
- **Status header:** `Status: REVIEW COMPLETE`
- **Migrate to book:** ❌ Link from main doc, don't include in book

**Published Phase Documents:**
- **Location:** `docs/` (ready for book)
- **Naming:** `[topic].md`
- **Status header:** `Status: ✅ CURRENT` or `Version: v0.5.0`
- **Migrate to book:** ✅ PRIMARY CONTENT

**Archived Phase Documents:**
- **Location:** `docs/legacy/[category]/`
- **Naming:** Original name preserved
- **Status header:** `Status: ARCHIVED - See [new doc]`
- **Migrate to book:** ❌ Reference only

---

## 3. Directory Organization

### 3.1 Recommended Structure (During Development)

```
rusty-kaspa/wallet/igra/
│
├── README.md                           # Project README (always root)
├── CODE-GUIDELINE.md                   # Code standards (always root)
│
├── docs/                               # Active documentation
│   │
│   ├── wip/                            # Work in progress (temporary)
│   │   ├── design-frost-integration-proposal.md
│   │   ├── design-protocol-v2-architecture-draft.md
│   │   └── README.md (explains this directory)
│   │
│   ├── config/                         # Configuration documentation
│   │   ├── network-modes.md            (primary)
│   │   ├── network-modes-verification.md (meta)
│   │   ├── network-modes-gaps.md       (meta)
│   │   ├── iroh-discovery.md           (primary)
│   │   ├── iroh-discovery-review.md    (meta)
│   │   ├── hyperlane.md                (primary)
│   │   └── secrets-management.md       (primary)
│   │
│   ├── security/                       # Security documentation
│   │   ├── timing-attacks.md           (primary)
│   │   ├── timing-attacks-implementation.md (meta)
│   │   ├── timing-attacks-checklist.md (meta)
│   │   ├── timing-attacks-library-proof.md (meta)
│   │   ├── key-management-audit.md     (primary)
│   │   ├── soc2-compliance.md          (primary)
│   │   └── cis-ig1-plan.md             (primary)
│   │
│   ├── protocol/                       # Protocol documentation
│   │   ├── architecture.md             (primary)
│   │   ├── two-phase-consensus.md      (primary)
│   │   ├── two-phase-implementation.md (meta)
│   │   ├── two-phase-review.md  (meta)
│   │   ├── crdt-gossip.md              (primary)
│   │   ├── pskt.md                     (primary)
│   │   └── design-decisions/
│   │       ├── utxo-consensus.md
│   │       ├── privacy-analysis.md
│   │       └── failure-modes.md
│   │
│   ├── ops/                            # Operations documentation
│   │   ├── deployment-devnet.md
│   │   ├── deployment-testnet.md
│   │   ├── deployment-mainnet.md
│   │   ├── monitoring.md
│   │   └── troubleshooting.md
│   │
│   ├── dev/                            # Developer documentation
│   │   ├── code-guidelines.md
│   │   ├── architecture.md
│   │   ├── building.md
│   │   ├── testing.md
│   │   └── contributing.md
│   │
│   ├── api/                            # API documentation
│   │   ├── json-rpc.md
│   │   ├── websocket-events.md
│   │   └── examples.md
│   │
│   └── legacy/                         # Historical archive
│       ├── dev-proc/                   (development logs)
│       ├── refactoring/                (refactoring steps)
│       ├── security/                   (old security docs)
│       └── ...
│
├── book/                               # mdBook (after migration)
│   ├── book.toml
│   ├── src/
│   │   ├── SUMMARY.md
│   │   └── ... (mirrors docs/ structure)
│   └── book/ (generated, gitignored)
│
└── examples/                           # Runnable code examples
    ├── sign-pskt.rs
    ├── configure-network.rs
    └── ...
```

---

### 3.2 Directory Purpose

| Directory | Purpose | Migrate to Book? | Naming Convention |
|-----------|---------|------------------|-------------------|
| `docs/wip/` | Work in progress, design docs | ❌ NO | `design-*-draft.md` |
| `docs/config/` | Configuration guides | ✅ YES (primary) | `[topic].md` |
| `docs/security/` | Security docs | ✅ YES (primary) | `[topic].md` |
| `docs/protocol/` | Protocol specs | ✅ YES (primary) | `[topic].md` |
| `docs/ops/` | Operations guides | ✅ YES (primary) | `deployment-*.md` |
| `docs/dev/` | Developer guides | ✅ YES (primary) | `[topic].md` |
| `docs/api/` | API reference | ✅ YES (primary) | `[api-type].md` |
| `docs/legacy/` | Historical archive | ❌ NO | Original names |

---

## 4. Renaming Current Docs

### 4.1 Historical Renames (Pre-2026-01-24 → Current)

**Use this table to rename your existing files:**

#### Root Level

| Current | Category | New Name | Reason |
|---------|----------|----------|--------|
| `Igra-Protocol.md` | Protocol | `docs/protocol/architecture.md` | Better location |
| `CODE-GUIDELINE.md` | Dev | Keep as-is (root) | Standard location |
| `AGENTS.md` | Internal | Keep as-is (root) | Internal tool |

#### Configuration Documents

| Current | New Name | Directory | Reason |
|---------|----------|-----------|--------|
| `NetworkMode-Security.md` | `network-modes.md` | `docs/config/` | Simpler name |
| `NetworkMode-Security-VERIFICATION.md` | `network-modes-verification.md` | `docs/config/` | Add lifecycle suffix |
| `NetworkMode-Security-GAPS.md` | `network-modes-gaps.md` | `docs/config/` | Add lifecycle suffix |
| `Iroh-Discovery.md` | `iroh-discovery.md` | `docs/config/` | Lowercase |
| `Iroh-Discovery-REVIEW.md` | `iroh-discovery-review.md` | `docs/config/` | Lowercase + suffix |
| `Iroh-Discovery-GAPS.md` | `iroh-discovery-gaps.md` | `docs/config/` | Lowercase + suffix |
| `Iroh-Discovery-FINAL-SUMMARY.md` | `iroh-discovery-summary.md` | `docs/config/` | Simpler suffix |
| `HYPERLANE-INTEGRATION.md` | `hyperlane.md` | `docs/config/` | Simpler name |

#### Security Documents

| Current | New Name | Directory | Reason |
|---------|----------|-----------|--------|
| `TIMING-ATTACK-ANALYSIS.md` | `timing-attacks.md` | `docs/security/` | Simpler name |
| `TIMING-ATTACK-IMPLEMENTATION-CHECKLIST.md` | `timing-attacks-checklist.md` | `docs/security/` | Lowercase |
| `TIMING-ATTACK-LIBRARY-PROOF-SUMMARY.md` | `timing-attacks-library-proof.md` | `docs/security/` | Simpler |
| `TIMING-ATTACK-QUICK-FIX.md` | `timing-attacks-quick-fix.md` | `docs/security/` | Lowercase |
| `TIMING-ATTACK-README.md` | `timing-attacks-overview.md` | `docs/security/` | Better suffix |
| `KEY-MANAGEMENT-AUDIT.md` | `key-management-audit.md` | `docs/security/` | Lowercase |
| `IGRA-KEY-MANAGEMENT-AUDIT.md` | `key-management-extended-audit.md` | `docs/security/` | Descriptive |
| `Key-Management-Diagram.md` | `key-management-diagrams.md` | `docs/security/` | Lowercase |
| `SOC2.md` | `soc2-compliance.md` | `docs/security/` | More descriptive |
| `SECURITY-ISSUES-REMEDIATION.md` | `security-issues-remediation.md` | `docs/security/` | Lowercase |
| `SECURITY-QUICK-CHECK.md` | `security-quick-check.md` | `docs/security/` | Lowercase |

#### Protocol Documents

| Current | New Name | Directory | Reason |
|---------|----------|-----------|--------|
| `Igra-Protocol.md` | `architecture.md` | `docs/protocol/` | Move from root |
| `TWO-PHASE-PROTOCOL.md` | `two-phase-consensus.md` | `docs/protocol/` | More descriptive |
| `TWO-PHASE-PROTOCOL-IMPLEMENTATION.md` | `two-phase-implementation.md` | `docs/protocol/` | Lowercase |
| `TWO-PHASE-PROTOCOL-EXPERT-REVIEW.md` | `two-phase-review.md` | `docs/protocol/` | Simpler |
| `UTXO_CONSENSUS_PROBLEM.md` | `utxo-consensus-problem.md` | `docs/protocol/design-decisions/` | Lowercase |
| `ANTI_ENTROPY_ENHANCEMENT.md` | `anti-entropy.md` | `docs/protocol/` | Simpler |
| `DISTRIBUTED-SYSTEM-FAILURE-ANALYSIS.md` | `failure-modes.md` | `docs/protocol/design-decisions/` | Simpler |
| `Origin-Destination-Linkability.md` | `privacy-analysis.md` | `docs/protocol/design-decisions/` | More descriptive |

#### Developer Documents

| Current | New Name | Directory | Reason |
|---------|----------|-----------|--------|
| `Code-Quality-Audit.md` | `code-quality-audit.md` | `docs/dev/` | Lowercase |
| `Code-Quality-Progress-Report.md` | `code-quality-report.md` | `docs/dev/` | Simpler |
| `Refactoring-Audit-2026.md` | `refactoring-audit-2026.md` | `docs/dev/` | Lowercase |
| `Refactoring-TODOs.md` | `refactoring-todos.md` | `docs/dev/` | Lowercase |
| `Refactor-HexEncode.md` | `hex-encoding-refactor.md` | `docs/dev/` | Better order |
| `Hex-Refactor.md` | `hex-refactor.md` | `docs/dev/` | Lowercase |
| `Hex-Refactor-Completion.md` | `hex-refactor-completion.md` | `docs/dev/` | Lowercase |

#### Operations Documents

| Current | New Name | Directory | Reason |
|---------|----------|-----------|--------|
| `Hyperlane-devnet.md` | `deployment-devnet.md` | `docs/ops/` | Better prefix |
| `Observability.md` | `monitoring.md` | `docs/ops/` | Simpler name |
| `Igra-Obeserver.md` | `observer-setup.md` | `docs/ops/` | Fix typo |

#### Getting Started

| Current | New Name | Directory | Reason |
|---------|----------|-----------|--------|
| `Kaspa-Signers-Hyperlane-HowTo.md` | `quickstart.md` | `docs/guide/` | Simpler |
| `DERIVATION.md` | `key-derivation.md` | `docs/guide/` | Lowercase |

#### Other

| Current | New Name | Directory | Reason |
|---------|----------|-----------|--------|
| `Audit-v1.md` | `audit-v1.md` | `docs/security/audits/` | Lowercase, subdir |
| `TODO-FIXES.md` | `todo-fixes.md` | `docs/dev/` | Lowercase, dev dir |
| `FOLLOWUP-TODO-FIXES.md` | `followup-todos.md` | `docs/dev/` | Simpler |

---

### 4.2 Bulk Rename Script

**Use this script to rename all files at once:**

```bash
#!/bin/bash
# rename-docs.sh - Standardize documentation naming

cd /Users/user/Source/personal/rusty-kaspa/wallet/igra

# Create new directory structure
mkdir -p docs/{config,security,protocol/design-decisions,ops,dev,guide,api}
mkdir -p docs/security/audits
mkdir -p docs/wip

echo "📁 Creating directory structure..."

# Configuration
mv docs/NetworkMode-Security.md docs/config/network-modes.md
mv docs/NetworkMode-Security-VERIFICATION.md docs/config/network-modes-verification.md
mv docs/NetworkMode-Security-GAPS.md docs/config/network-modes-gaps.md
mv docs/Iroh-Discovery.md docs/config/iroh-discovery.md
mv docs/Iroh-Discovery-REVIEW.md docs/config/iroh-discovery-review.md
mv docs/Iroh-Discovery-GAPS.md docs/config/iroh-discovery-gaps.md
mv docs/Iroh-Discovery-FINAL-SUMMARY.md docs/config/iroh-discovery-summary.md
mv docs/HYPERLANE-INTEGRATION.md docs/config/hyperlane.md

# Security
mv docs/TIMING-ATTACK-ANALYSIS.md docs/security/timing-attacks.md
mv docs/TIMING-ATTACK-IMPLEMENTATION-CHECKLIST.md docs/security/timing-attacks-checklist.md
mv docs/TIMING-ATTACK-LIBRARY-PROOF-SUMMARY.md docs/security/timing-attacks-library-proof.md
mv docs/TIMING-ATTACK-QUICK-FIX.md docs/security/timing-attacks-quick-fix.md
mv docs/TIMING-ATTACK-README.md docs/security/timing-attacks-overview.md
mv docs/KEY-MANAGEMENT-AUDIT.md docs/security/key-management-audit.md
mv docs/IGRA-KEY-MANAGEMENT-AUDIT.md docs/security/key-management-extended-audit.md
mv docs/Key-Management-Diagram.md docs/security/key-management-diagrams.md
mv docs/KeyManager-Design.md docs/security/key-manager-design.md
mv docs/KeyManagement-Refactor.md docs/security/key-management-refactor.md
mv docs/Key-Management-TODOs.md docs/security/key-management-todos.md
mv docs/RawPrivKey-Feature.md docs/security/raw-privkey-feature.md
mv docs/SOC2.md docs/security/soc2-compliance.md
mv docs/SECURITY-ISSUES-REMEDIATION.md docs/security/issues-remediation.md
mv docs/SECURITY-QUICK-CHECK.md docs/security/quick-check.md
mv docs/Audit-v1.md docs/security/audits/audit-v1.md
mv docs/security/CIS-IG1-Plan.md docs/security/cis-ig1-plan.md

# Protocol
mv Igra-Protocol.md docs/protocol/architecture.md
mv docs/Igra-Protocol.md docs/protocol/architecture-v2.md 2>/dev/null || true
mv docs/TWO-PHASE-PROTOCOL.md docs/protocol/two-phase-consensus.md
mv docs/TWO-PHASE-PROTOCOL-IMPLEMENTATION.md docs/protocol/two-phase-implementation.md
mv docs/TWO-PHASE-PROTOCOL-EXPERT-REVIEW.md docs/protocol/two-phase-review.md
mv docs/2-phase-algo-v1.md docs/protocol/two-phase-algo-v1.md
mv docs/2-phase-algo-v1-current.md docs/protocol/two-phase-algo-current.md
mv docs/UTXO_CONSENSUS_PROBLEM.md docs/protocol/design-decisions/utxo-consensus.md
mv docs/ANTI_ENTROPY_ENHANCEMENT.md docs/protocol/anti-entropy.md
mv docs/DISTRIBUTED-SYSTEM-FAILURE-ANALYSIS.md docs/protocol/design-decisions/failure-modes.md
mv docs/Origin-Destination-Linkability.md docs/protocol/design-decisions/privacy-analysis.md
mv docs/Event-ID-signle-sign-per-TX-HASH.md docs/protocol/design-decisions/event-id-design.md

# Operations
mv docs/Hyperlane-devnet.md docs/ops/deployment-devnet.md
mv docs/Observability.md docs/ops/monitoring.md
mv docs/Igra-Obeserver.md docs/ops/observer-setup.md

# Developer
mv docs/Code-Quality-Audit.md docs/dev/code-quality-audit.md
mv docs/Code-Quality-Progress-Report.md docs/dev/code-quality-report.md
mv docs/Refactoring-Audit-2026.md docs/dev/refactoring-audit-2026.md
mv docs/Refactoring-TODOs.md docs/dev/refactoring-todos.md
mv docs/Refactor.md docs/dev/refactor-general.md
mv docs/Refactor-HexEncode.md docs/dev/hex-encoding-refactor.md
mv docs/Hex-Refactor.md docs/dev/hex-refactor.md
mv docs/Hex-Refactor-Completion.md docs/dev/hex-refactor-completion.md
mv docs/TODO-FIXES.md docs/dev/todo-fixes.md
mv docs/FOLLOWUP-TODO-FIXES.md docs/dev/followup-todos.md
mv docs/FIXES_CRDT_GOSSIP_VALIDATION.md docs/dev/crdt-gossip-fixes.md

# Getting Started
mv docs/Kaspa-Signers-Hyperlane-HowTo.md docs/guide/quickstart.md
mv docs/DERIVATION.md docs/guide/key-derivation.md

# WIP / Design
mv docs/v2/Design-2-Exec-Plan.md docs/wip/v2-execution-plan.md
mv docs/v2/Design-2-Impl.md docs/wip/v2-implementation.md
mv docs/v2/Desing-2.md docs/wip/v2-design.md

# Create README files
cat > docs/wip/README.md << 'EOF'
# Work in Progress

This directory contains draft documents, design proposals, and work-in-progress documentation.

**Status:** These docs are NOT finalized and may be outdated.

**Naming:** `design-[topic]-*.md` or `[topic]-draft.md`

**Lifecycle:** When design is approved and implemented, move to appropriate category directory.
EOF

echo "✅ Rename complete!"
echo "📊 Run: git status to see changes"
echo "⚠️  Review changes before committing!"
```

**Execute:**
```bash
chmod +x rename-docs.sh
./rename-docs.sh
git status  # Review all moves
```

---

### 4.3 Git-Friendly Renaming

**To preserve git history when renaming:**

```bash
# Option 1: Git mv (preserves history)
git mv docs/NetworkMode-Security.md docs/config/network-modes.md

# Option 2: Bulk rename with script, then commit
./rename-docs.sh
git add -A
git commit -m "docs: reorganize into category directories

- Move files to category subdirectories (config/, security/, protocol/, etc.)
- Rename to lowercase kebab-case for consistency
- Add lifecycle suffixes (*-review, *-gaps, *-verification)
- Create docs/wip/ for work-in-progress docs

No content changes, only file organization."
```

---

## 5. Developer Workflow

### 5.1 Creating New Documentation During Development

**Follow this process:**

#### Phase 1: Design (Before Coding)

**When:** You're designing a new feature (e.g., FROST integration)

**Create:**
```bash
# Design proposal
vim docs/wip/design-frost-integration-proposal.md
```

**Template:**
```markdown
# FROST Integration - Design Proposal

**Status:** DRAFT - For Discussion
**Author:** [Your Name]
**Date:** 2026-01-24
**Related Issue:** #123

## Problem Statement

Why do we need FROST?

## Proposed Solution

How will we integrate FROST?

## Alternatives Considered

What other options did we evaluate?

## Decision

Which approach did we choose and why?

## Implementation Plan

High-level steps (link to -implementation.md when created)

## Open Questions

- [ ] Question 1?
- [ ] Question 2?
```

**Naming:**
- `design-[feature]-proposal.md` - Initial design
- `design-[feature]-alternatives.md` - Options analysis
- `design-[feature]-decision.md` - Final decision

**Location:** `docs/wip/`

**Lifecycle:** When approved → Becomes implementation doc

---

#### Phase 2: Implementation (During Coding)

**When:** You're actively implementing the feature

**Create:**
```bash
# Implementation guide
vim docs/wip/[category]-[feature]-implementation.md
```

**Template:**
```markdown
# [Feature] - Implementation Guide

**Status:** IMPLEMENTATION IN PROGRESS
**Author:** [Your Name]
**Date:** 2026-01-24
**Related PR:** #456

## Overview

Brief description of what's being implemented.

## Implementation Steps

### Step 1: [Task]

**File:** `path/to/file.rs`

**Code:**
\`\`\`rust
// Code example
\`\`\`

**Verification:**
\`\`\`bash
cargo test [test_name]
\`\`\`

### Step 2: [Task]

...

## Testing

How to verify the implementation works.

## Known Issues

- [ ] Issue 1
- [ ] Issue 2

## Next Steps

What remains to be done.
```

**Naming:** `[category]-[feature]-implementation.md`

**Location:** `docs/wip/` (while in progress)

**Lifecycle:** When complete → Move to category dir, remove WIP status

---

#### Phase 3: Review (After Coding)

**When:** Implementation is complete, needs review

**Create:**
```bash
# Review document
vim docs/[category]/[feature]-review.md
```

**Template:**
```markdown
# [Feature] - Implementation Review

**Status:** REVIEW COMPLETE
**Reviewer:** [Reviewer Name]
**Date:** 2026-01-24
**Related PR:** #456

## Summary

Brief summary of what was implemented.

## Verification Results

- ✅ All tests pass
- ✅ Code follows CODE-GUIDELINE.md
- ✅ Documentation updated
- ⚠️ Performance needs monitoring

## Gaps Found

- Gap 1: [Description]
- Gap 2: [Description]

## Recommendations

- [ ] Recommendation 1
- [ ] Recommendation 2

## Sign-Off

**Approved:** ☐ Yes ☐ No
**Reviewer:** ________________
**Date:** ________________
```

**Naming:** `[category]-[feature]-review.md`

**Location:** Same directory as main doc

**Lifecycle:** Reference document (link from main doc)

---

#### Phase 4: Production Documentation (After Merge)

**When:** Feature is merged and released

**Create/Update:**
```bash
# Primary documentation
vim docs/[category]/[feature].md
```

**Template:**
```markdown
# [Feature]

**Version:** v0.5.0
**Status:** ✅ CURRENT
**Last Updated:** 2026-01-24

## Overview

What is this feature?

## Configuration

How to configure it.

## Usage

How to use it.

## Examples

Complete working examples.

## Troubleshooting

Common issues and solutions.

## References

- [Implementation Guide]([feature]-implementation.md)
- [Review Report]([feature]-review.md)
- [API Reference](../api/[relevant-api].md)
```

**Naming:** `[category]-[feature].md` (no suffix = primary doc)

**Location:** `docs/[category]/`

**Lifecycle:** Ready for mdBook migration

---

### 5.2 Documentation States and Headers

**Every document should have a status header:**

```markdown
**Status:** [STATE]
**Version:** [VERSION]
**Last Updated:** [DATE]
```

**Valid states:**

| State | Meaning | Action |
|-------|---------|--------|
| `DRAFT - For Discussion` | Design phase | Get feedback, iterate |
| `IMPLEMENTATION IN PROGRESS` | Active development | Update as you code |
| `REVIEW PENDING` | Ready for review | Assign reviewer |
| `REVIEW COMPLETE` | Review done | Address gaps, finalize |
| `✅ CURRENT` | Production documentation | Keep updated |
| `⚠️ OUTDATED` | Needs update | Update or archive |
| `ARCHIVED - See [link]` | Historical | Don't update |

---

### 5.3 Linking Between Documents

**Use consistent link patterns:**

**During development (before mdBook):**
```markdown
<!-- Link to docs in same category -->
See [Key Management](./key-management-audit.md)

<!-- Link to docs in different category -->
See [Network Modes](../config/network-modes.md)

<!-- Link to code -->
See `igra-core/src/domain/crdt/event_state.rs:102`

<!-- Link to external -->
See [Rust Book](https://doc.rust-lang.org/book/)
```

**After migration to mdBook:**
```markdown
<!-- mdBook uses absolute paths from src/ root -->
See [Key Management](../security/key-management-audit.md)
See [Network Modes](../configuration/network-modes.md)
```

**Best practice:** Use relative paths (work in both contexts)

---

## 6. Migration to mdBook

### 6.1 Document Categorization for mdBook

**Primary docs (migrate to book):**
- ✅ No lifecycle suffix or `-guide`, `-spec`, `-audit`
- ✅ Status: `✅ CURRENT`
- ✅ User-facing or developer-facing

**Meta docs (link only, don't migrate):**
- ❌ Suffixes: `-review`, `-verification`, `-gaps`, `-checklist`
- ❌ Status: Internal tracking
- ❌ Purpose: Quality assurance, not user documentation

**WIP docs (don't migrate yet):**
- ❌ Suffixes: `-wip`, `-draft`, `-proposal`
- ❌ Location: `docs/wip/`
- ❌ Status: `DRAFT` or `IN PROGRESS`

---

### 6.2 Migration Checklist Per Document

**Before migrating a doc to book:**

- [ ] **Status is ✅ CURRENT** (not DRAFT or OUTDATED)
- [ ] **No broken links** (use linkcheck)
- [ ] **Code examples compile** (if applicable)
- [ ] **Follows naming convention** (kebab-case)
- [ ] **Has proper header** (status, version, date)
- [ ] **Cross-references updated** (relative paths work)
- [ ] **Appropriate for audience** (user-facing or dev-facing)

---

### 6.3 Migration Path

```
Development Phase:
docs/wip/design-frost-proposal.md
         ↓ (design approved)
docs/wip/security-frost-implementation.md
         ↓ (implementation done)
docs/security/frost-integration.md
         ↓ (reviewed, tested)
docs/security/frost-integration.md (Status: ✅ CURRENT)
         ↓ (ready for book)
book/src/security/frost-integration.md
```

---

## 7. Examples and Templates

### 7.1 Document Templates by Type

#### Template: Primary Documentation

**File:** `docs/[category]/[topic].md`

```markdown
# [Topic Title]

**Version:** v0.5.0
**Status:** ✅ CURRENT
**Last Updated:** 2026-01-24

---

## Overview

Brief description (2-3 sentences).

## Problem Statement

What problem does this solve?

## Solution

How does it work?

## Configuration

\`\`\`toml
[example]
setting = "value"
\`\`\`

## Usage

\`\`\`rust
// Code example
\`\`\`

## Examples

Complete working examples.

## Troubleshooting

Common issues and solutions.

## References

- [Related Doc](../other/related.md)
- [External Link](https://example.com)

---

**Next:** [Related Topic](../next-topic.md)
```

---

#### Template: Implementation Guide

**File:** `docs/[category]/[topic]-implementation.md`

```markdown
# [Topic] - Implementation Guide

**Status:** IMPLEMENTATION IN PROGRESS (or COMPLETE)
**Author:** [Name]
**Date:** 2026-01-24
**Estimated Effort:** X hours
**Related:**
- Design: [link to design doc]
- Issue: #123
- PR: #456

---

## Table of Contents

<!-- Auto-generated by mdbook-toc -->

---

## Implementation Overview

What we're building and why.

## Prerequisites

- Rust 1.75+
- Understanding of [related concept]

## Step-by-Step Implementation

### Step 1: [Task Name]

**Goal:** What this step accomplishes

**File:** `path/to/file.rs`

**Action:**
\`\`\`rust
// Code to add/modify
\`\`\`

**Verification:**
\`\`\`bash
cargo test [test_name]
\`\`\`

**Expected:** Test passes

---

### Step 2: [Task Name]

...

## Testing

\`\`\`bash
# Unit tests
cargo test --package igra-core [feature]

# Integration tests
cargo test --test integration [feature]
\`\`\`

## Verification Checklist

- [ ] All tests pass
- [ ] Code follows CODE-GUIDELINE.md
- [ ] Documentation updated
- [ ] Examples added

## Known Issues

- Issue 1: [description]
- Issue 2: [description]

## Next Steps

What remains to be done.

---

**Related Documents:**
- [Design Proposal](design-[topic]-proposal.md)
- [Review Report]([topic]-review.md)
```

---

#### Template: Review/Verification Document

**File:** `docs/[category]/[topic]-review.md`

```markdown
# [Topic] - Implementation Review

**Status:** REVIEW COMPLETE
**Reviewer:** [Name]
**Date:** 2026-01-24
**Implementation:** [Link to primary doc or PR]

---

## Review Summary

**Overall Assessment:** ✅ APPROVED (or ⚠️ CONDITIONAL, ❌ REJECTED)

**Completion:** X% (if not 100%)
**Code Quality:** ⭐⭐⭐⭐⭐ (5/5)
**Security:** ✅ No issues found
**Testing:** ✅ Comprehensive

---

## Requirements Verification

| Requirement | Status | Notes |
|------------|--------|-------|
| Requirement 1 | ✅ PASS | Implemented correctly |
| Requirement 2 | ⚠️ PARTIAL | Needs improvement |
| Requirement 3 | ✅ PASS | |

---

## Code Quality

- ✅ Follows CODE-GUIDELINE.md
- ✅ No .unwrap() in production code
- ✅ Proper error handling
- ✅ Good test coverage

---

## Gaps Found

### Gap 1: [Description]

**Severity:** 🔴 HIGH / 🟡 MEDIUM / 🟢 LOW
**Fix:** [How to fix]
**Effort:** X hours

### Gap 2: ...

---

## Recommendations

- [ ] Recommendation 1
- [ ] Recommendation 2

---

## Sign-Off

**Approved for merge:** ☐ Yes ☐ No (pending fixes)
**Reviewer:** ________________
**Date:** ________________
```

---

#### Template: Gap Analysis

**File:** `docs/[category]/[topic]-gaps.md`

```markdown
# [Topic] - Gap Analysis & Fixes

**Date:** 2026-01-24
**Status:** Implementation Guide
**Related:** [Primary doc link]

---

## Gap Summary

| Gap # | Description | Priority | Effort | Status |
|-------|-------------|----------|--------|--------|
| Gap 1 | [Description] | 🔴 HIGH | 2 hours | ❌ TODO |
| Gap 2 | [Description] | 🟡 MEDIUM | 1 hour | ✅ DONE |

---

## Gap 1: [Description]

### Status
[Current state]

### Priority
🔴 HIGH - [Why this is important]

### Effort
X hours

### Why This Matters
[Impact analysis]

### Fix Instructions

#### Step 1: [Action]

**File:** `path/to/file.rs`

**Code:**
\`\`\`rust
// Complete, copy-pasteable code
\`\`\`

**Verification:**
\`\`\`bash
cargo test
\`\`\`

---

## Verification Checklist

After closing all gaps:

- [ ] Gap 1 fixed
- [ ] Gap 2 fixed
- [ ] All tests pass
- [ ] Documentation updated

---

**Next:** [Implementation Checklist]([topic]-checklist.md)
```

---

### 7.2 Naming Examples by Category

#### Security Documents

```
Primary:
✅ docs/security/timing-attacks.md
✅ docs/security/key-management-audit.md
✅ docs/security/soc2-compliance.md

Meta (support docs):
📋 docs/security/timing-attacks-implementation.md
📋 docs/security/timing-attacks-checklist.md
📋 docs/security/timing-attacks-quick-fix.md
📊 docs/security/timing-attacks-library-proof.md
📝 docs/security/key-management-review.md

Archived:
📦 docs/legacy/security/old-threat-model.md
```

---

#### Protocol Documents

```
Primary:
✅ docs/protocol/architecture.md
✅ docs/protocol/two-phase-consensus.md
✅ docs/protocol/crdt-gossip.md
✅ docs/protocol/pskt.md

Meta:
📋 docs/protocol/two-phase-implementation.md
📝 docs/protocol/two-phase-review.md

Design Decisions:
📖 docs/protocol/design-decisions/utxo-consensus.md
📖 docs/protocol/design-decisions/privacy-analysis.md

WIP:
🚧 docs/wip/design-v2-architecture-proposal.md
```

---

#### Configuration Documents

```
Primary:
✅ docs/config/network-modes.md
✅ docs/config/iroh-discovery.md
✅ docs/config/hyperlane.md
✅ docs/config/secrets-management.md

Meta:
📝 docs/config/network-modes-verification.md
📊 docs/config/network-modes-gaps.md
📝 docs/config/iroh-discovery-review.md
```

---

## 8. Developer Guidelines

### 8.1 When to Create Documentation

**Always create docs when:**
- ✅ Adding a new feature (design → implementation → primary doc)
- ✅ Changing configuration options (update config docs)
- ✅ Discovering security issues (create security doc)
- ✅ Adding public API (update API docs)
- ✅ Changing deployment process (update ops docs)

**Optional (but recommended):**
- Design decisions (document WHY)
- Complex refactorings (implementation guide)
- Bug fixes (if security-relevant or architectural)

---

### 8.2 Documentation Workflow (Git-Based)

```
1. Feature Branch
   ├── Code changes
   └── docs/wip/[feature]-implementation.md (created)

2. Create PR
   ├── Code review
   └── Doc review (in same PR)

3. After Merge
   ├── Move docs/wip/[feature]-implementation.md
   │   to docs/[category]/[feature].md
   └── Update docs/[category]/[feature].md (primary doc)

4. Release
   └── docs/[category]/[feature].md migrated to book/
```

---

### 8.3 Documentation Checklist (For PRs)

**Include in PR description:**

```markdown
## Documentation Checklist

- [ ] Design doc created (if new feature)
- [ ] Implementation guide created (if complex)
- [ ] Primary documentation updated
- [ ] Code examples added (if API change)
- [ ] Configuration documented (if config change)
- [ ] Security implications documented (if security-relevant)
- [ ] Links updated (cross-references)
- [ ] Status headers updated
- [ ] Follows naming convention

## Documentation Changes

**Files modified:**
- `docs/[category]/[file].md` - [Description]

**New files:**
- `docs/[category]/[new-file].md` - [Description]
```

---

### 8.4 Documentation Review Checklist

**Reviewer should verify:**

- [ ] **Accuracy:** Code examples compile and run
- [ ] **Completeness:** All steps documented
- [ ] **Clarity:** Understandable to target audience
- [ ] **Consistency:** Follows CODE-GUIDELINE.md doc standards
- [ ] **Links:** All internal links work
- [ ] **Naming:** Follows convention (kebab-case, category prefix)
- [ ] **Status:** Header shows current status
- [ ] **Examples:** Complete and runnable

---

## 9. Maintenance Guidelines

### 9.1 When to Archive Documents

**Archive a document when:**
- ✅ Feature is replaced/removed
- ✅ Approach is deprecated
- ✅ Content is > 2 versions old

**How to archive:**

```bash
# Move to legacy
git mv docs/config/old-approach.md docs/legacy/config/old-approach.md

# Update with archive notice
cat >> docs/legacy/config/old-approach.md << 'EOF'

---

**ARCHIVED:** This document describes an old approach that has been replaced.

**See instead:** [New Approach](../../config/new-approach.md)

**Archived:** 2026-01-24
**Reason:** Feature replaced with new implementation
EOF
```

---

### 9.2 Document Update Frequency

**Update frequency by type:**

| Document Type | Update When | Frequency |
|--------------|-------------|-----------|
| **Getting Started** | Installation process changes | Rarely |
| **Configuration** | Config options change | Per feature |
| **Security** | Vulnerability found | Immediately |
| **Protocol** | Protocol changes | Per major refactor |
| **API** | API changes | Per API change |
| **Operations** | Deployment process changes | Per release |
| **Developer** | Code guidelines change | Quarterly |

---

### 9.3 Quarterly Documentation Review

**Every 3 months, review:**

```bash
# Find docs older than 6 months
find docs -name "*.md" -mtime +180 -type f

# For each old doc:
# 1. Is it still accurate?
# 2. Should it be updated?
# 3. Should it be archived?
```

**Checklist:**
- [ ] All docs have current status headers
- [ ] No broken links (run linkcheck)
- [ ] Code examples still compile
- [ ] Version numbers are current
- [ ] No outdated screenshots/diagrams
- [ ] Cross-references still valid

---

## 10. Migration-Ready Checklist

### 10.1 How to Know a Document is Ready for mdBook

**A document is book-ready when:**

✅ **Content:**
- [ ] Status: `✅ CURRENT` (not DRAFT/WIP)
- [ ] All sections complete
- [ ] Code examples compile
- [ ] No TODOs or placeholders

✅ **Structure:**
- [ ] Proper markdown formatting
- [ ] Headers follow hierarchy (H1 → H2 → H3)
- [ ] Code blocks have language tags
- [ ] Images use relative paths

✅ **Links:**
- [ ] All internal links work
- [ ] Links use relative paths
- [ ] No absolute GitHub URLs (use relative)

✅ **Naming:**
- [ ] Follows naming convention (kebab-case)
- [ ] Has category prefix
- [ ] No version numbers in filename
- [ ] Located in correct directory

✅ **Metadata:**
- [ ] Has status header
- [ ] Has last updated date
- [ ] Has version info (if version-specific)

---

### 10.2 Quick Migration Test

**Before adding to book, test:**

```bash
# Create test book
mkdir /tmp/test-book
cd /tmp/test-book
mdbook init

# Copy your doc
cp /path/to/your-doc.md src/test-doc.md

# Add to SUMMARY.md
echo "- [Test](test-doc.md)" >> src/SUMMARY.md

# Build
mdbook build

# Check for errors
# - Broken links?
# - Formatting issues?
# - Images missing?

# If all good, doc is book-ready ✅
```

---

## 11. Team Workflow Example

### Scenario: Implementing FROST MPC Integration

**Developer: Alice**

---

**Week 1: Design Phase**

```bash
# Day 1: Create design proposal
vim docs/wip/design-frost-integration-proposal.md
# Status: DRAFT - For Discussion
# Content: Problem, solution, alternatives

# Share with team
git add docs/wip/design-frost-integration-proposal.md
git commit -m "docs: FROST integration design proposal"
git push
# Create PR for discussion
```

**Team reviews, approves design**

---

**Week 2-3: Implementation Phase**

```bash
# Day 1: Create implementation guide
vim docs/wip/security-frost-implementation.md
# Status: IMPLEMENTATION IN PROGRESS
# Content: Step-by-step code changes

# Day 2-10: Implement feature + update guide
# Update implementation.md as you code
# Document decisions, gotchas, examples

# Day 10: Create checklist
vim docs/wip/security-frost-checklist.md
# Track completion of implementation steps

# Push regularly
git add docs/wip/security-frost-*.md
git commit -m "docs: FROST implementation progress"
```

---

**Week 4: Review Phase**

```bash
# Feature complete, create PR
# PR includes:
# - Code changes
# - docs/wip/security-frost-implementation.md
# - docs/wip/security-frost-checklist.md

# After code review, Bob creates review doc
vim docs/security/frost-integration-review.md
# Status: REVIEW COMPLETE
# Content: Verification results, gaps, recommendations

# Alice addresses gaps, updates implementation
```

---

**Week 5: Publication Phase**

```bash
# Implementation complete, merge PR
# Post-merge: Create primary documentation

# Move implementation guide to final location
git mv docs/wip/security-frost-implementation.md \
        docs/security/frost-implementation.md

# Update status header
sed -i 's/IN PROGRESS/✅ CURRENT/' docs/security/frost-implementation.md

# Create primary doc
vim docs/security/frost-integration.md
# Status: ✅ CURRENT
# Content: User-facing guide (what, why, how)

# Commit
git add docs/security/frost-*.md
git commit -m "docs: add FROST integration documentation

- Primary doc: frost-integration.md (user guide)
- Implementation: frost-implementation.md (dev guide)
- Review: frost-integration-review.md (QA report)
- Checklist: frost-integration-checklist.md (tracking)

Ready for mdBook migration."
git push
```

---

**Week 6: mdBook Integration**

```bash
# When ready to publish
cd book/src

# Copy to book
cp ../../docs/security/frost-integration.md security/frost.md

# Add to SUMMARY.md
vim SUMMARY.md
# Add under Security section:
#   - [FROST Integration](security/frost.md)

# Build and deploy
mdbook build
git add book/src/
git commit -m "docs: add FROST integration to book"
git push  # Auto-deploys via GitHub Actions
```

---

## 12. Naming Convention Reference

### 12.1 Filename Format Reference

```
Pattern: docs/<category>/[topic]-[subtopic]-[lifecycle].md

Category directories:
├── docs/guide/                    (Getting started guides)
├── docs/config/                   (Configuration)
├── docs/security/                 (Security)
├── docs/protocol/                 (Protocol)
├── docs/protocol/design-decisions/ (Design decisions)
├── docs/ops/                      (Operations)
├── docs/dev/                      (Developer/internal)
├── docs/wip/                      (Drafts)
└── docs/legacy/                   (Archive; keep names)

Topic (Required):
├── Descriptive noun or noun phrase
├── Use full words (not abbreviations)
└── Examples: network-modes, iroh-discovery, key-management

Subsection (Optional):
├── Further specify topic
└── Examples: two-phase-consensus, utxo-selection

Lifecycle Suffix (Optional):
├── (none)          Primary doc (migrate to book)
├── -guide          How-to guide (migrate to book)
├── -spec           Formal spec (migrate to book)
├── -implementation Implementation guide (subsection in book)
├── -review         Review report (link only)
├── -verification   Verification report (link only)
├── -gaps           Gap analysis (link only)
├── -checklist      Tracking checklist (link only)
├── -audit          Audit report (migrate to book)
├── -wip            Work in progress (don't migrate)
├── -draft          Draft version (becomes primary when done)
├── -notes          Dev notes (internal)
└── -todo           TODO tracking (internal)
```

---

### 12.2 Examples by Category

**Getting Started:**
```
✅ docs/guide/installation.md
✅ docs/guide/quickstart.md
✅ docs/guide/first-transaction.md
✅ docs/guide/key-derivation.md
```

**Configuration:**
```
✅ docs/config/network-modes.md
✅ docs/config/iroh-discovery.md
✅ docs/config/hyperlane.md
✅ docs/config/secrets-management.md
📋 docs/config/network-modes-verification.md (meta)
📋 docs/config/iroh-discovery-gaps.md (meta)
```

**Security:**
```
✅ docs/security/threat-model.md
✅ docs/security/timing-attacks.md
✅ docs/security/key-management-audit.md
✅ docs/security/soc2-compliance.md
📋 docs/security/timing-attacks-quick-fix.md (meta)
📋 docs/security/timing-attacks-checklist.md (meta)
📊 docs/security/timing-attacks-library-proof.md (meta)
```

**Protocol:**
```
✅ docs/protocol/architecture.md
✅ docs/protocol/two-phase-consensus.md
✅ docs/protocol/crdt-gossip.md
✅ docs/protocol/pskt.md
📋 docs/protocol/two-phase-implementation.md (meta)
📝 docs/protocol/two-phase-review.md (meta)
📖 docs/protocol/design-decisions/utxo-consensus-problem.md
📖 docs/protocol/design-decisions/privacy-analysis.md
```

**Operations:**
```
✅ docs/ops/deployment-devnet.md
✅ docs/ops/deployment-testnet.md
✅ docs/ops/deployment-mainnet.md
✅ ops-monitoring.md
✅ ops-troubleshooting.md
```

**Development:**
```
✅ dev-code-guidelines.md
✅ dev-architecture.md
✅ dev-building.md
✅ dev-testing.md
✅ dev-contributing.md
📋 dev-code-quality-audit.md (meta)
📋 dev-refactoring-todos.md (internal)
```

---

## 13. mdBook Migration Decision Tree

### 13.1 Should This Document Go in the Book?

```
                    ┌─────────────────────┐
                    │ Document Created    │
                    └──────────┬──────────┘
                              │
                    ┌──────────▼──────────┐
                    │ Is it user-facing?  │
                    │ (not internal)      │
                    └──────────┬──────────┘
                         Yes   │   No
                    ┌──────────┴──────────┐
                    │                     │
            ┌───────▼────────┐   ┌───────▼────────┐
            │ Is it current? │   │ Keep in docs/  │
            │ (not outdated) │   │ Don't migrate  │
            └───────┬────────┘   └────────────────┘
              Yes   │   No
       ┌────────────┴────────────┐
       │                         │
┌──────▼────────┐       ┌────────▼────────┐
│ Status?       │       │ Archive to      │
│               │       │ docs/legacy/    │
└──────┬────────┘       └─────────────────┘
       │
       ├─ Primary/Guide/Spec/Audit → ✅ MIGRATE TO BOOK
       ├─ Implementation/Review/Verification → 📋 LINK ONLY
       └─ WIP/Draft/Notes/TODO → ❌ DON'T MIGRATE
```

---

### 13.2 Migration Decision Table

| Document Suffix | User-Facing? | Book Status | Action |
|----------------|--------------|-------------|--------|
| *(none)* | ✅ Yes | ✅ PRIMARY | Migrate as main page |
| `-guide` | ✅ Yes | ✅ PRIMARY | Migrate as main page |
| `-spec` | ✅ Yes | ✅ PRIMARY | Migrate as main page |
| `-audit` | ✅ Yes | ✅ PRIMARY | Migrate as main page |
| `-implementation` | ⚠️ Developer | 📋 SUBSECTION | Include as subsection or appendix |
| `-review` | ❌ No | 📋 REFERENCE | Link from main doc, don't include |
| `-verification` | ❌ No | 📋 REFERENCE | Link from main doc |
| `-gaps` | ❌ No | 📋 REFERENCE | Link from main doc |
| `-checklist` | ❌ No | 📋 REFERENCE | Link from main doc |
| `-wip` | ❌ No | ❌ EXCLUDE | Don't migrate (temporary) |
| `-draft` | ❌ No | ❌ EXCLUDE | Becomes primary when finalized |
| `-notes` | ❌ No | ❌ EXCLUDE | Internal only |
| `-todo` | ❌ No | ❌ EXCLUDE | Internal tracking |

---

## 14. Practical Examples

### Example 1: Network Mode Security (Completed Feature)

**Current files:**
```
docs/NetworkMode-Security.md                      (primary)
docs/NetworkMode-Security-VERIFICATION.md         (review)
docs/NetworkMode-Security-GAPS.md                 (gaps)
```

**Renamed:**
```
docs/config/network-modes.md                      (primary)
docs/config/network-modes-verification.md         (meta)
docs/config/network-modes-gaps.md                 (meta)
```

**Migrated to book:**
```
book/src/configuration/network-modes.md           (primary only)

# Add to primary doc:
## Internal Documentation

For implementation details and verification reports, see:
- [Verification Report](https://github.com/.../docs/config/network-modes-verification.md)
- [Gap Analysis](https://github.com/.../docs/config/network-modes-gaps.md)
```

**Lifecycle:**
```
Design → Implementation → Review → ✅ Published → Book
```

---

### Example 2: Timing Attack Fix (Active Security Work)

**Current files:**
```
docs/TIMING-ATTACK-ANALYSIS.md                    (analysis)
docs/TIMING-ATTACK-IMPLEMENTATION-CHECKLIST.md    (tracking)
docs/TIMING-ATTACK-QUICK-FIX.md                   (reference)
docs/TIMING-ATTACK-LIBRARY-PROOF-SUMMARY.md       (proof)
docs/TIMING-ATTACK-README.md                      (navigation)
```

**Renamed:**
```
docs/security/timing-attacks.md                   (primary - comprehensive)
docs/security/timing-attacks-checklist.md         (meta - tracking)
docs/security/timing-attacks-quick-fix.md         (meta - reference)
docs/security/timing-attacks-library-proof.md     (meta - proof)
docs/security/timing-attacks-overview.md          (meta - navigation)
```

**Migrated to book:**
```
book/src/security/cryptography/timing-attacks.md  (primary only)

# Optionally include as subsections:
book/src/security/cryptography/
├── timing-attacks.md              (main content from ANALYSIS)
├── timing-attacks-quick-fix.md    (include as "Quick Reference" section)
└── library-security.md            (include LIBRARY-PROOF as separate page)

# Link to implementation checklist in primary doc:
## Implementation

See [Implementation Checklist](https://github.com/.../timing-attacks-checklist.md)
for tracking implementation progress.
```

---

### Example 3: New Feature (During Development)

**Developer workflow:**

**Week 1: Design**
```bash
# Create design proposal
vim docs/wip/design-hsm-support-proposal.md

# Content:
# Status: DRAFT - For Discussion
# Author: Alice
# Date: 2026-01-24
# ...

# Commit to feature branch
git checkout -b feature/hsm-support
git add docs/wip/design-hsm-support-proposal.md
git commit -m "docs: HSM support design proposal"
```

**Week 2-3: Implementation**
```bash
# Create implementation guide
vim docs/wip/security-hsm-implementation.md

# Status: IMPLEMENTATION IN PROGRESS
# Step 1: Add HSM trait
# Step 2: Implement YubiHSM backend
# ...

# Update as you code
# Commit frequently
git add docs/wip/security-hsm-implementation.md
git commit -m "docs: HSM implementation progress (Step 3 complete)"
```

**Week 4: Review**
```bash
# Create review doc
vim docs/security/hsm-support-review.md

# Status: REVIEW COMPLETE
# Gaps: Gap 1 (testing), Gap 2 (docs)
# Recommendations: Add integration test

# Create gaps doc
vim docs/security/hsm-support-gaps.md
# Gap 1: Missing integration test
# Gap 2: Missing troubleshooting section
```

**Week 5: Finalize**
```bash
# Move to final location
git mv docs/wip/security-hsm-implementation.md \
        docs/security/hsm-implementation.md

# Create primary doc
vim docs/security/hsm-support.md
# Status: ✅ CURRENT
# Version: v0.6.0
# User-facing guide (not impl details)

# Update implementation doc status
sed -i 's/IN PROGRESS/✅ CURRENT/' docs/security/hsm-implementation.md

# Commit
git add docs/security/hsm-*.md
git commit -m "docs: finalize HSM support documentation

Primary docs:
- hsm-support.md (user guide)
- hsm-implementation.md (developer guide)

Meta docs:
- hsm-support-review.md (QA report)
- hsm-support-gaps.md (gap analysis)

Status: Ready for mdBook migration"
```

**Week 6: Migrate to Book**
```bash
# Copy to book
cp docs/security/hsm-support.md book/src/security/hsm.md
cp docs/security/hsm-implementation.md book/src/developer/hsm-integration.md

# Add to SUMMARY.md
# Security section: - [HSM Support](security/hsm.md)
# Developer section: - [HSM Integration](developer/hsm-integration.md)

# Build and deploy
mdbook build
git add book/src/
git commit -m "docs: add HSM support to documentation book"
git push  # Auto-deploys
```

---

## 15. Quick Reference Card

### Naming Cheat Sheet

```
Creating a new doc? Follow this formula:

1. Choose category prefix:
   guide-, config-, security-, protocol-, ops-, dev-, api-

2. Add topic (descriptive, kebab-case):
   network-modes, iroh-discovery, key-management

3. Add lifecycle suffix (if applicable):
   -implementation, -review, -verification, -gaps, -checklist

4. Add .md extension

Examples:
✅ docs/config/network-modes.md
✅ docs/security/timing-attacks.md
✅ docs/protocol/two-phase-consensus.md
✅ docs/security/timing-attacks-quick-fix.md
✅ docs/config/iroh-discovery-review.md
```

---

### Document Lifecycle Quick Reference

```
Design Phase:       docs/wip/design-[topic]-proposal.md
                    Status: DRAFT

Implementation:     docs/wip/[topic]-implementation.md
                    Status: IN PROGRESS

Review:             docs/<category>/[topic]-review.md
                    Status: REVIEW COMPLETE

Published:          docs/<category>/[topic].md
                    Status: ✅ CURRENT

Book:               book/src/<section>/[topic].md
                    (Migrated from published)

Archived:           docs/legacy/[category]/[topic].md
                    Status: ARCHIVED
```

---

### Migration Decision Quick Reference

```
Migrate to book?

✅ YES:
   - Primary docs (no suffix)
   - Guides (-guide)
   - Specs (-spec)
   - Audits (-audit)
   - Status: ✅ CURRENT

📋 LINK ONLY:
   - Implementation guides (-implementation)
   - Reviews (-review)
   - Verifications (-verification)
   - Gaps (-gaps)
   - Checklists (-checklist)

❌ NO:
   - WIP (-wip, -draft)
   - Internal (-notes, -todo)
   - Archived
   - Outdated
```

---

## 16. Team Standards

### 16.1 Documentation Standards (Add to CODE-GUIDELINE.md)

**Every document must have:**
```markdown
# Document Title

**Status:** [STATE]
**Version:** [VERSION] (if version-specific)
**Last Updated:** [DATE]
**Author:** [NAME] (optional)

---

## [Content starts here]
```

**Every code example must:**
- Have language tag (```rust, ```toml, ```bash)
- Be complete (imports, context)
- Compile and run (if Rust code)
- Have expected output

**Every link must:**
- Use relative paths (not absolute GitHub URLs)
- Include link text (not raw URLs)
- Be verified (no broken links)

---

### 16.2 Documentation Review Standards

**Reviewers must check:**

✅ **Content Quality:**
- [ ] Accurate (matches implementation)
- [ ] Complete (no missing sections)
- [ ] Clear (target audience can understand)

✅ **Technical Quality:**
- [ ] Code examples compile
- [ ] Commands work
- [ ] Links are valid

✅ **Standards Compliance:**
- [ ] Follows naming convention
- [ ] Has status header
- [ ] Proper category/directory
- [ ] Lifecycle suffix correct

---

## 17. Appendix: Bulk Rename Commands

### One-Time Migration (Run Once)

**Before running, backup:**
```bash
git checkout -b docs/reorganization
git commit -am "checkpoint before reorganization"
```

**Create directories:**
```bash
cd /Users/user/Source/personal/rusty-kaspa/wallet/igra/docs
mkdir -p {config,security/audits,protocol/design-decisions,ops,dev,guide,api,wip}
```

**Rename in batches:**

```bash
# Configuration (8 files)
git mv NetworkMode-Security.md config/network-modes.md
git mv NetworkMode-Security-VERIFICATION.md config/network-modes-verification.md
git mv NetworkMode-Security-GAPS.md config/network-modes-gaps.md
git mv Iroh-Discovery.md config/iroh-discovery.md
git mv Iroh-Discovery-REVIEW.md config/iroh-discovery-review.md
git mv Iroh-Discovery-GAPS.md config/iroh-discovery-gaps.md
git mv Iroh-Discovery-FINAL-SUMMARY.md config/iroh-discovery-summary.md
git mv HYPERLANE-INTEGRATION.md config/hyperlane.md

# Security (15 files)
git mv TIMING-ATTACK-ANALYSIS.md security/timing-attacks.md
git mv TIMING-ATTACK-IMPLEMENTATION-CHECKLIST.md security/timing-attacks-checklist.md
git mv TIMING-ATTACK-LIBRARY-PROOF-SUMMARY.md security/timing-attacks-library-proof.md
git mv TIMING-ATTACK-QUICK-FIX.md security/timing-attacks-quick-fix.md
git mv TIMING-ATTACK-README.md security/timing-attacks-overview.md
git mv KEY-MANAGEMENT-AUDIT.md security/key-management-audit.md
git mv IGRA-KEY-MANAGEMENT-AUDIT.md security/key-management-extended-audit.md
git mv Key-Management-Diagram.md security/key-management-diagrams.md
git mv KeyManager-Design.md security/key-manager-design.md
git mv KeyManagement-Refactor.md security/key-management-refactor.md
git mv Key-Management-TODOs.md security/key-management-todos.md
git mv RawPrivKey-Feature.md security/raw-privkey-feature.md
git mv SOC2.md security/soc2-compliance.md
git mv SECURITY-ISSUES-REMEDIATION.md security/issues-remediation.md
git mv SECURITY-QUICK-CHECK.md security/quick-check.md
git mv Audit-v1.md security/audits/audit-v1.md

# Protocol (11 files)
git mv ../Igra-Protocol.md protocol/architecture.md
git mv Igra-Protocol.md protocol/architecture-v2.md 2>/dev/null || true
git mv TWO-PHASE-PROTOCOL.md protocol/two-phase-consensus.md
git mv TWO-PHASE-PROTOCOL-IMPLEMENTATION.md protocol/two-phase-implementation.md
git mv TWO-PHASE-PROTOCOL-EXPERT-REVIEW.md protocol/two-phase-review.md
git mv 2-phase-algo-v1.md protocol/two-phase-algo-v1.md
git mv 2-phase-algo-v1-current.md protocol/two-phase-algo-current.md
git mv UTXO_CONSENSUS_PROBLEM.md protocol/design-decisions/utxo-consensus.md
git mv ANTI_ENTROPY_ENHANCEMENT.md protocol/anti-entropy.md
git mv DISTRIBUTED-SYSTEM-FAILURE-ANALYSIS.md protocol/design-decisions/failure-modes.md
git mv Origin-Destination-Linkability.md protocol/design-decisions/privacy-analysis.md
git mv Event-ID-signle-sign-per-TX-HASH.md protocol/design-decisions/event-id-design.md

# Operations (3 files)
git mv Hyperlane-devnet.md ops/deployment-devnet.md
git mv Observability.md ops/monitoring.md
git mv Igra-Obeserver.md ops/observer-setup.md

# Developer (10 files)
git mv Code-Quality-Audit.md dev/code-quality-audit.md
git mv Code-Quality-Progress-Report.md dev/code-quality-report.md
git mv Refactoring-Audit-2026.md dev/refactoring-audit-2026.md
git mv Refactoring-TODOs.md dev/refactoring-todos.md
git mv Refactor.md dev/refactor-general.md
git mv Refactor-HexEncode.md dev/hex-encoding-refactor.md
git mv Hex-Refactor.md dev/hex-refactor.md
git mv Hex-Refactor-Completion.md dev/hex-refactor-completion.md
git mv TODO-FIXES.md dev/todo-fixes.md
git mv FOLLOWUP-TODO-FIXES.md dev/followup-todos.md
git mv FIXES_CRDT_GOSSIP_VALIDATION.md dev/crdt-gossip-fixes.md

# Getting Started (2 files)
git mv Kaspa-Signers-Hyperlane-HowTo.md guide/quickstart.md
git mv DERIVATION.md guide/key-derivation.md

# WIP / Design (3 files from v2/)
git mv v2/Design-2-Exec-Plan.md wip/v2-execution-plan.md
git mv v2/Design-2-Impl.md wip/v2-implementation.md
git mv v2/Desing-2.md wip/v2-design.md

# Commit
git commit -m "docs: reorganize and rename for consistency

- Move files to category subdirectories
- Rename to kebab-case
- Add lifecycle suffixes
- Create docs/wip/ for work-in-progress

Benefits:
- Easier to find documents (category directories)
- Clear lifecycle (suffixes indicate status)
- Ready for mdBook migration
- Consistent naming across project

No content changes, only organization."

# Push for review
git push origin docs/reorganization
```

**After team review and approval:**
```bash
git checkout master
git merge docs/reorganization
git push
```

---

## 18. Summary

### Key Takeaways

**1. Consistent Naming:**
- `docs/<category>/[topic]-[lifecycle].md`
- kebab-case (all lowercase with hyphens)
- Descriptive names (no abbreviations)

**2. Clear Lifecycle:**
- Design → Implementation → Review → Published → Book → Archive
- Each phase has specific naming patterns and locations

**3. Directory Organization:**
- `docs/wip/` - Work in progress
- `docs/[category]/` - Published docs
- `docs/legacy/` - Historical archive
- `book/src/` - mdBook content

**4. Migration Ready:**
- Primary docs (no suffix) → Migrate to book
- Meta docs (suffixes) → Link only
- WIP docs → Don't migrate

---

### Action Plan for Your Team

**Today:**
1. Read this document (30 min)
2. Review proposed renames (15 min)
3. Decide: Rename now or gradually? (5 min)

**This Week:**
4. Run bulk rename script (OR rename gradually as you touch files)
5. Update internal links (1-2 hours)
6. Commit reorganization

**This Month:**
7. Follow workflow for new docs (all new docs follow convention)
8. Gradually rename remaining files (as you update them)

---

**Result:** Consistent naming, easy to migrate to mdBook, maintainable long-term

---

**End of Document**

**Status:** ✅ CURRENT
**Version:** v1.0
**Last Updated:** 2026-01-24
