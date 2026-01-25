# Igra Documentation - Quick Navigation

**Last Updated:** 2026-01-24

---

## 📚 For Team: Setting Up Documentation

**Your task:** Migrate 51 markdown files to mdBook for professional documentation site

**START HERE:**
1. **Read:** `docs/dev/documentation-start-here.md` (navigation)
2. **Read:** `docs/dev/documentation-refactoring-plan.md` (complete step-by-step guide)
2. **Execute:** Phase 1 commands (4 hours → deployed documentation)
3. **Deploy:** GitHub Pages (automatic after setup)

**Result:** Professional docs at https://[org].github.io/rusty-kaspa/igra/

---

## 📖 Documentation Files in This Repository

### Active Documentation (55 files)

**Root Level (core files):**
- `AGENTS.md` - Internal (AI agent guidelines)
- `CODE-GUIDELINE.md` - Code standards ⭐⭐⭐
- `Igra-Protocol.md` - Main architecture ⭐⭐⭐
- `README-DOCS.md` - This file

**Team documentation (how to maintain docs):**
- `docs/dev/documentation-start-here.md`
- `docs/dev/documentation-refactoring-plan.md`
- `docs/dev/documentation-naming-conventions.md`
- `docs/dev/documentation-team-quickstart.md`
- `docs/dev/documentation-guide.md`

**docs/ Directory (active docs, categorized):**

**Configuration:**
- `docs/config/network-modes.md` ⭐⭐⭐
- `docs/config/iroh-discovery.md` ⭐⭐⭐
- `docs/config/hyperlane.md` ⭐⭐
- Plus verification/gap analysis files in `docs/config/`

**Security:**
- `docs/security/timing-attacks.md` ⭐⭐⭐
- `docs/security/key-management-audit.md` ⭐⭐⭐
- `docs/security/soc2-compliance.md` ⭐⭐
- Plus library proofs, checklists, and audits in `docs/security/`

**Protocol:**
- `docs/protocol/architecture.md` ⭐⭐⭐
- `docs/protocol/two-phase-consensus.md` ⭐⭐⭐
- `docs/protocol/design-decisions/utxo-consensus-problem.md` ⭐⭐
- Plus implementation guides, reviews, and design notes in `docs/protocol/`

**Developer:**
- Code quality audits and refactoring guides in `docs/dev/`

**Operations:**
- Deployment and monitoring docs in `docs/ops/`

**Guides / WIP:**
- Quickstart and key derivation in `docs/guide/`
- Drafts and future design in `docs/wip/`

---

### Legacy Documentation (Archive)

**docs/legacy/ (~100 files):**
- Historical development logs
- Old specifications
- Refactoring steps
- Archived analysis

**Status:** Keep for git history, don't migrate to book

---

## 🎯 Which Document Should I Read?

### For Setting Up Documentation System

**Read in order:**
1. `docs/dev/documentation-start-here.md` - Navigation + next actions
2. `docs/dev/documentation-refactoring-plan.md` - Step-by-step migration guide
3. `docs/dev/documentation-naming-conventions.md` - Team standards
4. `docs/dev/documentation-guide.md` - Background and best practices

**Time:** 30 min reading + 4 hours implementation

---

### For Using Igra (Users/Operators)

**Essential reading:**
1. `docs/guide/quickstart.md` - Quick start
2. `docs/config/network-modes.md` - Security validation
3. `docs/config/iroh-discovery.md` - P2P configuration
4. `docs/ops/deployment-devnet.md` - Devnet setup

**Time:** 2-3 hours

---

### For Understanding Protocol (Developers/Auditors)

**Essential reading:**
1. `Igra-Protocol.md` - Architecture overview
2. `docs/protocol/two-phase-consensus.md` - Consensus algorithm
3. `docs/protocol/design-decisions/utxo-consensus-problem.md` - Design rationale
4. `CODE-GUIDELINE.md` - Code standards

**Time:** 4-6 hours

---

### For Security Review (Auditors)

**Essential reading:**
1. `docs/security/timing-attacks.md` - Cryptographic security
2. `docs/security/key-management-audit.md` - Key management
3. `docs/config/network-modes.md` - Validation rules
4. `docs/security/soc2-compliance.md` - Compliance

**Time:** 6-8 hours (comprehensive review)

---

### For Contributing (Developers)

**Essential reading:**
1. `CODE-GUIDELINE.md` - Coding standards
2. `docs/dev/code-quality-audit.md` - Quality expectations
3. `Igra-Protocol.md` - Architecture understanding

**Time:** 3-4 hours

---

## 📁 Directory Structure

```
/Users/user/Source/personal/rusty-kaspa/wallet/igra/
│
├── Root Documentation
│   ├── CODE-GUIDELINE.md ⭐⭐⭐
│   ├── Igra-Protocol.md ⭐⭐⭐
│   └── README-DOCS.md
│
├── docs/ (51 active files, categorized)
│   ├── config/ (Network modes, Iroh, Hyperlane)
│   ├── security/ (Timing attacks, key management, compliance)
│   ├── protocol/ (Two-phase, CRDT, design decisions)
│   ├── dev/ (Code quality, refactoring)
│   ├── ops/ (Deployment, monitoring)
│   ├── guide/ (Quickstart, derivation)
│   ├── wip/ (Design drafts)
│   └── legacy/ (historical archive - ~100 files)
│
├── book/ (mdBook source)
│   ├── book.toml (configuration)
│   ├── src/ (markdown source)
│   │   ├── SUMMARY.md (table of contents)
│   │   ├── intro.md
│   │   ├── getting-started/
│   │   ├── configuration/
│   │   ├── security/
│   │   ├── protocol/
│   │   ├── developer/
│   │   ├── operations/
│   │   └── appendix/
│   └── book/ (generated HTML - gitignored)
│
└── orchestration/ (deployment configs)
    ├── devnet/
    └── testnet/
```

---

## 🏁 Next Steps

**For your team to set up documentation:**

1. **Assign someone** to run `docs/dev/documentation-refactoring-plan.md`
2. **Allocate time:** 4 hours for Phase 1 (deployed docs)
3. **Review together:** After Phase 1, whole team reviews
4. **Iterate:** Expand in Phase 2-3 based on feedback

**Timeline:**
- Today: Read both docs (30 min)
- This week: Complete Phase 1 (4 hours)
- This month: Complete Phases 2-3 (8 hours)

**Deliverable:** Professional documentation site ready for mainnet launch

---

**Start now:** Open `docs/dev/documentation-start-here.md`
