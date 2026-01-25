# Documentation Team Quick Start Guide

**Date:** 2026-01-24
**For:** Igra development team
**Goal:** Get everyone on same page for documentation

---

## 📚 Three Documentation Guides - Which to Read?

Your team has **3 comprehensive documentation guides**. Here's when to use each:

---

### 1. docs/dev/documentation-naming-conventions.md ⭐ **READ FIRST**

**Purpose:** Team standards for creating and organizing docs

**When to read:**
- ✅ Before creating any new documentation
- ✅ When starting a new feature (need to document design)
- ✅ When organizing existing docs

**What you'll learn:**
- How to name files (kebab-case, category directories, lifecycle suffixes)
- Where to put files (`docs/wip/`, `docs/security/`, etc.)
- Document lifecycle (design → implementation → review → published → book)
- When to migrate to mdBook vs keep separate
- Developer workflow (how to document as you code)

**Time:** 30 min read
**Use:** Daily reference when creating docs

---

### 2. docs/dev/documentation-refactoring-plan.md ⭐ **FOR SETUP**

**Purpose:** One-time migration to mdBook

**When to read:**
- ✅ When setting up mdBook for first time
- ✅ When migrating existing docs to book

**What you'll learn:**
- Step-by-step mdBook setup (install, configure, deploy)
- File migration mapping (current location → book location)
- Priority order (which 10 docs to migrate first)
- GitHub Pages deployment

**Time:** 15 min read + 4 hours execution
**Use:** One-time (or when adding major doc sections)

---

### 3. docs/dev/documentation-guide.md 📖 **FOR REFERENCE**

**Purpose:** Background and best practices

**When to read:**
- ✅ When you want to understand mdBook vs GitBook
- ✅ When writing security-critical documentation
- ✅ When planning long-term doc strategy

**What you'll learn:**
- What is mdBook (rustbook)?
- What is GitBook?
- Comparison and when to use each
- Best practices for blockchain project documentation
- Writing style for security docs
- Long-term maintenance strategy

**Time:** 30-45 min read
**Use:** Reference as needed

---

## 🎯 Quick Decision Matrix

### Scenario: "I'm creating a new feature, what docs do I need?"

**Answer:**
1. **Read:** docs/dev/documentation-naming-conventions.md Section 5 (Developer Workflow)
2. **Create:** Design proposal in `docs/wip/`
3. **Follow:** Lifecycle (design → implementation → review → published)
4. **Result:** Well-organized docs ready for book migration

---

### Scenario: "I need to set up mdBook for our team"

**Answer:**
1. **Read:** docs/dev/documentation-refactoring-plan.md (15 min)
2. **Execute:** Phase 1, Steps 1-8 (4 hours)
3. **Result:** Deployed documentation at https://[org].github.io/rusty-kaspa/igra/

---

### Scenario: "What should I name this document?"

**Answer:**
1. **Read:** docs/dev/documentation-naming-conventions.md Section 1 (Naming Rules)
2. **Use formula:** `[category]-[topic]-[lifecycle].md`
3. **Example:** `security-hsm-support-implementation.md`

---

### Scenario: "Should this doc go in the book?"

**Answer:**
1. **Check:** docs/dev/documentation-naming-conventions.md Section 6 (Migration Decision Tree)
2. **Rule:** Primary docs (no suffix) → YES, Meta docs (suffixes) → Link only
3. **Example:** `timing-attacks.md` → YES, `timing-attacks-review.md` → NO

---

### Scenario: "I need to understand mdBook vs GitBook"

**Answer:**
1. **Read:** docs/dev/documentation-guide.md Section 3 (Comparison)
2. **TL;DR:** Use mdBook (free, Rust-native, perfect for us)
3. **Time:** 10 min

---

## 📋 Team Responsibilities

### Role: Documentation Lead (1 person)

**Reads:**
- All 3 guides (2 hours total)

**Does:**
- Set up mdBook (`docs/dev/documentation-refactoring-plan.md` Phase 1)
- Establish naming standards (share `docs/dev/documentation-naming-conventions.md` with team)
- Review all documentation PRs
- Maintain book structure

**Time:** 1-2 days initial, 2-4 hours/month ongoing

---

### Role: Feature Developers (Everyone)

**Reads:**
- docs/dev/documentation-naming-conventions.md Section 5 (Developer Workflow) - 20 min

**Does:**
- Create design docs for new features
- Document implementation as you code
- Follow naming convention
- Include docs in PR

**Time:** 1-2 hours per feature

---

### Role: Documentation Reviewers (2-3 people)

**Reads:**
- docs/dev/documentation-naming-conventions.md Section 5.4 (Review Checklist) - 10 min

**Does:**
- Review docs in PRs (accuracy, clarity, standards)
- Verify code examples compile
- Check links work

**Time:** 30 min per review

---

## ✅ Action Plan

### Week 1: Setup & Standards

**Monday (Doc Lead):**
- [ ] Read all 3 guides (2 hours)
- [ ] Set up mdBook following `docs/dev/documentation-refactoring-plan.md` Phase 1 (4 hours)
- [ ] Deploy to GitHub Pages

**Tuesday (Whole Team):**
- [ ] Everyone reads docs/dev/documentation-naming-conventions.md (30 min)
- [ ] Team meeting: Decide on rename strategy (30 min)
- [ ] Optional: Run bulk rename script (1 hour)

**Wednesday-Friday (Doc Lead):**
- [ ] Migrate priority docs (`docs/dev/documentation-refactoring-plan.md` Phase 2)
- [ ] Fix broken links
- [ ] Add FAQ and glossary

**Deliverable:** Live documentation site with 20+ pages

---

### Week 2-3: Adoption

**Everyone:**
- [ ] Follow naming convention for all new docs
- [ ] Include documentation in PRs
- [ ] Review each other's docs

**Doc Lead:**
- [ ] Complete migration (`docs/dev/documentation-refactoring-plan.md` Phase 3)
- [ ] Polish and review
- [ ] Team training (if needed)

**Deliverable:** Complete documentation (40+ pages)

---

### Ongoing: Maintenance

**Everyone:**
- Create docs using `docs/dev/documentation-naming-conventions.md` templates
- Document features as you build them
- Keep docs up to date

**Doc Lead:**
- Quarterly doc review
- Keep book deployed
- Manage structure

---

## 🎓 Learning Resources

### Essential Reading (First Week)

**Priority 1 (Must Read):**
- docs/dev/documentation-naming-conventions.md - 30 min
  - Section 1: Naming rules
  - Section 2: Document lifecycle
  - Section 5: Developer workflow

**Priority 2 (Should Read):**
- docs/dev/documentation-refactoring-plan.md - 15 min
  - Introduction and overview
  - Phase 1 (if you're doing setup)

**Priority 3 (Nice to Have):**
- docs/dev/documentation-guide.md - 30 min
  - Section 1-3: What is mdBook/GitBook
  - Section 8: Best practices

---

### External Resources (Optional)

**mdBook Documentation:**
- User Guide: https://rust-lang.github.io/mdBook/
- Quick start: https://rust-lang.github.io/mdBook/guide/creating.html

**Examples to Study:**
- Rust Book: https://doc.rust-lang.org/book/
- Tokio Tutorial: https://tokio.rs/tokio/tutorial

---

## 🔧 Practical Examples

### Example 1: Creating Docs for New Feature

**Scenario:** You're implementing relay server support

**Steps:**

```bash
# 1. Create design proposal (week 1)
vim docs/wip/design-relay-server-proposal.md
# Status: DRAFT
# Team discusses and approves

# 2. Create implementation guide (week 2-3)
vim docs/wip/ops-relay-server-implementation.md
# Status: IN PROGRESS
# Update as you code

# 3. After implementation complete (week 4)
git mv docs/wip/ops-relay-server-implementation.md \
       docs/ops/relay-server-implementation.md

# 4. Create primary doc (week 4)
vim docs/ops/relay-server.md
# Status: ✅ CURRENT
# User-facing guide

# 5. Ready for book (week 5+)
cp docs/ops/relay-server.md book/src/operations/relay-server.md
# Add to SUMMARY.md
# Deploy
```

**Naming:**
- Design: `design-relay-server-proposal.md` (WIP)
- Implementation: `ops-relay-server-implementation.md` (meta)
- Primary: `ops-relay-server.md` (book-ready)

---

### Example 2: Documenting a Security Fix

**Scenario:** You discovered a timing attack

**Steps:**

```bash
# 1. Create analysis doc
vim docs/security/timing-attacks.md
# Document: vulnerability, impact, fix

# 2. Create implementation guide
vim docs/security/timing-attacks-implementation.md
# Document: step-by-step fix instructions

# 3. Create tracking checklist
vim docs/security/timing-attacks-checklist.md
# Track: which steps complete

# 4. After fix merged
# Update status headers to ✅ CURRENT

# 5. Migrate to book
cp docs/security/timing-attacks.md book/src/security/cryptography/timing-attacks.md
# Link to implementation guide in book
```

**Result:**
- Primary doc in book (user sees)
- Implementation guide linked (developer reference)
- Checklist kept in docs/ (internal tracking)

---

## 🎯 Common Questions

### Q: "Do I need to read all 3 guides?"

**A:** No, read based on your role:
- **Setting up mdBook?** → docs/dev/documentation-refactoring-plan.md only
- **Creating new docs?** → docs/dev/documentation-naming-conventions.md only
- **Planning strategy?** → docs/dev/documentation-guide.md only

---

### Q: "Should we rename all 51 files now?"

**A:** Your choice:
- **Option A:** Rename now (1-2 hours, use bulk script from `docs/dev/documentation-naming-conventions.md`)
- **Option B:** Rename gradually (as you touch files)

**Recommendation:** Option A if you have time (cleaner long-term)

---

### Q: "Where do design docs go?"

**A:** `docs/wip/design-[topic]-proposal.md`
- See docs/dev/documentation-naming-conventions.md Section 5.1 (Design Phase)

---

### Q: "Where do implementation guides go?"

**A:** Start in `docs/wip/`, move to `docs/[category]/` when complete
- See docs/dev/documentation-naming-conventions.md Section 5.2 (Implementation Phase)

---

### Q: "How do I know if a doc should go in the book?"

**A:** Use decision tree in docs/dev/documentation-naming-conventions.md Section 13.1
- Primary docs (no suffix) → YES
- Meta docs (review, gaps, verification) → Link only
- WIP docs → NO

---

### Q: "Can I still create docs with ALL CAPS names?"

**A:** No, new standard is kebab-case:
- ❌ OLD: `NEW-FEATURE-IMPLEMENTATION.md`
- ✅ NEW: `security-new-feature-implementation.md`
- See docs/dev/documentation-naming-conventions.md Section 1

---

## 🎁 What You're Getting

**After reading these guides and following the plans:**

### Immediate (Week 1):
- ✅ Understanding of mdBook
- ✅ Clear naming standards for all docs
- ✅ Deployed documentation website
- ✅ Search, navigation, professional UI

### Short-Term (Month 1):
- ✅ All documentation well-organized
- ✅ Easy to find and maintain
- ✅ Consistent structure
- ✅ Ready for external users

### Long-Term (Ongoing):
- ✅ Documentation as code (git workflow)
- ✅ Auto-deploy on merge
- ✅ Sustainable maintenance
- ✅ Professional appearance

---

## 📊 Document Overview

| Guide | Lines | Read Time | Use Case |
|-------|-------|-----------|----------|
| **docs/dev/documentation-naming-conventions.md** | 1,200+ | 30 min | Daily (creating docs) |
| **docs/dev/documentation-refactoring-plan.md** | 800+ | 15 min | One-time (setup) |
| **docs/dev/documentation-guide.md** | 1,200+ | 45 min | Reference (best practices) |
| **This file (`docs/dev/documentation-team-quickstart.md`)** | 400 | 10 min | Navigation |

---

## ✅ Success Criteria

**Your team is successful when:**

- [ ] Everyone has read docs/dev/documentation-naming-conventions.md
- [ ] New docs follow naming convention
- [ ] mdBook is deployed (via `docs/dev/documentation-refactoring-plan.md`)
- [ ] Documentation is discoverable (search works)
- [ ] Docs are maintainable (clear ownership)
- [ ] External users can onboard (good getting-started)

---

## 🚀 Get Started

**Step 1 (Everyone - 30 minutes):**
```bash
# Read naming standards
cat docs/dev/documentation-naming-conventions.md
```

**Step 2 (Doc Lead - 4 hours):**
```bash
# Follow setup guide
cat docs/dev/documentation-refactoring-plan.md
# Execute Phase 1, Steps 1-8
```

**Step 3 (Everyone - Ongoing):**
- Follow naming convention for new docs
- Include docs in PRs
- Review each other's documentation

---

**Questions?** Check the Q&A sections in each guide, or ask in team channel.

**Ready to start?** Open docs/dev/documentation-naming-conventions.md first! 📖
