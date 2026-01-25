# Documentation Setup - START HERE

**Date:** 2026-01-24
**For:** Igra development team
**Goal:** Set up professional documentation with mdBook
**Time Required:** 4 hours (basic) to 12 hours (complete)

---

## ✅ Your Documentation is Ready for mdBook!

**Good news:** Your 55 markdown files are well-organized and high-quality. You just need mdBook structure.

**Current state:**
- ✅ Clean root directory (4 files)
- ✅ Active docs organized in docs/ (51 files)
- ✅ Historical docs archived in docs/legacy/
- ✅ Excellent technical content

**What you need:** mdBook to turn these into a searchable website

---

## 🎯 Three-Step Process

### Step 1: Read Background (15 minutes)

**Purpose:** Understand what mdBook is and why we're using it

**Read:** `docs/dev/documentation-guide.md` Sections 1-3
- Section 1: What is mdBook?
- Section 2: What is GitBook?
- Section 3: Comparison (why mdBook for Igra)

**Key takeaway:** mdBook is free, Rust-native, perfect for technical docs

---

### Step 2: Follow Implementation Guide (4 hours)

**Purpose:** Set up and deploy documentation

**Read and Execute:** `docs/dev/documentation-refactoring-plan.md` Phase 1

**You'll do:**
1. Install mdBook (10 min)
2. Initialize structure (15 min)
3. Configure book.toml (15 min)
4. Create SUMMARY.md (30 min)
5. Copy 10 priority docs (2 hours)
6. Build and test locally (10 min)
7. Deploy to GitHub Pages (30 min)
8. Verify deployment (10 min)

**Deliverable:** Live documentation at https://[org].github.io/rusty-kaspa/igra/

---

### Step 3: Expand Coverage (8 hours over next week)

**Purpose:** Complete documentation migration

**Execute:** `docs/dev/documentation-refactoring-plan.md` Phases 2-3

**You'll do:**
- Migrate remaining 41 docs (4 hours)
- Fix broken links (1 hour)
- Add FAQ and glossary (1 hour)
- Polish and review (2 hours)

**Deliverable:** Complete documentation (40+ pages)

---

## 📚 Documentation Files Overview

**You have 3 documentation-related files to read:**

| File | Purpose | Read Time | When to Read |
|------|---------|-----------|--------------|
| `docs/dev/documentation-start-here.md` | This file (navigation) | 5 min | First |
| `docs/dev/documentation-refactoring-plan.md` | Step-by-step implementation | 15 min | Second (then execute) |
| `docs/dev/documentation-guide.md` | Background and best practices | 30 min | Reference (as needed) |

---

## 🎬 Quick Start Commands

**If you just want to start immediately:**

```bash
# 1. Install mdBook (2 minutes)
cargo install mdbook mdbook-toc mdbook-mermaid mdbook-linkcheck

# 2. Create structure (5 minutes)
cd /Users/user/Source/personal/rusty-kaspa/wallet/igra
mkdir book && cd book
mdbook init
# Answer prompts: Title = "Igra Documentation", Create .gitignore = Yes

# 3. Preview (1 minute)
mdbook serve --open
# Opens http://localhost:3000

# You now have a working mdBook!
# Next: Follow `docs/dev/documentation-refactoring-plan.md` to add your content
```

If `book/` already exists in the repo, skip `mdbook init` and go straight to `mdbook serve`.

---

## 📊 What You'll Build

### After 4 Hours (Phase 1 Complete)

**Documentation site with:**
- 📖 15+ pages (essential content)
- 🔍 Full-text search
- 📱 Mobile-friendly UI
- 🎨 Professional appearance
- 🚀 Deployed to GitHub Pages

**Includes:**
- Introduction
- Getting Started (quick start tutorial)
- Configuration (network modes, Iroh, Hyperlane)
- Security (timing attacks, key management)
- Protocol (architecture, two-phase)
- Developer (code guidelines)

---

### After 12 Hours (Phases 1-3 Complete)

**Complete documentation with:**
- 📖 40+ pages (comprehensive coverage)
- 🔗 All internal links working
- 📝 FAQ and glossary
- 🏗️ Operations guides (devnet, testnet, mainnet)
- 🎓 Developer deep-dives
- 📊 Diagrams and examples

**Quality:** Production-ready for mainnet launch

---

## 🚦 Decision Matrix

### Should You Use This Guide?

**Yes, if:**
- ✅ You need to organize Igra documentation
- ✅ You want searchable, navigable docs
- ✅ You want to deploy docs to web
- ✅ You have 4-12 hours available

**No, if:**
- ❌ You just need to read existing docs (see "Which Document Should I Read?" in README-DOCS.md)
- ❌ You're looking for code guidelines (see CODE-GUIDELINE.md directly)
- ❌ You need specific security info (go directly to `docs/security/timing-attacks.md` or `docs/security/key-management-audit.md`)

---

## 👥 Who Does What?

### Role: Documentation Lead (1 person)

**Responsibilities:**
- Read `docs/dev/documentation-refactoring-plan.md`
- Execute Phase 1 (4 hours)
- Set up GitHub Pages deployment
- Coordinate Phase 2-3 with team

**Skills needed:** Basic Rust knowledge, comfortable with command line

---

### Role: Content Reviewers (2-3 people)

**Responsibilities:**
- Review migrated content for accuracy
- Test code examples
- Suggest improvements
- Proofread

**Skills needed:** Domain knowledge (protocol, security, operations)

---

### Role: Technical Writer (optional)

**Responsibilities:**
- Write new content (intro, installation, FAQ)
- Edit for clarity and consistency
- Add diagrams
- Improve examples

**Skills needed:** Technical writing, basic blockchain knowledge

---

## ⏱️ Time Estimates by Phase

| Phase | Task | Time | Deliverable |
|-------|------|------|-------------|
| **Setup** | Install tools, init structure | 30 min | Local mdBook preview |
| **Phase 1** | Migrate 10 priority docs | 2.5 hours | Deployed site (15 pages) |
| **Phase 1** | Deploy GitHub Pages | 30 min | Live at https://... |
| **Phase 2** | Migrate 15 more docs | 2 hours | Comprehensive (30 pages) |
| **Phase 2** | Fix links, add FAQ | 2 hours | Clean navigation |
| **Phase 3** | Migrate remaining docs | 2 hours | Complete (40+ pages) |
| **Phase 3** | Polish and review | 2 hours | Production quality |
| **TOTAL** | **End-to-end** | **12 hours** | **Professional docs** |

**Minimum viable:** 4 hours (Phase 1 only)
**Recommended:** 8 hours (Phases 1-2)
**Complete:** 12 hours (all phases)

---

## ✅ Success Metrics

### After Phase 1 (4 hours):

- [ ] mdBook builds without errors
- [ ] Can navigate via sidebar (left)
- [ ] Search box finds content
- [ ] Deployed to GitHub Pages
- [ ] Team can access at URL
- [ ] 15+ pages available

---

### After Phases 1-3 (12 hours):

- [ ] 40+ pages published
- [ ] Zero broken links (mdbook-linkcheck passes)
- [ ] All priority docs migrated
- [ ] Code examples tested
- [ ] FAQ and glossary complete
- [ ] Team signs off on quality
- [ ] Ready for external users

---

## 🚨 Common Pitfalls to Avoid

### Pitfall 1: Trying to Migrate Everything at Once

**Problem:** 51 files is too many for one session

**Solution:** Follow priority order (10 → 25 → 51)
- Phase 1: Just the essentials (10 files)
- Phase 2: Important reference (15 files)
- Phase 3: Complete coverage (26 files)

---

### Pitfall 2: Not Testing Locally First

**Problem:** Broken links discovered after deploy

**Solution:**
```bash
# Always test locally before pushing
mdbook serve
# Click through all links
# Run mdbook-linkcheck before committing
```

---

### Pitfall 3: Forgetting to Update SUMMARY.md

**Problem:** New pages don't appear in navigation

**Solution:** Every new file needs entry in SUMMARY.md
```markdown
# Add to SUMMARY.md:
- [New Page](path/to/new-page.md)
```

---

### Pitfall 4: Copy-Paste Without Updating Links

**Problem:** Internal links break (old paths don't work)

**Solution:** After copying, search and replace:
```bash
# Old: See [Security](../docs/security/timing-attacks.md)
# New: See [Security](../security/cryptography/timing-attacks.md)
```

---

## 📞 Getting Help

### If You Get Stuck

**Technical issues (mdBook not working):**
1. Check mdBook docs: https://rust-lang.github.io/mdBook/
2. Check GitHub issues: https://github.com/rust-lang/mdBook/issues
3. Ask in Rust community Discord

**Content questions (what to migrate):**
1. Check `docs/dev/documentation-refactoring-plan.md` (file mapping table)
2. Check priority list (🔴 HIGH first)
3. Ask team: "Do users need this doc?"

**Structural questions (how to organize):**
1. Look at Rust Book: https://doc.rust-lang.org/book/
2. Look at Tokio: https://tokio.rs/tokio/tutorial
3. Follow `docs/dev/documentation-refactoring-plan.md` proposed structure

---

## 🎯 Your First Session (4 Hours)

**Recommended schedule:**

**Hour 1: Setup and Learning**
- 0:00-0:15 - Read `docs/dev/documentation-start-here.md` (this file)
- 0:15-0:30 - Read `docs/dev/documentation-refactoring-plan.md` intro
- 0:30-0:50 - Install mdBook and initialize (Phase 1, Steps 1-3)
- 0:50-1:00 - Test local preview (`mdbook serve`)

**Hour 2: Core Content**
- 1:00-1:30 - Create SUMMARY.md (use template from `docs/dev/documentation-refactoring-plan.md`)
- 1:30-2:00 - Copy first 5 docs (Configuration + Security)

**Hour 3: More Content**
- 2:00-2:30 - Copy next 5 docs (Protocol + Developer)
- 2:30-3:00 - Create intro.md and getting-started/

**Hour 4: Deploy**
- 3:00-3:30 - Fix major broken links
- 3:30-3:45 - Set up GitHub Action (deployment)
- 3:45-4:00 - Test deployment, share with team

**Result:** Live documentation site ✅

---

## 📖 Complete Documentation Package

**Files in this repository:**

1. `docs/dev/documentation-start-here.md` (this file)
   - Quick navigation
   - What to read when
   - Time estimates

2. `docs/dev/documentation-refactoring-plan.md`
   - Current file inventory (55 files categorized)
   - Step-by-step implementation (Phases 1-3)
   - File mapping (current → book location)
   - Ready-to-use commands

3. `docs/dev/documentation-guide.md`
   - Background on mdBook vs GitBook
   - Best practices for crypto projects
   - Writing style guide
   - Long-term strategy

4. **README-DOCS.md**
   - Quick navigation for readers
   - Which doc to read for which purpose
   - Directory structure

---

## ⚡ TL;DR

**Your team should:**

1. **Read:** `docs/dev/documentation-refactoring-plan.md` (15 min)
2. **Execute:** Phase 1, Steps 1-8 (4 hours)
3. **Result:** Professional documentation site (deployed)

**Your docs are ready. Just need mdBook wrapper.** 🚀

---

**Next Action:** Open `docs/dev/documentation-refactoring-plan.md` → Run Phase 1, Step 1

**Questions?** Read `docs/dev/documentation-guide.md` for background, or just start with the commands!

---

**Good luck!** You have excellent content. Making it beautiful and searchable is the easy part. 📖
