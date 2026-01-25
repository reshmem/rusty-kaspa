# Architecture Enforcement Guide

This document describes strategies to enforce and preserve the layered architecture separation in the igra codebase.

## Current Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    igra-service                         │
│  (HTTP API, CLI, Service orchestration)                 │
├─────────────────────────────────────────────────────────┤
│                    application/                         │
│  (Coordinator, Signer, EventProcessor, Lifecycle)       │
├─────────────────────────────────────────────────────────┤
│     infrastructure/          │        domain/           │
│  (Storage, RPC, Transport,   │  (Models, Validation,    │
│   Config, Audit)             │   Policy, Signing, PSKT) │
├──────────────────────────────┴──────────────────────────┤
│                    foundation/                          │
│  (Types, Errors, Constants, HD utilities)               │
└─────────────────────────────────────────────────────────┘
```

## Allowed Dependencies

```
service      → application, infrastructure, domain, foundation
application  → infrastructure, domain, foundation
infrastructure → domain, foundation
domain       → foundation ONLY
foundation   → external crates ONLY (no internal deps)
```

## Forbidden Dependencies

| From | Cannot Depend On | Reason |
|------|------------------|--------|
| `domain/` | `infrastructure/` | Domain must be infrastructure-agnostic |
| `domain/` | `application/` | Domain is orchestrated, not orchestrating |
| `domain/` | `tracing`, `log` | Logging is infrastructure concern |
| `domain/` | `tokio`, `async-trait` | Async is infrastructure concern |
| `foundation/` | Any internal module | Foundation is the base layer |
| `infrastructure/` | `application/` | Infra is used by app, not vice versa |

---

## Strategy 1: Crate-Level Separation

**Recommended for strict enforcement**

Split into separate crates with explicit dependencies:

```toml
# Cargo.toml (workspace)
[workspace]
members = [
    "igra-foundation",
    "igra-domain",
    "igra-infrastructure",
    "igra-application",
    "igra-service",
]

# igra-domain/Cargo.toml
[dependencies]
igra-foundation = { path = "../igra-foundation" }
# NO igra-infrastructure, NO tracing, NO tokio

# igra-infrastructure/Cargo.toml
[dependencies]
igra-foundation = { path = "../igra-foundation" }
igra-domain = { path = "../igra-domain" }
tracing = "0.1"
tokio = { version = "1", features = ["full"] }
rocksdb = "0.21"

# igra-application/Cargo.toml
[dependencies]
igra-foundation = { path = "../igra-foundation" }
igra-domain = { path = "../igra-domain" }
igra-infrastructure = { path = "../igra-infrastructure" }
tracing = "0.1"
tokio = { version = "1", features = ["full"] }
```

**Pros:**
- Compile-time enforcement (won't compile if violated)
- Clear dependency graph
- Enables independent versioning

**Cons:**
- More complex workspace setup
- Refactoring effort to split existing code

---

## Strategy 2: CI Dependency Checks (Recommended for Current Structure)

Add automated checks to CI pipeline.

### 2.1 Forbidden Import Check Script

Create `scripts/check-architecture.sh`:

```bash
#!/bin/bash
set -e

echo "=== Architecture Dependency Check ==="

ERRORS=0

# Rule 1: domain/ cannot import from infrastructure/
echo "Checking: domain/ does not import infrastructure/"
if grep -r "use crate::infrastructure" igra-core/src/domain/ 2>/dev/null; then
    echo "ERROR: domain/ imports infrastructure/"
    ERRORS=$((ERRORS + 1))
fi

# Rule 2: domain/ cannot import from application/
echo "Checking: domain/ does not import application/"
if grep -r "use crate::application" igra-core/src/domain/ 2>/dev/null; then
    echo "ERROR: domain/ imports application/"
    ERRORS=$((ERRORS + 1))
fi

# Rule 3: domain/ cannot use tracing
echo "Checking: domain/ does not use tracing"
if grep -r "use tracing" igra-core/src/domain/ 2>/dev/null; then
    echo "ERROR: domain/ uses tracing (logging is infrastructure concern)"
    ERRORS=$((ERRORS + 1))
fi

# Rule 4: domain/ cannot use tokio directly
echo "Checking: domain/ does not use tokio"
if grep -r "use tokio" igra-core/src/domain/ 2>/dev/null; then
    echo "ERROR: domain/ uses tokio (async runtime is infrastructure concern)"
    ERRORS=$((ERRORS + 1))
fi

# Rule 5: foundation/ cannot import internal modules
echo "Checking: foundation/ does not import internal modules"
if grep -r "use crate::domain\|use crate::infrastructure\|use crate::application" igra-core/src/foundation/ 2>/dev/null; then
    echo "ERROR: foundation/ imports internal modules"
    ERRORS=$((ERRORS + 1))
fi

# Rule 6: infrastructure/ cannot import application/
echo "Checking: infrastructure/ does not import application/"
if grep -r "use crate::application" igra-core/src/infrastructure/ 2>/dev/null; then
    echo "ERROR: infrastructure/ imports application/"
    ERRORS=$((ERRORS + 1))
fi

if [ $ERRORS -gt 0 ]; then
    echo ""
    echo "=== FAILED: $ERRORS architecture violations found ==="
    exit 1
fi

echo ""
echo "=== PASSED: All architecture checks passed ==="
```

### 2.2 GitHub Actions Workflow

Create `.github/workflows/architecture.yml`:

```yaml
name: Architecture Check

on:
  push:
    branches: [master, devel]
  pull_request:
    branches: [master, devel]

jobs:
  architecture:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Check Architecture Dependencies
        run: |
          chmod +x scripts/check-architecture.sh
          ./scripts/check-architecture.sh
        working-directory: wallet/igra

      - name: Check for forbidden patterns in domain
        run: |
          # Domain should not have async functions
          if grep -r "async fn" igra-core/src/domain/ --include="*.rs"; then
            echo "WARNING: domain/ contains async functions"
            # Uncomment to make this a hard failure:
            # exit 1
          fi
        working-directory: wallet/igra
```

---

## Strategy 3: Rust Module Visibility

Use Rust's visibility system to enforce boundaries.

### 3.1 Private Module Internals

```rust
// igra-core/src/domain/mod.rs

// Public API - what other layers can use
pub mod model;
pub mod validation;
pub mod policy;
pub mod signing;
pub mod pskt;
pub mod coordination;
pub mod hashes;
pub mod group_id;

// Re-export only stable types
pub use model::*;
pub use validation::{MessageVerifier, VerificationReport, ValidationSource};
pub use policy::{PolicyEnforcer, GroupPolicy};
pub use signing::{SignerBackend, SigningBackendKind, PartialSigSubmit};

// Internal types not re-exported (implementation details)
// These can only be accessed as domain::internal::Foo
pub(crate) mod internal {
    // Implementation details hidden from other layers
}
```

### 3.2 Seal Traits to Prevent External Implementation

```rust
// domain/validation/mod.rs

mod private {
    pub trait Sealed {}
}

/// Message verifier trait - sealed to prevent external implementation
pub trait MessageVerifier: private::Sealed + Send + Sync {
    fn verify(&self, event: &SigningEvent) -> Result<VerificationReport, ThresholdError>;
}

// Only our types can implement it
impl private::Sealed for CompositeVerifier {}
impl private::Sealed for NoopVerifier {}
```

---

## Strategy 4: Architecture Tests (Rust)

Create dedicated architecture tests that run with `cargo test`.

### 4.1 Create Architecture Test Module

`igra-core/tests/architecture.rs`:

```rust
//! Architecture enforcement tests
//!
//! These tests verify that our layered architecture is preserved.
//! Run with: cargo test --test architecture

use std::fs;
use std::path::Path;

const DOMAIN_PATH: &str = "src/domain";
const INFRASTRUCTURE_PATH: &str = "src/infrastructure";
const APPLICATION_PATH: &str = "src/application";
const FOUNDATION_PATH: &str = "src/foundation";

fn collect_rust_files(dir: &Path) -> Vec<String> {
    let mut files = Vec::new();
    if dir.is_dir() {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files.extend(collect_rust_files(&path));
            } else if path.extension().map_or(false, |e| e == "rs") {
                files.push(fs::read_to_string(&path).unwrap());
            }
        }
    }
    files
}

fn contains_import(content: &str, pattern: &str) -> bool {
    content.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("use ") && trimmed.contains(pattern)
    })
}

#[test]
fn domain_does_not_depend_on_infrastructure() {
    let files = collect_rust_files(Path::new(DOMAIN_PATH));
    for content in &files {
        assert!(
            !contains_import(content, "crate::infrastructure"),
            "domain/ must not import from infrastructure/"
        );
        assert!(
            !contains_import(content, "super::infrastructure"),
            "domain/ must not import from infrastructure/"
        );
    }
}

#[test]
fn domain_does_not_depend_on_application() {
    let files = collect_rust_files(Path::new(DOMAIN_PATH));
    for content in &files {
        assert!(
            !contains_import(content, "crate::application"),
            "domain/ must not import from application/"
        );
    }
}

#[test]
fn domain_does_not_use_tracing() {
    let files = collect_rust_files(Path::new(DOMAIN_PATH));
    for content in &files {
        assert!(
            !contains_import(content, "tracing"),
            "domain/ must not use tracing (logging is infrastructure concern)"
        );
    }
}

#[test]
fn domain_does_not_use_tokio() {
    let files = collect_rust_files(Path::new(DOMAIN_PATH));
    for content in &files {
        assert!(
            !contains_import(content, "tokio"),
            "domain/ must not use tokio (async runtime is infrastructure concern)"
        );
    }
}

#[test]
fn domain_does_not_use_async_trait() {
    let files = collect_rust_files(Path::new(DOMAIN_PATH));
    for content in &files {
        assert!(
            !contains_import(content, "async_trait"),
            "domain/ must not use async_trait"
        );
    }
}

#[test]
fn foundation_has_no_internal_dependencies() {
    let files = collect_rust_files(Path::new(FOUNDATION_PATH));
    for content in &files {
        assert!(
            !contains_import(content, "crate::domain"),
            "foundation/ must not import domain/"
        );
        assert!(
            !contains_import(content, "crate::infrastructure"),
            "foundation/ must not import infrastructure/"
        );
        assert!(
            !contains_import(content, "crate::application"),
            "foundation/ must not import application/"
        );
    }
}

#[test]
fn infrastructure_does_not_depend_on_application() {
    let files = collect_rust_files(Path::new(INFRASTRUCTURE_PATH));
    for content in &files {
        assert!(
            !contains_import(content, "crate::application"),
            "infrastructure/ must not import application/"
        );
    }
}

#[test]
fn domain_functions_are_not_async() {
    let files = collect_rust_files(Path::new(DOMAIN_PATH));
    for content in &files {
        // Allow async in test modules
        let without_tests: String = content
            .lines()
            .filter(|line| !line.contains("#[cfg(test)]"))
            .collect::<Vec<_>>()
            .join("\n");

        let has_async_fn = without_tests
            .lines()
            .any(|line| {
                let trimmed = line.trim();
                (trimmed.starts_with("pub async fn") ||
                 trimmed.starts_with("async fn") ||
                 trimmed.starts_with("pub(crate) async fn"))
                && !trimmed.contains("test")
            });

        assert!(
            !has_async_fn,
            "domain/ should not have async functions (async is infrastructure concern)"
        );
    }
}
```

### 4.2 Run Architecture Tests in CI

```yaml
# In .github/workflows/ci.yml
- name: Run Architecture Tests
  run: cargo test --test architecture -p igra-core
  working-directory: wallet/igra
```

---

## Strategy 5: Pre-commit Hooks

### 5.1 Install Pre-commit

```bash
pip install pre-commit
```

### 5.2 Create `.pre-commit-config.yaml`

```yaml
repos:
  - repo: local
    hooks:
      - id: architecture-check
        name: Architecture Dependency Check
        entry: bash -c 'cd wallet/igra && ./scripts/check-architecture.sh'
        language: system
        pass_filenames: false
        files: \.rs$

      - id: domain-no-logging
        name: Domain No Logging
        entry: bash -c 'if grep -r "use tracing" wallet/igra/igra-core/src/domain/; then exit 1; fi'
        language: system
        pass_filenames: false
        files: ^wallet/igra/igra-core/src/domain/.*\.rs$
```

### 5.3 Install Hooks

```bash
pre-commit install
```

---

## Strategy 6: Custom Clippy Lints (Advanced)

For complex rules, create custom clippy lints using `dylint`.

### 6.1 Setup dylint

```toml
# Cargo.toml
[workspace.metadata.dylint]
libraries = [
    { path = "lints/igra-arch-lints" }
]
```

### 6.2 Example Custom Lint

```rust
// lints/igra-arch-lints/src/lib.rs
use clippy_utils::diagnostics::span_lint_and_help;
use rustc_lint::{LateContext, LateLintPass};
use rustc_session::{declare_lint_pass, declare_tool_lint};

declare_tool_lint! {
    pub igra_arch_lints::DOMAIN_USES_TRACING,
    Warn,
    "domain layer should not use tracing"
}

declare_lint_pass!(DomainUsesTracing => [DOMAIN_USES_TRACING]);

impl<'tcx> LateLintPass<'tcx> for DomainUsesTracing {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx rustc_hir::Item<'tcx>) {
        // Check if we're in domain module and importing tracing
        let source_file = cx.sess().source_map().span_to_filename(item.span);
        if source_file.to_string().contains("/domain/") {
            // Check for tracing imports
            // ... implementation
        }
    }
}
```

---

## Strategy 7: Documentation & Code Review

### 7.1 Architecture Decision Records (ADRs)

Create `docs/adr/` directory:

```markdown
# ADR-001: Layered Architecture

## Status
Accepted

## Context
We need clear separation between business logic and infrastructure concerns.

## Decision
We adopt a 4-layer architecture:
- **foundation**: Base types, errors, constants
- **domain**: Pure business logic, no I/O
- **infrastructure**: External systems (storage, RPC, transport)
- **application**: Orchestration layer

## Consequences
- Domain layer must not use tracing, tokio, or any async constructs
- All logging happens in application/infrastructure layers
- Domain returns rich result types for logging context
```

### 7.2 PR Template

Create `.github/pull_request_template.md`:

```markdown
## Architecture Checklist

- [ ] Domain changes do not add infrastructure dependencies
- [ ] Domain changes do not add logging/tracing
- [ ] Domain changes do not add async functions
- [ ] New types in domain return rich results (not just bool/unit)
- [ ] Application layer handles logging for domain operations
- [ ] Architecture tests pass (`cargo test --test architecture`)
```

### 7.3 CODEOWNERS

```
# .github/CODEOWNERS
/wallet/igra/igra-core/src/domain/ @architecture-team
/wallet/igra/igra-core/src/foundation/ @architecture-team
```

---

## Implementation Priority

| Strategy | Effort | Impact | Recommendation |
|----------|--------|--------|----------------|
| CI Dependency Checks | Low | High | **Implement first** |
| Architecture Tests | Medium | High | **Implement second** |
| Pre-commit Hooks | Low | Medium | Implement third |
| Module Visibility | Low | Medium | Ongoing refactor |
| Crate Separation | High | Very High | Future milestone |
| Custom Lints | High | High | Optional |
| Documentation/ADRs | Low | Medium | Implement alongside |

---

## Quick Start

1. **Create the check script:**
```bash
mkdir -p scripts
cat > scripts/check-architecture.sh << 'EOF'
#!/bin/bash
# ... (content from Strategy 2.1)
EOF
chmod +x scripts/check-architecture.sh
```

2. **Add architecture tests:**
```bash
# Create igra-core/tests/architecture.rs with content from Strategy 4.1
```

3. **Run checks locally:**
```bash
./scripts/check-architecture.sh
cargo test --test architecture -p igra-core
```

4. **Add to CI:**
```yaml
# Add to your GitHub Actions workflow
```

---

## Current Violations to Fix

Before enabling enforcement, fix these violations:

```bash
# Run to see current violations:
grep -r "use tracing" igra-core/src/domain/
```

Files to refactor (see DOMAIN_LOGGING_REFACTOR.md):
1. `domain/validation/hyperlane.rs`
2. `domain/validation/layerzero.rs`
3. `domain/policy/enforcement.rs`
4. `domain/signing/threshold.rs`
5. `domain/pskt/multisig.rs`
6. `domain/coordination/finalization.rs`
7. `domain/request/state_machine.rs`

Once these are fixed, enable the CI checks to prevent regressions.
