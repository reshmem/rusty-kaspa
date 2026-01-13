//! Architecture enforcement tests
//!
//! These tests verify that our layered architecture is preserved.
//! Run with: cargo test --test architecture
//!
//! Architecture rules:
//! - domain/ must not depend on infrastructure/, application/, or tracing
//! - foundation/ must not depend on any internal modules
//! - infrastructure/ must not depend on application/

use std::fs;
use std::path::Path;

const DOMAIN_PATH: &str = "src/domain";
const INFRASTRUCTURE_PATH: &str = "src/infrastructure";
const FOUNDATION_PATH: &str = "src/foundation";

fn collect_rust_files(dir: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    if dir.is_dir() {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files.extend(collect_rust_files(&path));
            } else if path.extension().map_or(false, |e| e == "rs") {
                let content = fs::read_to_string(&path).unwrap();
                let path_str = path.to_string_lossy().to_string();
                files.push((path_str, content));
            }
        }
    }
    files
}

fn contains_import(content: &str, pattern: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("use ") && trimmed.contains(pattern) {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn check_no_import(dir_path: &str, pattern: &str, layer_name: &str, forbidden: &str) {
    let path = Path::new(dir_path);
    if !path.exists() {
        return;
    }

    let files = collect_rust_files(path);
    let mut violations = Vec::new();

    for (file_path, content) in &files {
        if let Some(import_line) = contains_import(content, pattern) {
            violations.push(format!("  {}: {}", file_path, import_line));
        }
    }

    assert!(
        violations.is_empty(),
        "\n{} must not import {}.\n\nViolations found:\n{}\n",
        layer_name,
        forbidden,
        violations.join("\n")
    );
}

// =============================================================================
// Domain Layer Tests
// =============================================================================

#[test]
fn domain_does_not_depend_on_infrastructure() {
    check_no_import(DOMAIN_PATH, "crate::infrastructure", "domain/", "infrastructure/");
}

#[test]
fn domain_does_not_depend_on_application() {
    check_no_import(DOMAIN_PATH, "crate::application", "domain/", "application/");
}

#[test]
#[ignore = "Fix violations in DOMAIN_LOGGING_REFACTOR.md first"]
fn domain_does_not_use_tracing() {
    check_no_import(DOMAIN_PATH, "tracing", "domain/", "tracing (logging is infrastructure concern)");
}

#[test]
fn domain_does_not_use_tokio() {
    check_no_import(DOMAIN_PATH, "tokio", "domain/", "tokio (async runtime is infrastructure concern)");
}

#[test]
fn domain_does_not_use_async_trait() {
    check_no_import(DOMAIN_PATH, "async_trait", "domain/", "async_trait (async is infrastructure concern)");
}

// =============================================================================
// Foundation Layer Tests
// =============================================================================

#[test]
fn foundation_does_not_depend_on_domain() {
    check_no_import(FOUNDATION_PATH, "crate::domain", "foundation/", "domain/");
}

#[test]
fn foundation_does_not_depend_on_infrastructure() {
    check_no_import(FOUNDATION_PATH, "crate::infrastructure", "foundation/", "infrastructure/");
}

#[test]
fn foundation_does_not_depend_on_application() {
    check_no_import(FOUNDATION_PATH, "crate::application", "foundation/", "application/");
}

// =============================================================================
// Infrastructure Layer Tests
// =============================================================================

#[test]
fn infrastructure_does_not_depend_on_application() {
    check_no_import(INFRASTRUCTURE_PATH, "crate::application", "infrastructure/", "application/");
}

// =============================================================================
// Advanced Checks
// =============================================================================

#[test]
fn domain_functions_are_synchronous() {
    let path = Path::new(DOMAIN_PATH);
    if !path.exists() {
        return;
    }

    let files = collect_rust_files(path);
    let mut violations = Vec::new();

    for (file_path, content) in &files {
        // Skip test modules
        if file_path.contains("/tests/") || file_path.ends_with("_test.rs") {
            continue;
        }

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            // Skip lines in test cfg blocks
            if trimmed.contains("#[cfg(test)]") {
                continue;
            }

            // Check for async fn declarations
            if (trimmed.starts_with("pub async fn") || trimmed.starts_with("async fn") || trimmed.starts_with("pub(crate) async fn"))
                && !trimmed.contains("test")
            {
                violations.push(format!("  {}:{}: {}", file_path, line_num + 1, trimmed));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "\ndomain/ should not contain async functions (async is infrastructure concern).\n\nViolations found:\n{}\n",
        violations.join("\n")
    );
}

/// Test that domain types implement standard traits for testability
#[test]
fn domain_error_types_are_debug() {
    // This is a compile-time check - if ThresholdError doesn't impl Debug,
    // this won't compile
    fn assert_debug<T: std::fmt::Debug>() {}
    assert_debug::<igra_core::foundation::ThresholdError>();
}

/// Test that domain types are Clone where needed
#[test]
fn domain_model_types_are_clone() {
    fn assert_clone<T: Clone>() {}
    assert_clone::<igra_core::domain::SigningEvent>();
    assert_clone::<igra_core::domain::StoredEventCrdt>();
    assert_clone::<igra_core::domain::GroupPolicy>();
}
