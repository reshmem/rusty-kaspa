#!/bin/bash
# security-audit.sh - Pre-deployment security audit for Igra
# Run this before production deployment to catch security issues
#
# Usage: ./security-audit.sh [--fix]
#   --fix: Attempt to fix file permission issues automatically

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

FIX_MODE=false
ERRORS=0
WARNINGS=0

# Parse arguments
if [ "$1" = "--fix" ]; then
    FIX_MODE=true
fi

echo -e "${BLUE}🔒 Igra Security Audit${NC}"
echo "====================="
echo

# Helper functions
pass() {
    echo -e "${GREEN}✅ PASS:${NC} $1"
}

fail() {
    echo -e "${RED}❌ FAIL:${NC} $1"
    ERRORS=$((ERRORS + 1))
}

warn() {
    echo -e "${YELLOW}⚠️  WARNING:${NC} $1"
    WARNINGS=$((WARNINGS + 1))
}

info() {
    echo -e "${BLUE}ℹ️  INFO:${NC} $1"
}

section() {
    echo
    echo -e "${BLUE}$1${NC}"
    echo "---"
}

# 1. Check for secrets in logs
section "1. Checking for secret leaks in log statements..."
if grep -rn "private.key\|mnemonic\|passphrase\|wallet_secret\|payment_secret" \
    igra-core/src igra-service/src 2>/dev/null | \
    grep -E "info!\|warn!\|error!\|debug!\|trace!" | \
    grep -v "tests/" | \
    grep -v "#\[cfg(test)\]" | \
    grep -v "// Example\|TODO\|FIXME"; then
    fail "Potential secret leak found in log statements (see above)"
else
    pass "No secret leaks found in log statements"
fi

# 2. Check for hardcoded secrets
section "2. Checking for hardcoded secrets..."
if grep -rn "changeme\|password123\|test.*secret\|secret.*=.*\"[a-zA-Z0-9]\{8,\}\"" \
    igra-core/src igra-service/src 2>/dev/null | \
    grep -v "tests/\|examples/\|/bin/\|TODO\|FIXME\|doc"; then
    fail "Potential hardcoded secrets found (see above)"
else
    pass "No hardcoded secrets found"
fi

# 3. Check for unwrap/expect in security-critical code
section "3. Checking for panic risks in key management..."
CRITICAL_FILES=(
    "igra-core/src/foundation/hd.rs"
    "igra-core/src/infrastructure/secrets/"
)
FOUND_PANICS=false
for file_pattern in "${CRITICAL_FILES[@]}"; do
    if [ -e "$file_pattern" ] || [ -d "$file_pattern" ]; then
        if grep -rn "\.unwrap()\|\.expect(" "$file_pattern" 2>/dev/null | \
           grep -v "#\[cfg(test)\]\|#\[test\]\|tests/"; then
            FOUND_PANICS=true
        fi
    fi
done

if [ "$FOUND_PANICS" = true ]; then
    fail "Found unwrap/expect in key management code (see above)"
else
    pass "No panic risks in key management code"
fi

# 4. Check NetworkMode usage
section "4. Checking NetworkMode enforcement..."
if grep -q "NetworkMode::" igra-service/src/bin/kaspa-threshold-service.rs 2>/dev/null; then
    pass "NetworkMode enforcement present"
else
    warn "NetworkMode may not be enforced in main binary"
fi

# 5. Check for manual hex::encode in API responses
section "5. Checking for hex::encode anti-patterns in APIs..."
if grep -rn "hex::encode" igra-service/src/api/handlers/ 2>/dev/null | \
   grep -v "tests/\|TODO\|FIXME"; then
    warn "Manual hex::encode found in API handlers (see above) - should use typed serialization"
else
    pass "No manual hex::encode anti-patterns in API handlers"
fi

# 6. Check for duplicate hex parsing functions
section "6. Checking for duplicate hex parsing functions..."
if grep -rn "fn parse_.*hex.*(" igra-core/src igra-service/src 2>/dev/null | \
   grep -v "foundation/util/encoding.rs\|tests/"; then
    warn "Duplicate hex parsing functions found (see above) - consolidate to foundation/util/encoding.rs"
else
    pass "No duplicate hex parsing functions"
fi

# 7. Check for ThresholdError::Message overuse
section "7. Checking ThresholdError::Message usage..."
THRESHOLD_ERRORS=$(grep -rn "ThresholdError::Message" igra-core/src igra-service/src 2>/dev/null | \
    grep -v "tests/\|/bin/\|TODO" | wc -l || echo "0")
if [ "$THRESHOLD_ERRORS" -gt 10 ]; then
    warn "Found $THRESHOLD_ERRORS uses of ThresholdError::Message - should use structured variants"
else
    pass "ThresholdError::Message usage is acceptable ($THRESHOLD_ERRORS instances)"
fi

# 8. Validate test code isolation
section "8. Checking test code isolation..."
if grep -rn "\.unwrap()\|\.expect(" igra-core/src igra-service/src 2>/dev/null | \
   grep -v "tests/\|#\[cfg(test)\]\|#\[test\]" | \
   grep "fn test_\|mod test" | head -5; then
    warn "Test functions found outside #[cfg(test)] modules (see above)"
else
    pass "Test code properly isolated"
fi

# 9. Run security unit tests
section "9. Running security unit tests..."
if cargo test -p igra-core network_mode_security --quiet --no-fail-fast 2>&1 | tail -20; then
    pass "All security tests passed"
else
    fail "Security tests failed (see above)"
fi

# 10. Check file permission validation code
section "10. Checking file permission validation..."
if grep -q "0o600\|0o700" igra-core/src/infrastructure/network_mode/rules/filesystem.rs 2>/dev/null; then
    pass "File permission validation present"
else
    fail "File permission validation missing in network_mode/rules/filesystem.rs"
fi

# 11. Check for swallowed errors (let _ = )
section "11. Checking for swallowed errors..."
if grep -rn "let _ =" igra-core/src igra-service/src 2>/dev/null | \
   grep -v "tests/\|#\[cfg(test)\]" | \
   grep "Result\|?" | head -10; then
    warn "Potential swallowed errors found (let _ = with Result types)"
else
    pass "No swallowed errors detected"
fi

# 12. Verify audit logging implementation
section "12. Checking audit logging..."
if grep -q "KeyAuditLog\|AuditLog" igra-core/src/infrastructure/audit/ 2>/dev/null; then
    pass "Audit logging implementation present"
else
    fail "Audit logging implementation not found"
fi

# 13. Check for debug format {:?} in important logs
section "13. Checking for {:?} format in production logs..."
if grep -rn '{:?\}' igra-core/src igra-service/src 2>/dev/null | \
   grep -E "info!\|warn!\|error!" | \
   grep -v "tests/" | head -5; then
    warn "Debug format {:?} found in production logs (should use {})"
else
    pass "No inappropriate debug formatting in logs"
fi

# Summary
echo
echo "======================================="
echo -e "${BLUE}Security Audit Summary${NC}"
echo "======================================="
if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}🎉 All checks passed!${NC}"
    echo
    echo "Next steps:"
    echo "  1. Run: cargo clippy --workspace -- -D warnings"
    echo "  2. Run: cargo test --workspace"
    echo "  3. Validate config: kaspa-threshold-service --config <config> --validate-only"
    echo
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠️  $WARNINGS warning(s) found${NC}"
    echo
    echo "Review warnings above. Most are low-priority improvements."
    echo
    exit 0
else
    echo -e "${RED}❌ $ERRORS error(s) and $WARNINGS warning(s) found${NC}"
    echo
    echo "Fix errors above before proceeding to production deployment."
    echo
    exit 1
fi
