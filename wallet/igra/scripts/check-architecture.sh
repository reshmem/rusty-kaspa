#!/bin/bash
#
# Architecture Dependency Check Script
#
# This script verifies that the layered architecture is preserved:
# - domain/ does not depend on infrastructure/, application/, or logging
# - foundation/ has no internal dependencies
# - infrastructure/ does not depend on application/
#
# Run from the igra directory: ./scripts/check-architecture.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DOMAIN_DIR="$PROJECT_DIR/igra-core/src/domain"
INFRA_DIR="$PROJECT_DIR/igra-core/src/infrastructure"
FOUNDATION_DIR="$PROJECT_DIR/igra-core/src/foundation"
APP_DIR="$PROJECT_DIR/igra-core/src/application"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ERRORS=0
WARNINGS=0

echo "=========================================="
echo "  Architecture Dependency Check"
echo "=========================================="
echo ""

check_forbidden_import() {
    local dir="$1"
    local pattern="$2"
    local layer_name="$3"
    local forbidden_name="$4"
    local is_error="${5:-true}"

    if [ ! -d "$dir" ]; then
        echo -e "${YELLOW}SKIP${NC}: Directory $dir does not exist"
        return
    fi

    local matches
    matches=$(grep -r "$pattern" "$dir" --include="*.rs" 2>/dev/null || true)

    if [ -n "$matches" ]; then
        if [ "$is_error" = "true" ]; then
            echo -e "${RED}FAIL${NC}: $layer_name imports $forbidden_name"
            echo "$matches" | head -10
            ERRORS=$((ERRORS + 1))
        else
            echo -e "${YELLOW}WARN${NC}: $layer_name imports $forbidden_name"
            echo "$matches" | head -5
            WARNINGS=$((WARNINGS + 1))
        fi
    else
        echo -e "${GREEN}PASS${NC}: $layer_name does not import $forbidden_name"
    fi
}

echo "--- Domain Layer Checks ---"
echo ""

# Rule 1: domain/ cannot import from infrastructure/
check_forbidden_import "$DOMAIN_DIR" "use crate::infrastructure" "domain/" "infrastructure/"

# Rule 2: domain/ cannot import from application/
check_forbidden_import "$DOMAIN_DIR" "use crate::application" "domain/" "application/"

# Rule 3: domain/ cannot use tracing
check_forbidden_import "$DOMAIN_DIR" "use tracing" "domain/" "tracing (logging)"

# Rule 4: domain/ cannot use tokio directly
check_forbidden_import "$DOMAIN_DIR" "use tokio" "domain/" "tokio (async runtime)"

# Rule 5: domain/ cannot use async_trait
check_forbidden_import "$DOMAIN_DIR" "use async_trait" "domain/" "async_trait"

echo ""
echo "--- Foundation Layer Checks ---"
echo ""

# Rule 6: foundation/ cannot import domain/
check_forbidden_import "$FOUNDATION_DIR" "use crate::domain" "foundation/" "domain/"

# Rule 7: foundation/ cannot import infrastructure/
check_forbidden_import "$FOUNDATION_DIR" "use crate::infrastructure" "foundation/" "infrastructure/"

# Rule 8: foundation/ cannot import application/
check_forbidden_import "$FOUNDATION_DIR" "use crate::application" "foundation/" "application/"

echo ""
echo "--- Infrastructure Layer Checks ---"
echo ""

# Rule 9: infrastructure/ cannot import application/
check_forbidden_import "$INFRA_DIR" "use crate::application" "infrastructure/" "application/"

echo ""
echo "--- Async Function Checks ---"
echo ""

# Rule 10: domain/ should not have async functions (warning only)
if [ -d "$DOMAIN_DIR" ]; then
    async_fns=$(grep -r "async fn" "$DOMAIN_DIR" --include="*.rs" 2>/dev/null | grep -v "test" | grep -v "#\[cfg(test)\]" || true)
    if [ -n "$async_fns" ]; then
        echo -e "${YELLOW}WARN${NC}: domain/ contains async functions (should be sync)"
        echo "$async_fns" | head -5
        WARNINGS=$((WARNINGS + 1))
    else
        echo -e "${GREEN}PASS${NC}: domain/ has no async functions"
    fi
fi

echo ""
echo "=========================================="

if [ $ERRORS -gt 0 ]; then
    echo -e "${RED}FAILED${NC}: $ERRORS error(s), $WARNINGS warning(s)"
    echo ""
    echo "Fix the violations above before merging."
    echo "See DOMAIN_LOGGING_REFACTOR.md for guidance."
    exit 1
elif [ $WARNINGS -gt 0 ]; then
    echo -e "${YELLOW}PASSED WITH WARNINGS${NC}: $WARNINGS warning(s)"
    echo ""
    echo "Consider addressing the warnings above."
    exit 0
else
    echo -e "${GREEN}PASSED${NC}: All architecture checks passed"
    exit 0
fi
