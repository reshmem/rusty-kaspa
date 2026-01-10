#!/bin/bash
# Day 1 Refactoring Script - Production Ready Architecture
# Run this from: /Users/user/Source/personal/rusty-kaspa/wallet/igra
#
# IMPORTANT: Read PRODUCTION-REFACTOR-PLAN.md first!
# This script automates Day 1 tasks but YOU must verify each step.

set -e  # Exit on error

echo "========================================="
echo "Day 1: Production Refactoring - Starting"
echo "========================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
function step() {
    echo -e "${GREEN}[STEP]${NC} $1"
}

function warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

function error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

function check() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $1"
    else
        echo -e "${RED}✗${NC} $1 FAILED"
        exit 1
    fi
}

# Verify we're in the right directory
if [ ! -f "igra-core/Cargo.toml" ]; then
    error "Not in igra directory! Run from /Users/user/Source/personal/rusty-kaspa/wallet/igra"
    exit 1
fi

step "Current directory verified: $(pwd)"

# ============================================================================
# PHASE 0: Backup
# ============================================================================

echo ""
echo "========================================="
echo "PHASE 0: Creating Backup"
echo "========================================="

step "Checking git status..."
git status --short

warning "About to commit current state. Press Enter to continue or Ctrl+C to abort"
read

step "Creating backup commit..."
git add .
git commit -m "Backup before Day 1 production refactor" || true
check "Backup commit created"

step "Creating backup tag..."
git tag "before-day1-refactor-$(date +%Y%m%d-%H%M%S)"
check "Backup tag created"

echo ""
echo "Backup complete! You can rollback with:"
echo "  git reset --hard before-day1-refactor-*"

# ============================================================================
# PHASE 1: Delete Duplicates
# ============================================================================

echo ""
echo "========================================="
echo "PHASE 1: Delete Duplicate Files"
echo "========================================="

warning "About to delete duplicate coordinator/signer in infrastructure/"
warning "Press Enter to continue or Ctrl+C to abort"
read

step "Deleting infrastructure/coordination/coordinator.rs..."
rm -f igra-core/src/infrastructure/coordination/coordinator.rs
check "Deleted coordinator duplicate"

step "Deleting infrastructure/coordination/signer.rs..."
rm -f igra-core/src/infrastructure/coordination/signer.rs
check "Deleted signer duplicate"

step "Updating infrastructure/coordination/mod.rs..."
cat > igra-core/src/infrastructure/coordination/mod.rs << 'EOF'
//! Infrastructure coordination utilities
//!
//! This module contains infrastructure-level coordination utilities like
//! transaction monitoring, not the main Coordinator/Signer orchestration
//! (those are in the application layer).

pub mod monitoring;

pub use monitoring::TransactionMonitor;
EOF
check "Updated infrastructure/coordination/mod.rs"

step "Verifying build breaks (expected)..."
if cargo build --package igra-core 2>&1 | grep -q "cannot find.*Coordinator\|cannot find.*Signer"; then
    echo -e "${GREEN}✓${NC} Build breaks as expected (Coordinator/Signer not found)"
else
    warning "Build didn't break as expected - might be using legacy paths"
fi

# ============================================================================
# PHASE 2: Move Coordinator to Application
# ============================================================================

echo ""
echo "========================================="
echo "PHASE 2: Move Coordinator/Signer to Application"
echo "========================================="

warning "About to move coordinator/signer to application layer"
warning "Press Enter to continue or Ctrl+C to abort"
read

step "Moving coordinator.rs to application/..."
mv igra-core/src/coordination/coordinator.rs igra-core/src/application/coordinator.rs
check "Moved coordinator.rs"

step "Moving signer.rs to application/..."
mv igra-core/src/coordination/signer.rs igra-core/src/application/signer.rs
check "Moved signer.rs"

# ============================================================================
# PHASE 2b: Update Imports in coordinator.rs
# ============================================================================

echo ""
step "Updating imports in application/coordinator.rs..."

# Detect OS for sed syntax
if [[ "$OSTYPE" == "darwin"* ]]; then
    SED_INPLACE="sed -i ''"
else
    SED_INPLACE="sed -i"
fi

cd igra-core/src/application

# Update imports
sed -i '' 's|use crate::config::|use crate::infrastructure::config::|g' coordinator.rs
sed -i '' 's|use crate::storage::|use crate::infrastructure::storage::|g' coordinator.rs
sed -i '' 's|use crate::transport::|use crate::infrastructure::transport::|g' coordinator.rs
sed -i '' 's|use crate::rpc::|use crate::infrastructure::rpc::|g' coordinator.rs
sed -i '' 's|use crate::lifecycle::|use crate::application::lifecycle::|g' coordinator.rs
sed -i '' 's|use crate::model::|use crate::domain::model::|g' coordinator.rs
sed -i '' 's|use crate::pskt::|use crate::domain::pskt::|g' coordinator.rs
sed -i '' 's|use crate::types::|use crate::foundation::types::|g' coordinator.rs
sed -i '' 's|use crate::error::|use crate::foundation::error::|g' coordinator.rs

check "Updated coordinator.rs imports"

# ============================================================================
# PHASE 2c: Update Imports in signer.rs
# ============================================================================

echo ""
step "Updating imports in application/signer.rs..."

sed -i '' 's|use crate::config::|use crate::infrastructure::config::|g' signer.rs
sed -i '' 's|use crate::storage::|use crate::infrastructure::storage::|g' signer.rs
sed -i '' 's|use crate::transport::|use crate::infrastructure::transport::|g' signer.rs
sed -i '' 's|use crate::rpc::|use crate::infrastructure::rpc::|g' signer.rs
sed -i '' 's|use crate::lifecycle::|use crate::application::lifecycle::|g' signer.rs
sed -i '' 's|use crate::model::|use crate::domain::model::|g' signer.rs
sed -i '' 's|use crate::pskt::|use crate::domain::pskt::|g' signer.rs
sed -i '' 's|use crate::signing::|use crate::domain::signing::|g' signer.rs
sed -i '' 's|use crate::types::|use crate::foundation::types::|g' signer.rs
sed -i '' 's|use crate::error::|use crate::foundation::error::|g' signer.rs
sed -i '' 's|use crate::audit::|use crate::domain::audit::|g' signer.rs
sed -i '' 's|use crate::validation::|use crate::domain::validation::|g' signer.rs

check "Updated signer.rs imports"

cd ../../..  # Back to igra root

# ============================================================================
# PHASE 2d: Update application/mod.rs
# ============================================================================

echo ""
step "Updating application/mod.rs..."

cat > igra-core/src/application/mod.rs << 'EOF'
//! Application layer: orchestration combining domain + infrastructure
//!
//! This layer contains the main business workflow orchestration:
//! - Coordinator: Orchestrates signing session proposals
//! - Signer: Validates and signs proposals
//! - EventProcessor: Processes incoming events
//! - Lifecycle: Observability hooks

pub mod coordinator;
pub mod signer;
pub mod event_processor;
pub mod lifecycle;

pub use coordinator::Coordinator;
pub use signer::Signer;
pub use event_processor::{EventContext, EventProcessor, submit_signing_event};
pub use lifecycle::{LifecycleObserver, NoopObserver};
EOF

check "Updated application/mod.rs"

# ============================================================================
# PHASE 2e: Try to Build
# ============================================================================

echo ""
echo "========================================="
echo "Attempting Build..."
echo "========================================="

step "Building igra-core..."
if cargo build --package igra-core 2>&1 | tee build.log; then
    echo -e "${GREEN}✓✓✓${NC} BUILD SUCCESSFUL!"
else
    error "Build failed. Check build.log for errors."
    echo ""
    echo "Common issues:"
    echo "  - Missing imports: Add them manually"
    echo "  - Wrong paths: Check domain vs infrastructure"
    echo "  - Circular deps: Domain shouldn't import infrastructure"
    echo ""
    echo "To rollback:"
    echo "  git reset --hard before-day1-refactor-*"
    exit 1
fi

# ============================================================================
# PHASE 2f: Run Tests
# ============================================================================

echo ""
echo "========================================="
echo "Running Tests..."
echo "========================================="

step "Running igra-core tests..."
if cargo test --package igra-core -- --test-threads=1 2>&1 | tee test.log; then
    echo -e "${GREEN}✓✓✓${NC} TESTS PASSED!"
else
    warning "Some tests failed. Check test.log"
    echo ""
    echo "This might be OK if tests need import updates."
    echo "Check test files in igra-core/tests/"
    echo ""
    echo "Continue anyway? (y/n)"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# ============================================================================
# Success!
# ============================================================================

echo ""
echo "========================================="
echo "Day 1 Morning: COMPLETE! ✓"
echo "========================================="
echo ""
echo "What was done:"
echo "  ✓ Deleted duplicate coordinator/signer"
echo "  ✓ Moved coordinator/signer to application/"
echo "  ✓ Updated imports to new paths"
echo "  ✓ Code compiles"
echo "  ✓ Tests pass (or ready to fix)"
echo ""
echo "Next steps:"
echo "  1. Commit these changes:"
echo "     git add ."
echo "     git commit -m 'refactor: move coordinator/signer to application (Day 1 complete)'"
echo ""
echo "  2. Continue with Day 1 Afternoon (if time permits):"
echo "     - Read PRODUCTION-REFACTOR-PLAN.md Phase 3"
echo "     - Move model.rs to domain/model.rs"
echo ""
echo "  3. Or stop here and continue tomorrow"
echo ""
echo "Status files updated:"
echo "  - Build log: build.log"
echo "  - Test log: test.log"
echo ""
echo "To rollback if needed:"
echo "  git reset --hard before-day1-refactor-*"
echo ""

exit 0
