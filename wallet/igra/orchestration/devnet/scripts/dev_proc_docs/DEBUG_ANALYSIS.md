# Debug Log Analysis - Missing Binaries Issue

**Date**: 2026-01-07
**Issue**: rothschild binary not built, kaspad requires retry

---

## 🔍 **Root Cause Identified**

### Problem

The cargo build command has a **`--bin` filter issue**:

```bash
# Line 160 from log (build_rusty_repo function):
cargo build --release --locked \
  -p kaspad \
  -p rothschild \
  -p igra-service --bin kaspa-threshold-service --bin fake_hyperlane_ism_api
```

**What goes wrong**:
- The `--bin` flags filter binaries for **ALL** packages specified before them
- `kaspad` and `rothschild` packages don't have binaries named `kaspa-threshold-service` or `fake_hyperlane_ism_api`
- Result: kaspad and rothschild are **NOT built** in the first attempt

### Current Workaround

Lines 313-324 add a **retry for kaspad only**:
```bash
if [[ ! -x "${TARGET_DIR}/release/kaspad" ]]; then
  log_warn "kaspad binary not found after workspace build, retrying targeted kaspad build..."
  cargo build --release --locked -p kaspad --bin kaspad
fi
```

**Problem**: No similar retry for **rothschild**, so it stays missing!

### Evidence from Log

```
Line 822: Finished `release` profile [optimized] target(s) in 1m 59s
Line 823: + [[ ! -x /tmp/igra_devnet/target/release/kaspad ]]
Line 824: + log_warn 'kaspad binary not found after workspace build, retrying targeted kaspad build...'
Line 834: + cargo build --release --locked -p kaspad --bin kaspad
Line 1021: Finished `release` profile [optimized] target(s) in 50.57s
Line 1022: + [[ ! -x /tmp/igra_devnet/target/release/kaspad ]]  # Now it exists!

Line 1583: Missing rothschild; build it or set ROTHSCHILD_BIN...  # NEVER BUILT!
```

### Current Binary Status

```bash
$ ls -la /tmp/igra_devnet/target/release/
✅ kaspad                     # Built on retry (line 834)
❌ rothschild                 # NEVER BUILT - no retry mechanism
✅ kaspa-threshold-service    # Built correctly (has --bin filter)
✅ fake_hyperlane_ism_api     # Built correctly (has --bin filter)
✅ devnet-keygen              # Built separately (line 337)
✅ kaspa-miner                # Built separately (line 352)
```

---

## 🔧 **Solution Options**

### Option 1: Add Rothschild Retry (Quick Fix)

Add same retry logic for rothschild after kaspad retry.

**Implementation** (add after line 324):

```bash
    fi
    # Check for rothschild and retry if missing
    if [[ ! -x "${TARGET_DIR}/release/rothschild" ]]; then
      log_warn "rothschild binary not found after workspace build, retrying targeted rothschild build..."
      if ! (cd "${repo_path}" && RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" \
        cargo build --release --locked -p rothschild); then
        log_error "Targeted rothschild build failed; see build output above."
        exit 1
      fi
      if [[ ! -x "${TARGET_DIR}/release/rothschild" ]]; then
        log_error "rothschild still missing after targeted build (expected at ${TARGET_DIR}/release/rothschild)"
        exit 1
      fi
    fi
  fi
  # Build devnet-keygen separately...
```

**Pros**:
- ✅ Quick fix
- ✅ Consistent with existing kaspad retry
- ✅ Works with current structure

**Cons**:
- ⚠️ Band-aid solution
- ⚠️ Builds packages twice (inefficient)
- ⚠️ Doesn't fix the root cause

---

### Option 2: Fix Build Command (Better Solution)

Build each package with proper `--bin` filters or no filters.

**Implementation** (replace lines 304-312):

```bash
    # Build packages without conflicting --bin filters
    # kaspad and rothschild: build default binaries (no --bin filter)
    if ! (cd "${repo_path}" && RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" \
      cargo build --release --locked \
        -p kaspad \
        -p rothschild); then
      log_error "Failed to build kaspad and rothschild from ${repo_path}"
      exit 1
    fi

    # igra-service: build specific binaries
    if ! (cd "${repo_path}" && RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" \
      cargo build --release --locked \
        -p igra-service --bin kaspa-threshold-service --bin fake_hyperlane_ism_api); then
      log_error "Failed to build igra-service binaries from ${repo_path}"
      exit 1
    fi
```

Then **remove the retry logic** (lines 313-324) since it won't be needed.

**Pros**:
- ✅ Fixes root cause
- ✅ More efficient (builds once)
- ✅ Clearer what's being built
- ✅ No retry needed

**Cons**:
- ⚠️ More cargo invocations (but each is correct)

---

### Option 3: Build All Packages Without Filters (Simplest)

Let cargo build all default binaries for all packages.

**Implementation** (replace lines 304-324):

```bash
    # Build all packages with their default binaries
    if ! (cd "${repo_path}" && RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" \
      cargo build --release --locked \
        -p kaspad \
        -p rothschild \
        -p igra-service); then
      log_error "Failed to build kaspa binaries from ${repo_path}"
      exit 1
    fi

    # Verify critical binaries exist
    for binary in kaspad rothschild kaspa-threshold-service fake_hyperlane_ism_api; do
      if [[ ! -x "${TARGET_DIR}/release/${binary}" ]]; then
        log_error "${binary} not found after build (expected at ${TARGET_DIR}/release/${binary})"
        log_error "This may indicate the package doesn't produce this binary, or the build failed silently."
        exit 1
      fi
    done
```

**Pros**:
- ✅ Simplest solution
- ✅ Lets cargo decide what to build
- ✅ Validation ensures binaries exist
- ✅ Single build command

**Cons**:
- ⚠️ Might build extra binaries we don't need
- ⚠️ If igra-service has multiple binaries, builds all of them

---

## 📊 **Recommendation: Option 2**

**Why Option 2 is best**:
1. Fixes the root cause (incorrect --bin filter placement)
2. Explicit about what's being built
3. Efficient (no retries needed)
4. Clear separation of concerns

**Implementation Steps**:
1. Split the build into two cargo commands
2. Remove retry logic for kaspad (no longer needed)
3. Test that all binaries build correctly
4. Verify build time isn't significantly impacted

---

## 🧪 **Testing**

### After Implementing Fix

```bash
# Test 1: Clean build
./run_local_devnet.sh clean
./run_local_devnet.sh build 2>&1 | tee /tmp/test-build.log

# Verify all binaries exist
for bin in kaspad rothschild kaspa-threshold-service fake_hyperlane_ism_api devnet-keygen kaspa-miner; do
  if [[ -x /tmp/igra_devnet/target/release/${bin} ]]; then
    echo "✅ ${bin}"
  else
    echo "❌ ${bin} MISSING"
  fi
done

# Test 2: Check build log
grep "retrying targeted.*build" /tmp/test-build.log
# Should show NOTHING (no retries needed)

# Test 3: Full workflow
./run_local_devnet.sh clean
./run_local_devnet.sh setup
./run_local_devnet.sh start kaspad
./run_local_devnet.sh status
./run_local_devnet.sh stop
```

---

## 💡 **Additional Observations**

### Option 1 Already Implemented for Config Source

From the log (lines 1354-1357):
```bash
+ [[ clone == \c\l\o\n\e ]]
+ config_source=/tmp/igra_devnet/sources/rusty-kaspa/wallet/igra/orchestration/devnet
+ [[ ! -f /tmp/igra_devnet/sources/rusty-kaspa/wallet/igra/orchestration/devnet/.env ]]
+ ENV_FILE=/tmp/igra_devnet/sources/rusty-kaspa/wallet/igra/orchestration/devnet/.env
```

✅ **Config source fix (Option 1 from FIXES-2.md) is already implemented!**
The script now uses configs from the cloned GitHub repo in clone mode.

---

## 📝 **Complete Fix Code**

### Recommended Implementation (Option 2)

**File**: `run_local_devnet.sh`
**Lines to replace**: 304-324

```bash
  else
    # Clear RUSTC_WRAPPER to avoid sccache/wrappers interfering with target dir
    # Build kaspad and rothschild (these have default binary targets)
    if ! (cd "${repo_path}" && RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" \
      cargo build --release --locked \
        -p kaspad \
        -p rothschild); then
      log_error "Failed to build kaspad and rothschild from ${repo_path}"
      exit 1
    fi

    # Build igra-service with specific binary filters
    if ! (cd "${repo_path}" && RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" \
      cargo build --release --locked \
        -p igra-service --bin kaspa-threshold-service --bin fake_hyperlane_ism_api); then
      log_error "Failed to build igra-service binaries from ${repo_path}"
      exit 1
    fi

    # Verify critical binaries were built
    for binary in kaspad rothschild kaspa-threshold-service fake_hyperlane_ism_api; do
      if [[ ! -x "${TARGET_DIR}/release/${binary}" ]]; then
        log_error "${binary} not found after build (expected at ${TARGET_DIR}/release/${binary})"
        exit 1
      fi
    done
  fi
```

### Alternative Quick Fix (Option 1)

If you want the quickest fix, just add after line 324:

```bash
    fi
    # Check for rothschild and retry if missing
    if [[ ! -x "${TARGET_DIR}/release/rothschild" ]]; then
      log_warn "rothschild binary not found after workspace build, retrying targeted rothschild build..."
      if ! (cd "${repo_path}" && RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" \
        cargo build --release --locked -p rothschild); then
        log_error "Targeted rothschild build failed; see build output above."
        exit 1
      fi
      if [[ ! -x "${TARGET_DIR}/release/rothschild" ]]; then
        log_error "rothschild still missing after targeted build (expected at ${TARGET_DIR}/release/rothschild)"
        exit 1
      fi
    fi
  fi
```

---

## 🎯 **Summary**

| Issue | Status | Solution |
|-------|--------|----------|
| **rothschild missing** | 🔴 Critical | Add retry OR fix build command |
| **kaspad needs retry** | 🟡 Works but inefficient | Fix build command (remove retry) |
| **Config from GitHub** | ✅ Fixed | Already implemented |

**Next Action**: Implement Option 2 (recommended) or Option 1 (quick fix) to resolve the missing rothschild binary issue.

**Also remember**: Disable debug mode after fixing! Change line 2 back to `set -euo pipefail`.
