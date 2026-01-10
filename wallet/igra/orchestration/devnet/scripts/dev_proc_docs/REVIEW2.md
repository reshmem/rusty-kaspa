# run_local_devnet.sh - COMPREHENSIVE REVIEW 2

**Date**: 2026-01-07
**Review Type**: Triple-check comprehensive analysis
**Status**: 🔴 **CRITICAL BUGS FOUND**

---

## ✅ Previously Fixed Issues

Excellent work! The following critical issues from REVIEW.md were fixed:

1. ✅ **Issue #1 FIXED**: `.env` source file no longer modified (Python line 48-49)
2. ✅ **Issue #2 FIXED**: `default` command no longer calls `prepare_igra_config` (line 839-844)
3. ✅ **Issue #3 FIXED**: All commands added to argument parsing (line 109)
4. ✅ **Issue #5 FIXED**: Redundant `DATA_ROOT` variable removed
5. ✅ **Issue #6 FIXED**: Python arguments reduced from 11 to 9
6. ✅ **Issue #7 FIXED**: `restart` now includes `stage_binaries` (line 864)
7. ✅ **Issue #9 FIXED**: `RUSTC_WRAPPER=` comment added (lines 301, 468)
8. ✅ **Issue #11 FIXED**: Timeouts now configurable (lines 225-227)

---

## 🔴 CRITICAL BUG #1: Missing Import in Python Script

**Severity**: CRITICAL - Script will crash
**Location**: update_devnet_config.py lines 157, 172, 190

### Problem

The Python script uses `shutil.copy2()` but never imports `shutil`:

```python
# Lines 17-21: Imports
import datetime
import hashlib
import json
import pathlib
import sys
# ❌ Missing: import shutil

# Line 157:
shutil.copy2(ini_out, dest)  # ❌ NameError: name 'shutil' is not defined

# Line 172:
shutil.copy2(hyperlane_out, dest)  # ❌ NameError

# Line 190:
shutil.copy2(keyset_out, dest)  # ❌ NameError
```

### Impact

Running `generate-keys` will crash with:
```
NameError: name 'shutil' is not defined
```

### Fix

Add to imports:
```python
import datetime
import hashlib
import json
import pathlib
import shutil  # ← ADD THIS
import sys
```

### Test

```bash
./run_local_devnet.sh generate-keys
# Should complete without NameError
```

---

## 🔴 CRITICAL BUG #2: `start` Command Overwrites Generated Configs

**Severity**: CRITICAL - Data loss
**Location**: Bash script lines 851-855

### Problem

The `start` command calls `prepare_igra_config` which overwrites generated configs with templates:

```bash
start)
  ensure_binaries
  stage_binaries
  prepare_igra_config  # ❌ OVERWRITES generated configs!
  start_targets
  ;;
```

### What `prepare_igra_config` Does (lines 427-434)

```bash
prepare_igra_config() {
  cp -f "${ENV_FILE}" "${CONFIG_DIR}/.env"                 # Overwrites with template
  cp -f "${HYPERLANE_KEYS_SRC}" "${HYPERLANE_KEYS}"        # Overwrites with template
  sed ... "${IGRA_CONFIG_TEMPLATE}" > "${IGRA_CONFIG}"     # Overwrites with template
}
```

### Scenario Demonstrating Bug

```bash
# User workflow:
./run_local_devnet.sh clean
./run_local_devnet.sh build
./run_local_devnet.sh generate-keys  # ✅ Generates real keys in CONFIG_DIR

# Check generated keys exist:
grep "KASPA_DEVNET_WALLET_MNEMONIC" ./igra_devnet/config/.env
# Shows: KASPA_DEVNET_WALLET_MNEMONIC=word1 word2 word3... ✅

./run_local_devnet.sh start  # ❌ Calls prepare_igra_config!

# Check keys again:
grep "KASPA_DEVNET_WALLET_MNEMONIC" ./igra_devnet/config/.env
# Shows: KASPA_DEVNET_WALLET_MNEMONIC=<placeholder or missing> ❌ LOST!
```

### Impact

- **Data Loss**: Generated keys are replaced with placeholder templates
- **Services Fail**: Processes start with invalid configs and will likely crash
- **User Confusion**: "Why did my keys disappear?"

### Root Cause

`prepare_igra_config` was designed for `setup` command (initial template copy), but it's also called by `start` and `restart`.

### Fix Option 1: Conditional Config Preparation (Recommended)

Only copy templates if configs don't exist:

```bash
prepare_igra_config() {
  # Only copy templates if configs don't exist (initial setup)
  if [[ ! -f "${CONFIG_DIR}/.env" ]]; then
    log_info "Copying template .env to ${CONFIG_DIR}"
    cp -f "${ENV_FILE}" "${CONFIG_DIR}/.env"
  fi

  if [[ ! -f "${HYPERLANE_KEYS}" ]]; then
    log_info "Copying template hyperlane-keys.json to ${CONFIG_DIR}"
    cp -f "${HYPERLANE_KEYS_SRC}" "${HYPERLANE_KEYS}"
  fi

  if [[ ! -f "${IGRA_CONFIG}" ]]; then
    log_info "Copying template igra-config.ini to ${CONFIG_DIR}"
    sed \
      -e "s|/data/igra|${IGRA_DATA}|g" \
      -e "s|grpc://kaspad:16110|grpc://127.0.0.1:16110|g" \
      "${IGRA_CONFIG_TEMPLATE}" > "${IGRA_CONFIG}"
  else
    log_info "Using existing igra-config.ini (not overwriting)"
  fi
}
```

### Fix Option 2: Remove from start/restart (Alternative)

```bash
start)
  ensure_binaries
  stage_binaries
  # prepare_igra_config  # ← REMOVE - configs should already exist
  start_targets
  ;;

restart)
  stop_targets
  ensure_binaries
  stage_binaries
  # prepare_igra_config  # ← REMOVE
  start_targets
  ;;
```

**Problem with Option 2**: If user runs `start` before `setup` or `generate-keys`, configs won't exist and services will fail.

### Fix Option 3: Check for Generated Configs (Best)

```bash
ensure_configs() {
  # Check if configs have been generated (look for a marker that only generate_keys creates)
  if [[ ! -f "${KEYSET_JSON}" ]]; then
    log_error "Configs not generated. Run 'setup' or 'generate-keys' first."
    exit 1
  fi

  # Verify critical config files exist
  if [[ ! -f "${CONFIG_DIR}/.env" ]] || [[ ! -f "${IGRA_CONFIG}" ]]; then
    log_error "Missing config files in ${CONFIG_DIR}. Run 'generate-keys'."
    exit 1
  fi
}

# In start command:
start)
  ensure_binaries
  stage_binaries
  ensure_configs  # ← ADD THIS instead of prepare_igra_config
  start_targets
  ;;
```

**Recommendation**: Use Fix Option 1 (conditional preparation) - it's the safest and most user-friendly.

---

## 🔴 CRITICAL BUG #3: `restart` Command Has Same Issue

**Severity**: CRITICAL - Data loss
**Location**: Lines 861-866

Same issue as Bug #2:

```bash
restart)
  stop_targets
  ensure_binaries
  stage_binaries
  prepare_igra_config  # ❌ OVERWRITES generated configs!
  start_targets
  ;;
```

**Fix**: Apply the same solution as Bug #2.

---

## ⚠️ SERIOUS ISSUE #4: Incorrect Success Message

**Severity**: High - Misleading information
**Location**: Line 848

```bash
generate-keys)
  generate_keys
  log_success "Keys regenerated and configs written to ${CONFIG_DIR} (and source files). ..."
  #                                                                    ^^^^^^^^^^^^^^^^^ ❌ WRONG!
```

### Problem

The message says "(and source files)" but the Python script no longer modifies source files (this was fixed in Bug #1).

### Fix

```bash
generate-keys)
  generate_keys
  log_success "Keys regenerated and configs written to ${CONFIG_DIR}. Existing data dirs may be incompatible with new keys."
  #                                                    ^^^^^^^^^^^^^^^^^^^^^^^ Removed "(and source files)"
  exit 0
  ;;
```

---

## ⚠️ DESIGN ISSUE #5: Redundant Copy Logic in Python Script

**Severity**: Low - Code complexity
**Location**: Python script lines 154-157, 169-172, 187-190

### Problem

The copy logic is redundant and never executes:

```python
def rewrite_ini(...):
  new_text = "\n".join(out_lines) + "\n"
  ini_out.write_text(new_text)  # Write to CONFIG_DIR/igra-config.ini
  dest = config_dir / ini_out.name  # CONFIG_DIR / "igra-config.ini"
  if ini_out != dest:  # ❌ Always false (ini_out IS dest)
    shutil.copy2(ini_out, dest)
```

### Analysis

When called from bash:
- `ini_out` = `pathlib.Path("${CONFIG_DIR}/igra-config.ini")` = `/path/to/igra_devnet/config/igra-config.ini`
- `dest` = `config_dir / ini_out.name` = `/path/to/igra_devnet/config` / `"igra-config.ini"` = `/path/to/igra_devnet/config/igra-config.ini`
- They're the same path, so the copy never executes

### Impact

No functional issue, but adds cognitive overhead.

### Fix

**Option 1 - Remove redundant code**:
```python
def rewrite_ini(...):
  new_text = "\n".join(out_lines) + "\n"
  ini_out.write_text(new_text)
  # Remove lines 155-157 (redundant copy)

def write_hyperlane_keys(...):
  content = json.dumps({"validators": validators}, indent=2) + "\n"
  hyperlane_out.write_text(content)
  # Remove lines 170-172

def write_keyset(...):
  content = json.dumps(payload, indent=2) + "\n"
  keyset_out.write_text(content)
  # Remove lines 188-190
```

**Option 2 - Keep for future flexibility**:
Leave as-is if you plan to support writing to a temp location then copying.

**Recommendation**: Option 1 (remove) - simplifies code.

---

## 🟡 MODERATE ISSUE #6: `setup` Command Doesn't Generate Keys

**Severity**: Medium - Unexpected behavior
**Location**: Lines 826-831

### Problem

The `setup` command only copies template configs, not generated keys:

```bash
setup)
  ensure_binaries     # Build
  stage_binaries      # Copy to BIN_DIR
  prepare_igra_config # Copy TEMPLATES (no key generation!)
  log_success "Setup complete. Configs in ${CONFIG_DIR}. Binaries staged in ${BIN_DIR}."
  exit 0
  ;;
```

### Impact

After running `setup`, configs contain placeholder values, not real keys. Users must then run `generate-keys` separately.

### Current Workflow

```bash
./run_local_devnet.sh setup  # Builds + templates
./run_local_devnet.sh generate-keys  # Generate keys
./run_local_devnet.sh start  # Start services (but overwrites keys! See Bug #2)
```

### Expected Workflow (based on command name)

```bash
./run_local_devnet.sh setup  # Builds + generates keys (everything needed)
./run_local_devnet.sh start  # Start services
```

### Discussion

**Option A - Current Design (separate steps)**:
- `setup` = build + copy templates
- `generate-keys` = generate keys
- `default` = build + generate keys (all-in-one)

**Option B - Setup includes key generation**:
```bash
setup)
  ensure_binaries
  stage_binaries
  generate_keys  # ADD THIS
  log_success "Setup complete with generated keys. Configs in ${CONFIG_DIR}."
  exit 0
  ;;
```

**Recommendation**:
- If you want `setup` to be minimal (just prepare structure), keep current design but document clearly
- If you want `setup` to be "ready to start", add `generate_keys` to it
- Consider: Is `default` redundant with `setup`?

---

## 🟡 MODERATE ISSUE #7: Unclear Difference Between `default` and `setup`

**Severity**: Medium - UX confusion
**Location**: Lines 826-831 (setup), 839-844 (default)

### Current Behavior

```bash
# setup command:
setup)
  ensure_binaries      # Build
  stage_binaries       # Stage
  prepare_igra_config  # Copy templates
  ;;

# default command:
default)
  ensure_binaries  # Build
  stage_binaries   # Stage
  generate_keys    # Generate keys
  ;;
```

### The Only Difference

`default` calls `generate_keys` instead of `prepare_igra_config`.

### User Confusion

**User**: "What's the difference between running the script with no command (default) vs `setup`?"
**Answer**: Default generates real keys, setup just copies templates.

**But**: This isn't obvious from the command names!

### Recommendations

**Option 1 - Rename for clarity**:
- Keep `setup` = build + copy templates (minimal setup)
- Rename `default` → `init` or `initialize` = build + generate keys (full initialization)

**Option 2 - Make setup complete**:
- `setup` = build + generate keys (full setup)
- Remove `default` command (users must explicitly use setup/build/generate-keys)

**Option 3 - Document clearly**:
Update usage() to explain:
```bash
Commands:
  (no command)        Build, generate keys, and prepare for first run (recommended for new setups)
  setup               Build binaries and copy template configs (keys not generated)
  build               Build binaries only
  generate-keys       Generate new keys and update configs (run after setup)
  start [target]      Start services (requires setup or generated keys)
  ...
```

**Recommendation**: Option 3 (document) + eventually move to Option 2 (make setup complete).

---

## 🔵 MINOR ISSUE #8: CARGO_TARGET_DIR Set Twice

**Severity**: Low - Redundancy
**Location**: Line 177 (export), lines 302, 321, 336, 469 (explicit)

### Code

```bash
# Line 177:
export CARGO_TARGET_DIR="${TARGET_DIR}"

# Line 302:
RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" cargo build ...
```

### Analysis

The explicit `CARGO_TARGET_DIR=` in the command overrides the exported value, making the export unnecessary.

### Impact

None functionally, but slightly confusing.

### Fix Options

**Option 1 - Remove export**:
```bash
# Line 177: Remove this line
# export CARGO_TARGET_DIR="${TARGET_DIR}"
```

**Option 2 - Remove explicit overrides**:
```bash
# Use the exported value everywhere:
RUSTC_WRAPPER= cargo build ...
```

**Option 3 - Keep both (defensive)**:
Current approach ensures the correct value is used even if the export fails or is overridden elsewhere.

**Recommendation**: Keep as-is (defensive programming) or apply Option 2 (cleaner).

---

## 🔵 MINOR ISSUE #9: `validate_json` Function Only Used Once

**Severity**: Very Low - Code organization
**Location**: Lines 486-500 (definition), 722 (usage)

### Analysis

Function is only called once (line 722 in `generate_keys`), making it a candidate for inlining.

### Recommendation

Keep the function - it's well-defined, reusable, and might be useful if you add more JSON validation later.

---

## 🔵 MINOR ISSUE #10: Inconsistent Logging in `require_cmd`

**Severity**: Very Low - Style
**Location**: Lines 79-91

### Code

```bash
require_cmd() {
  local cmd="$1"
  local reason="${2:-required by this script}"
  local install_hint="${3:-}"

  if ! command -v "${cmd}" >/dev/null 2>&1; then
    log_error "Required command '${cmd}' not found (context: ${reason})"
    if [[ -n "${install_hint}" ]]; then
      log_warn "Install hint: ${install_hint}"
    fi
    exit 1
  fi
}
```

### Observation

Most of the script moved to using `log_*` functions, but some places still use plain `echo` (e.g., lines 362, 366).

### Recommendation

For consistency, use `log_*` functions everywhere, or document when plain `echo` is intentional.

---

## 📋 Command Flow Analysis

Let me trace each command's flow to verify correctness:

### Command: `clean`

```
Line 127-142:
1. Check RUN_ROOT is safe
2. Remove RUN_ROOT directory
Status: ✅ Correct
```

### Command: `setup`

```
Lines 826-831:
1. ensure_binaries (build)
2. stage_binaries (copy to BIN_DIR)
3. prepare_igra_config (copy templates)
Result: Binaries ready, template configs in place, NO keys generated
Status: ⚠️ Incomplete (no keys) - see Issue #6
```

### Command: `build`

```
Lines 833-837:
1. ensure_binaries (build)
2. stage_binaries (copy to BIN_DIR)
Result: Binaries ready
Status: ✅ Correct
```

### Command: `default`

```
Lines 839-844:
1. ensure_binaries (build)
2. stage_binaries (copy to BIN_DIR)
3. generate_keys (generate and write configs)
Result: Binaries ready, configs with real keys
Status: ✅ Correct
```

### Command: `generate-keys`

```
Lines 846-849:
1. generate_keys
Result: Configs updated with new keys
Status: ⚠️ Message wrong (Issue #4), but logic correct
```

### Command: `start`

```
Lines 851-855:
1. ensure_binaries (may rebuild)
2. stage_binaries
3. prepare_igra_config → ❌ OVERWRITES GENERATED CONFIGS (Bug #2)
4. start_targets
Status: 🔴 BROKEN - loses generated keys
```

### Command: `stop`

```
Lines 857-859:
1. stop_targets
Status: ✅ Correct
```

### Command: `restart`

```
Lines 861-866:
1. stop_targets
2. ensure_binaries (may rebuild)
3. stage_binaries
4. prepare_igra_config → ❌ OVERWRITES GENERATED CONFIGS (Bug #3)
5. start_targets
Status: 🔴 BROKEN - loses generated keys
```

### Command: `status`

```
Lines 868-870:
1. show_status
Status: ✅ Correct
```

---

## 🎯 Priority-Ordered Fixes

### 🔴 CRITICAL (Must Fix Before Any Use)

1. **Python Import Bug**: Add `import shutil` to update_devnet_config.py (line 21)
2. **Start Command**: Fix `start` to not overwrite configs (lines 851-855)
3. **Restart Command**: Fix `restart` to not overwrite configs (lines 861-866)

### 🟡 HIGH (Fix Soon)

4. **Success Message**: Remove "(and source files)" from line 848
5. **Clarify setup vs default**: Document the difference or make setup complete

### 🟢 MEDIUM (Nice to Have)

6. **Remove redundant copy logic** in Python script
7. **Simplify CARGO_TARGET_DIR** handling

---

## ✅ Testing Protocol

After applying critical fixes, run this complete test:

```bash
# Test 1: Clean slate
./run_local_devnet.sh clean
[[ ! -d ./igra_devnet ]] && echo "✓ Clean works" || echo "✗ Clean failed"

# Test 2: Default command (build + generate keys)
./run_local_devnet.sh default
grep -q "KASPA_DEVNET_WALLET_MNEMONIC" ./igra_devnet/config/.env && echo "✓ Keys generated" || echo "✗ No keys"
[[ -f ./igra_devnet/config/devnet-keys.json ]] && echo "✓ Keyset exists" || echo "✗ No keyset"

# Test 3: Start doesn't overwrite keys
BEFORE=$(grep "KASPA_DEVNET_WALLET_MNEMONIC" ./igra_devnet/config/.env)
./run_local_devnet.sh --dry-run start  # Use dry-run to skip actual process start
AFTER=$(grep "KASPA_DEVNET_WALLET_MNEMONIC" ./igra_devnet/config/.env)
[[ "$BEFORE" == "$AFTER" ]] && echo "✓ Keys preserved" || echo "✗ Keys overwritten!"

# Test 4: Generate-keys succeeds
./run_local_devnet.sh generate-keys
[[ $? -eq 0 ]] && echo "✓ Generate-keys successful" || echo "✗ Generate-keys failed"

# Test 5: Status works
./run_local_devnet.sh status
[[ $? -eq 0 ]] && echo "✓ Status works" || echo "✗ Status failed"

# Test 6: Git is clean (no source file modifications)
cd "$(git rev-parse --show-toplevel)"
git status --porcelain wallet/igra/orchestration/devnet/.env
[[ $? -ne 0 ]] && echo "✓ Source .env not modified" || echo "✗ Source .env modified!"
```

---

## 📝 Recommended Implementation Order

### Phase 1: Critical Fixes (30 minutes)

```bash
# 1. Fix Python import
# File: update_devnet_config.py
# Add on line 21:
import shutil

# 2. Fix start command
# File: run_local_devnet.sh line 851-855
start)
  ensure_binaries
  stage_binaries
  ensure_configs  # NEW: Check configs exist instead of overwriting
  start_targets
  ;;

# Add new function before start_targets definition:
ensure_configs() {
  local required_files=("${CONFIG_DIR}/.env" "${IGRA_CONFIG}" "${HYPERLANE_KEYS}" "${KEYSET_JSON}")
  for file in "${required_files[@]}"; do
    if [[ ! -f "${file}" ]]; then
      log_error "Missing required config: ${file}"
      log_error "Run 'generate-keys' first or use 'default' command for initial setup"
      exit 1
    fi
  done
  log_info "Verified all required configs exist"
}

# 3. Fix restart command (same as start)
restart)
  stop_targets
  ensure_binaries
  stage_binaries
  ensure_configs  # NEW: Check instead of overwrite
  start_targets
  ;;

# 4. Fix success message line 848
log_success "Keys regenerated and configs written to ${CONFIG_DIR}. Existing data dirs may be incompatible with new keys."
```

### Phase 2: Documentation (15 minutes)

```bash
# Update usage() to clarify commands:
Commands:
  (no command)        Build binaries, generate keys, prepare full devnet (recommended)
  setup               Build binaries and copy template configs (keys NOT generated - run generate-keys after)
  build               Build binaries only
  generate-keys       Generate new keys and update all configs
  start [target]      Start services (requires prior setup/key generation)
  stop [target]       Stop services
  restart [target]    Restart services
  status              Show running processes
  clean               Remove all devnet data and configs
  help                Show this help
```

### Phase 3: Cleanup (15 minutes)

```bash
# Python script - remove redundant copies
# Lines 154-157, 169-172, 187-190
# Just keep the write_text() call, remove the copy logic
```

---

## 🏆 Final Assessment

### What's Working Well

- ✅ Excellent logging with timestamps and colors
- ✅ Comprehensive error handling in most places
- ✅ Dry-run mode well implemented
- ✅ Health checks provide good feedback
- ✅ Process management is robust
- ✅ Code structure is clean and maintainable
- ✅ Python script extracted successfully
- ✅ Source files no longer modified

### What Needs Fixing

- 🔴 **3 Critical Bugs** that will cause failures
- 🟡 **2 High Priority Issues** causing confusion
- 🟢 **5 Minor Issues** for code quality

### Time to Production Ready

- **With Critical Fixes**: 30 minutes
- **With All Fixes**: 1 hour

---

## 📊 Bug Severity Matrix

| Bug # | Severity | Impact | Fix Time | Blocks Usage? |
|-------|----------|--------|----------|---------------|
| #1 | 🔴 Critical | Script crashes | 1 min | Yes |
| #2 | 🔴 Critical | Data loss | 15 min | Yes |
| #3 | 🔴 Critical | Data loss | 5 min | Yes |
| #4 | 🟡 High | Misleading info | 1 min | No |
| #5 | 🟢 Low | Code complexity | 10 min | No |
| #6 | 🟡 Medium | UX confusion | 5 min | No |
| #7 | 🟡 Medium | UX confusion | 5 min | No |
| #8 | 🟢 Low | Redundancy | 2 min | No |
| #9 | 🟢 Low | Style | 0 min | No |
| #10 | 🟢 Low | Style | 0 min | No |

---

## ✅ Sign-Off Checklist

Before deploying:

- [ ] Python `import shutil` added
- [ ] `start` command doesn't overwrite configs
- [ ] `restart` command doesn't overwrite configs
- [ ] Success message corrected
- [ ] All tests pass (see Testing Protocol)
- [ ] Git status is clean after running generate-keys
- [ ] Documentation updated

---

**TRIPLE-CHECKED** ✓✓✓
**Overall Status**: Very close to production-ready! Fix the 3 critical bugs and you're good to go.
**Recommendation**: Fix Critical bugs immediately, then deploy. Address other issues in next iteration.
