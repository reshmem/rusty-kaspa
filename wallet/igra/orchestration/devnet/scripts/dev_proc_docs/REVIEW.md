# run_local_devnet.sh - Implementation Review

**Date**: 2026-01-07
**Reviewer**: Claude Code
**Status**: Implementation reviewed, issues identified

---

## ✅ Successfully Implemented

Great job implementing most of the suggestions! The following improvements were well-executed:

1. ✅ **Logging with timestamps and colors** (lines 4-30)
2. ✅ **Enhanced error messages with context** (`require_cmd` on line 243-254)
3. ✅ **Fixed `.env` parsing** with quote stripping (lines 168-183)
4. ✅ **Process termination with timeout and force-kill** (lines 514-556)
5. ✅ **Build error handling** with exit code checks (lines 297-304, 331-335)
6. ✅ **Keygen validation** with JSON checking (lines 455-478, 480-494)
7. ✅ **Python3 early validation** with version check (lines 191-199)
8. ✅ **Clone URL warning** for non-GitHub sources (lines 268-276)
9. ✅ **Dry-run mode** throughout (lines 75, 81-84, and various functions)
10. ✅ **Status command** with process monitoring (lines 786-815)
11. ✅ **Health checks** for kaspad and igra services (lines 622-682)
12. ✅ **`--locked` flag** consistently applied (lines 298, 317, 332)
13. ✅ **Improved `copy_if_changed`** that actually checks changes (lines 436-443)
14. ✅ **Log directory permissions** restricted to 700 (line 420)
15. ✅ **Security notes** in usage (lines 68-70)
16. ✅ **Python script extracted** to separate file (update_devnet_config.py)

---

## 🐛 Critical Issues Found

### Issue #1: `.env` Source File Is Modified 🔴

**Location**: Python script line 51, bash line 721-723

**Problem**: The `generate_keys` command modifies the source `.env` file in the repository (`${DEVNET_DIR}/.env`), which contaminates the git working directory.

**Current behavior**:
```python
# update_devnet_config.py line 51
env_path.write_text("\n".join(lines) + "\n")  # Modifies DEVNET_DIR/.env!
```

**Impact**:
- Running `generate-keys` dirties the git working directory
- Generated secrets appear in `git status`
- Risk of accidentally committing secrets

**Fix Option 1 - Don't modify source**:
```python
# Only write to config_dir, not to env_path
# env_path.write_text(...)  # REMOVE THIS LINE
shutil.copy2(env_path, config_dir / ".env")  # Copy template first
output_env = config_dir / ".env"
output_env.write_text("\n".join(lines) + "\n")  # Update the copy
```

**Fix Option 2 - Document the behavior**:
Add to usage():
```bash
⚠️  Note: generate-keys updates ${DEVNET_DIR}/.env with generated credentials.
   This modifies files in your repo. Use 'git checkout ${DEVNET_DIR}/.env' to revert.
```

**Recommendation**: Implement Fix Option 1 to avoid polluting the repo.

---

### Issue #2: `default` Command Overwrites Generated Configs 🔴

**Location**: Lines 833-839

**Problem**: The `default` command sequence is incorrect:

```bash
default)
  ensure_binaries
  stage_binaries
  generate_keys      # Generates new configs
  prepare_igra_config # OVERWRITES the configs just generated!
```

**What happens**:
1. `generate_keys` calls Python script which writes:
   - `${CONFIG_DIR}/.env` (with generated credentials)
   - `${CONFIG_DIR}/igra-config.ini` (with generated keys/addresses)
   - `${CONFIG_DIR}/hyperlane-keys.json` (with generated validator keys)

2. `prepare_igra_config` then does:
   ```bash
   cp -f "${ENV_FILE}" "${CONFIG_DIR}/.env"  # Overwrites with template!
   cp -f "${HYPERLANE_KEYS_SRC}" "${HYPERLANE_KEYS}"  # Overwrites with template!
   sed ... "${IGRA_CONFIG_TEMPLATE}" > "${IGRA_CONFIG}"  # Overwrites with template!
   ```

3. Result: All generated keys are lost, replaced with template placeholders

**Fix**:
```bash
default)
  ensure_binaries
  stage_binaries
  generate_keys
  # prepare_igra_config  # REMOVE THIS - configs already generated
  log_success "Default completed: built, regenerated keys, staged binaries."
  exit 0
  ;;
```

**Verification Test**:
```bash
./run_local_devnet.sh clean
./run_local_devnet.sh default
# Check if generated keys are preserved:
grep "KASPA_DEVNET_WALLET_MNEMONIC" ./igra_devnet/config/.env
# Should show a real mnemonic, not placeholder
```

---

### Issue #3: Missing Commands in Argument Parsing

**Location**: Line 95

**Problem**: The break statement doesn't include all valid commands:

```bash
help|setup|build|start|stop|restart|clean) break ;;
```

**Missing**: `status` and `generate-keys`

**Impact**:
- If user runs `./run_local_devnet.sh status`, it works (validated on line 105)
- But the argument parsing logic is inconsistent

**Fix**:
```bash
help|setup|build|start|stop|restart|status|clean|generate-keys) break ;;
```

---

## ⚠️ Design Complexity Issues

### Issue #4: Unnecessary Binary Staging (BIN_DIR)

**Current Flow**:
```
Build → TARGET_DIR/release/{binary}
  ↓
resolve_bin → finds in TARGET_DIR or BIN_DIR
  ↓
stage_binaries → copies to BIN_DIR
  ↓
Processes use binaries from wherever resolve_bin found them
```

**Problem**: The staging adds complexity without clear benefit:
1. Binaries are built to `TARGET_DIR/release/`
2. They're resolved (checked if they exist)
3. They're copied to `BIN_DIR`
4. But processes can use them from either location

**Questions**:
- Why copy binaries to BIN_DIR if processes can use them from TARGET_DIR?
- On subsequent runs, binaries in BIN_DIR take precedence, potentially using stale versions

**Simplification Option 1 - Remove BIN_DIR entirely**:
```bash
# Remove stage_binaries() function
# Update ensure_binaries() to just resolve without staging:
KASPAD_BIN="$(resolve_bin kaspad "" KASPAD_BIN "${DEFAULT_KASPAD_BIN:-}")"
# Remove first parameter (BIN_DIR path) since we don't use it
```

**Simplification Option 2 - Always stage**:
Keep BIN_DIR but make it the single source of truth:
- Always copy binaries to BIN_DIR after build
- Always use binaries from BIN_DIR (don't check TARGET_DIR)
- Simpler logic: build → stage → use

**Current approach might be intentional if**:
- You want users to provide custom binaries that get "installed" to BIN_DIR
- You want a stable location that doesn't change between clone/local modes

**Recommendation**: Document the rationale for BIN_DIR, or simplify by removing it.

---

### Issue #5: Redundant DATA_ROOT Variable

**Location**: Line 134

```bash
DATA_ROOT="${RUN_ROOT}"
```

**Problem**: `DATA_ROOT` is set equal to `RUN_ROOT` and never differs. This adds cognitive overhead.

**Usage**:
- `LOG_DIR="${DATA_ROOT}/logs"` (line 135)
- `PIDS_DIR="${DATA_ROOT}/pids"` (line 136)
- etc.

**Simplification**:
```bash
# Remove line 134
# Replace all ${DATA_ROOT} with ${RUN_ROOT}:
LOG_DIR="${RUN_ROOT}/logs"
PIDS_DIR="${RUN_ROOT}/pids"
# ... etc
```

**Impact**: Reduces variables, clearer code

---

### Issue #6: Unused Python Arguments

**Location**: Python script invocation, line 721-723

**Problem**: Two arguments are passed but never used:
- `argv[2]` - `hyperlane_template` (HYPERLANE_KEYS_SRC)
- `argv[9]` - `keyset_template` (KEYSET_JSON_TEMPLATE)

**Python script only uses**:
- `argv[0]` - env_path
- `argv[1]` - ini_template
- `argv[3]` - config_dir
- `argv[4]` - ini_out
- `argv[5]` - hyperlane_out
- `argv[6]` - keygen_path
- `argv[7]` - igra_data
- `argv[8]` - run_root
- `argv[10]` - keyset_out

**Simplification**:
Remove unused arguments from both bash and Python:

**Bash (line 721-723)**:
```bash
python3 "${SCRIPT_DIR}/update_devnet_config.py" \
  "$ENV_FILE" "$IGRA_CONFIG_TEMPLATE" "$CONFIG_DIR" "$IGRA_CONFIG" "$HYPERLANE_KEYS" \
  "$keygen_tmp" "$IGRA_DATA" "$RUN_ROOT" "$KEYSET_JSON"
```

**Python (adjust argv indices)**:
```python
if len(argv) != 9:  # Was 11
    print(__doc__, file=sys.stderr)
    return 1

env_path = pathlib.Path(argv[0])
ini_template = pathlib.Path(argv[1])
config_dir = pathlib.Path(argv[2])  # Was argv[3]
ini_out = pathlib.Path(argv[3])     # Was argv[4]
hyperlane_out = pathlib.Path(argv[4])  # Was argv[5]
keygen_path = pathlib.Path(argv[5])    # Was argv[6]
igra_data = pathlib.Path(argv[6])      # Was argv[7]
run_root = pathlib.Path(argv[7])       # Was argv[8]
keyset_out = pathlib.Path(argv[8])     # Was argv[10]
```

---

## 🔍 Minor Issues

### Issue #7: `restart` Command Missing `stage_binaries`

**Location**: Lines 856-861

```bash
restart)
  stop_targets
  ensure_binaries    # May rebuild
  prepare_igra_config
  start_targets
  ;;
```

**Problem**: If `ensure_binaries` rebuilds binaries, they won't be staged to BIN_DIR.

**Impact**: Low if binaries are used from TARGET_DIR anyway (see Issue #4)

**Fix** (if keeping BIN_DIR):
```bash
restart)
  stop_targets
  ensure_binaries
  stage_binaries  # ADD THIS
  prepare_igra_config
  start_targets
  ;;
```

---

### Issue #8: Inconsistent Process Names in `show_status`

**Location**: Line 788

```bash
local processes=(kaspad kaspaminer igra-signer-1 igra-signer-2 igra-signer-3 fake-hyperlane-signer-1 fake-hyperlane-signer-2 fake-hyperlane-signer-3)
```

**Problem**: The actual PID files are named differently:
- Actual: `igra-signer-1.pid` (from `start_igra` which calls `start_process "igra-${profile}"`)
- Checked: `igra-signer-1.pid` ✓ CORRECT
- Actual: `fake-hyperlane-signer-1.pid` (from `start_process "fake-hyperlane-${profile}"`)
- Checked: `fake-hyperlane-signer-1.pid` ✓ CORRECT

Actually, looking more carefully at the process names, they seem correct. Let me verify by checking `start_igra`:

```bash
start_igra() {
  local profile="$1"  # e.g., "signer-1"
  ...
  start_process "igra-${profile}" ...        # Creates igra-signer-1.pid
  start_process "fake-hyperlane-${profile}" ... # Creates fake-hyperlane-signer-1.pid
}
```

So the names are correct. **False alarm - no issue here.**

---

### Issue #9: `RUSTC_WRAPPER=` Override in Build Commands

**Location**: Lines 297, 316, 331, 463

```bash
RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" cargo build ...
```

**Question**: Why is `RUSTC_WRAPPER` being cleared?

**Possible reasons**:
- Avoid sccache or similar caching tools that might interfere
- Ensure clean builds without external wrappers
- Workaround for specific build environment issue

**Impact**: None if intentional, but worth documenting

**Recommendation**: Add comment explaining why:
```bash
# Clear RUSTC_WRAPPER to avoid sccache/build wrapper interference
if ! (cd "${repo_path}" && RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" \
```

---

### Issue #10: `validate_json` Function Is Defined But Only Used Once

**Location**: Lines 480-494 (definition), line 716 (usage)

**Current**:
```bash
validate_json() {
  local json_str="$1"
  local description="${2:-JSON data}"
  if [[ -z "${json_str}" ]]; then
    log_error "${description} is empty"
    return 1
  fi
  if ! echo "${json_str}" | python3 -m json.tool >/dev/null 2>&1; then
    log_error "${description} is not valid JSON"
    log_error "Content: ${json_str}"
    return 1
  fi
  log_success "${description} validated"
  return 0
}
```

**Usage**: Only called once in `generate_keys` (line 716)

**Simplification**: Inline the validation or keep the function for potential future use.

**Recommendation**: Keep it - it's clean and might be useful later.

---

### Issue #11: Hardcoded Wait Timeouts

**Location**:
- Line 627: kaspad timeout = 30 seconds
- Line 663: igra timeout = 20 seconds
- Line 537: stop process timeout = 10 seconds

**Suggestion**: Make these configurable via environment variables:

```bash
# At top of script with other config
KASPAD_STARTUP_TIMEOUT="${KASPAD_STARTUP_TIMEOUT:-30}"
IGRA_STARTUP_TIMEOUT="${IGRA_STARTUP_TIMEOUT:-20}"
PROCESS_STOP_TIMEOUT="${PROCESS_STOP_TIMEOUT:-10}"

# Then use:
local max_wait=${KASPAD_STARTUP_TIMEOUT}
```

**Priority**: Low - current values are reasonable

---

## 📊 Path Consistency Review

Let me trace all paths to ensure consistency:

### Source Paths (in repo, read-only):
- ✅ `SCRIPT_DIR` = this script's directory
- ✅ `DEVNET_DIR` = `${SCRIPT_DIR}/..`
- ✅ `REPO_ROOT` = `${DEVNET_DIR}/../../../..`
- ✅ `ENV_FILE` = `${DEVNET_DIR}/.env`
- ✅ `IGRA_CONFIG_TEMPLATE` = `${DEVNET_DIR}/igra-devnet.ini`
- ✅ `HYPERLANE_KEYS_SRC` = `${DEVNET_DIR}/hyperlane-keys.json`
- ✅ `KEYSET_JSON_TEMPLATE` = `${DEVNET_DIR}/devnet-keys.json`

### Runtime Paths (in RUN_ROOT, written):
- ✅ `RUN_ROOT` = user-specified or `$(pwd)/igra_devnet`
- ⚠️ `DATA_ROOT` = `${RUN_ROOT}` (redundant, see Issue #5)
- ✅ `LOG_DIR` = `${DATA_ROOT}/logs` → should be `${RUN_ROOT}/logs`
- ✅ `PIDS_DIR` = `${DATA_ROOT}/pids`
- ✅ `KASPAD_DATA` = `${DATA_ROOT}/kaspad`
- ✅ `KASPAD_APPDIR` = `${RUN_ROOT}/.rusty-kaspa`
- ✅ `IGRA_DATA` = `${DATA_ROOT}/igra`
- ✅ `WALLET_DATA` = `${DATA_ROOT}/wallet`
- ✅ `CONFIG_DIR` = `${DATA_ROOT}/config`
- ⚠️ `BIN_DIR` = `${DATA_ROOT}/bin` (see Issue #4 about necessity)

### Build Paths:
- ✅ `SRC_ROOT` = `${RUN_ROOT}/sources` (clone mode)
- ✅ `RUSTY_SRC` = `${SRC_ROOT}/rusty-kaspa`
- ✅ `MINER_SRC` = `${SRC_ROOT}/kaspa-miner`
- ✅ `TARGET_DIR` = user-specified, or `${REPO_ROOT}/target` (local), or `${RUN_ROOT}/target` (clone)

### Config Files (generated):
- ✅ `IGRA_CONFIG` = `${CONFIG_DIR}/igra-config.ini`
- ✅ `HYPERLANE_KEYS` = `${CONFIG_DIR}/hyperlane-keys.json`
- ✅ `KEYSET_JSON` = `${CONFIG_DIR}/devnet-keys.json`

**Overall**: Paths are consistent except for `DATA_ROOT` redundancy.

---

## 🎯 Priority Summary

### 🔴 Must Fix (Breaks Functionality)
1. **Issue #2**: `default` command overwrites generated configs
2. **Issue #1**: `.env` source file modification (git pollution)

### 🟡 Should Fix (Complexity/Consistency)
3. **Issue #4**: Clarify or simplify binary staging (BIN_DIR)
4. **Issue #5**: Remove redundant `DATA_ROOT` variable
5. **Issue #6**: Remove unused Python arguments
6. **Issue #3**: Add missing commands to argument parsing

### 🟢 Nice to Have (Polish)
7. **Issue #7**: Add `stage_binaries` to `restart` command
8. **Issue #9**: Document `RUSTC_WRAPPER=` rationale
9. **Issue #11**: Make timeouts configurable

---

## 🚀 Recommended Action Plan

### Phase 1: Critical Fixes (30 minutes)
1. Fix `default` command (remove `prepare_igra_config` call)
2. Fix Python script to not modify source `.env`
3. Add missing commands to line 95

**Test**:
```bash
./run_local_devnet.sh clean
./run_local_devnet.sh default
git status  # Should show no changes in DEVNET_DIR
grep MNEMONIC ./igra_devnet/config/.env  # Should show generated mnemonic
```

### Phase 2: Simplification (1 hour)
4. Remove `DATA_ROOT`, use `RUN_ROOT` everywhere
5. Remove unused Python arguments
6. Decide on BIN_DIR: keep with documentation or remove

### Phase 3: Polish (30 minutes)
7. Add `stage_binaries` to `restart` if keeping BIN_DIR
8. Add comments for `RUSTC_WRAPPER=`
9. Make timeouts configurable

---

## ✅ What's Working Well

**Excellent improvements**:
- Logging is clear and informative
- Error handling is comprehensive
- Dry-run mode is well-integrated
- Health checks provide good feedback
- Process management is robust
- Code is well-structured and readable

**The script is very close to production-ready!** Just needs the critical fixes above.

---

## 📝 Testing Checklist

After applying fixes, test these scenarios:

```bash
# Test 1: Fresh setup with default
./run_local_devnet.sh clean
./run_local_devnet.sh default
./run_local_devnet.sh status
git status  # Should be clean

# Test 2: Start/stop cycle
./run_local_devnet.sh start all
./run_local_devnet.sh status
./run_local_devnet.sh stop all
./run_local_devnet.sh status

# Test 3: Restart
./run_local_devnet.sh start kaspad
./run_local_devnet.sh restart kaspad
./run_local_devnet.sh status

# Test 4: Dry run
./run_local_devnet.sh --dry-run start all

# Test 5: Generate keys doesn't break configs
./run_local_devnet.sh clean
./run_local_devnet.sh setup
./run_local_devnet.sh generate-keys
cat ./igra_devnet/config/igra-config.ini | grep "generated 20"  # Should see timestamps

# Test 6: Binary staging
./run_local_devnet.sh clean
./run_local_devnet.sh build
ls -la ./igra_devnet/bin/  # Should have all binaries
```

---

**Review Complete** ✓
**Overall Assessment**: Strong implementation with 2 critical bugs that need fixing. Once fixed, the script will be production-ready.
