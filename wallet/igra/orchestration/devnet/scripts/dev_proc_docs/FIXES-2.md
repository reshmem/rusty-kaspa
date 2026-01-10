# FIXES-2.md - Additional Issues & Solutions

**Date**: 2026-01-07
**Status**: 🔴 Two issues identified

## 📋 **Quick Summary**

| Issue | Status | Solution | Priority |
|-------|--------|----------|----------|
| **#1: Missing kaspad/rothschild binaries** | 🔍 Investigating | Need debug log | 🔴 Critical |
| **#2: Config templates from local repo** | ✅ Decided | Implement Option 1 | 🟡 High |

**Next Steps**:
1. Run build with debug enabled, share log
2. Implement Option 1 for config source (code provided below)
3. Test fixes
4. Disable debug mode

---

## 🐛 **Issue #1: Missing Binaries After Build**

### Error Message
```
Missing kaspad; build it or set KASPAD_BIN. Tried: /tmp/igra_devnet/bin/kaspad , /tmp/igra_devnet/target/release/kaspad
```

### Status
🔍 **INVESTIGATING** - Debug mode enabled, awaiting full build log

### Debug Steps Completed
1. ✅ Enabled bash debug mode (`set -euxo pipefail`)
2. ⏳ Waiting for full build log with `-x` trace

### What We Know So Far
- Build creates `/tmp/igra_devnet/target/release/` directory
- Found these binaries in target:
  - ✅ `devnet-keygen`
  - ✅ `fake_hyperlane_ism_api`
  - ✅ `kaspa-miner`
  - ✅ `kaspa-threshold-service`
  - ❌ `kaspad` (MISSING)
  - ❌ `rothschild` (likely MISSING)

### Hypothesis
The build command may be incomplete or failing silently for some packages. The `-x` trace will show:
- Exact `cargo build` command executed
- Which packages are included in the build
- Any errors during kaspad/rothschild build

### Next Steps
1. Run with debug enabled:
   ```bash
   ./run_local_devnet.sh clean 2>&1 | tee /tmp/clean.log
   ./run_local_devnet.sh build 2>&1 | tee /tmp/build.log
   ```
2. Share `/tmp/build.log` for analysis
3. Look for:
   - `cargo build` command line
   - Build errors for kaspad/rothschild
   - Where cargo is writing outputs

---

## 🐛 **Issue #2: Config Templates Always Use Local Repo**

### Problem Description

When using `--build clone` (default mode), the script:
- ✅ **Code**: Clones from GitHub and builds
- ❌ **Configs**: Uses templates from LOCAL repo (where script is)

**User Expectation**:
> "I expect when I use 'default' it will build from github source, and not from my local repo. It should copy configs and everything from repo we cloned from github."

### Current Behavior

```bash
# Config template sources (Lines 171-177)
DEVNET_DIR="${SCRIPT_DIR}/.."  # /your/local/rusty-kaspa/wallet/igra/orchestration/devnet

ENV_FILE="${DEVNET_DIR}/.env"                       # Always LOCAL
IGRA_CONFIG_TEMPLATE="${DEVNET_DIR}/igra-devnet.ini"  # Always LOCAL
HYPERLANE_KEYS_SRC="${DEVNET_DIR}/hyperlane-keys.json"  # Always LOCAL
KEYSET_JSON_TEMPLATE="${DEVNET_DIR}/devnet-keys.json"  # Always LOCAL
```

**Even in clone mode**, configs come from your local checkout, NOT from:
```bash
# NEVER used currently:
${RUSTY_SRC}/wallet/igra/orchestration/devnet/.env
${RUSTY_SRC}/wallet/igra/orchestration/devnet/igra-devnet.ini
```

### Why This Happens

Config paths are set **before cloning** (line 171), so they can't reference the cloned repo yet.

---

## 🔧 **Solution for Issue #2: Config Source**

### Option 1: Use Cloned Configs (Recommended for Pure GitHub Build)

**What it does**: In clone mode, use configs from cloned GitHub repo.

**Implementation**:

```bash
# Around line 32-34, keep these:
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEVNET_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${DEVNET_DIR}/../../../.." && pwd)"

# Around line 171-177, REPLACE with:
# Config paths will be set after we know BUILD_MODE and have cloned/located sources
# These are just placeholders that will be overridden
ENV_FILE=""
IGRA_CONFIG_TEMPLATE=""
HYPERLANE_KEYS_SRC=""
KEYSET_JSON_TEMPLATE=""

# Then in ensure_binaries function (around line 424), ADD after prepare_sources:
ensure_binaries() {
  prepare_sources  # This sets BUILD_MODE and clones if needed

  # NOW determine config source based on actual build mode
  if [[ "${BUILD_MODE}" == "clone" ]]; then
    # Use configs from cloned GitHub repo
    local config_source="${RUSTY_SRC}/wallet/igra/orchestration/devnet"

    # Verify configs exist in cloned repo
    if [[ ! -f "${config_source}/.env" ]]; then
      log_error "Cloned repo missing config templates at ${config_source}"
      log_error "Falling back to local repo configs"
      config_source="${DEVNET_DIR}"
    fi
  else
    # Use configs from local repo
    config_source="${DEVNET_DIR}"
  fi

  # Set all config paths
  ENV_FILE="${config_source}/.env"
  IGRA_CONFIG_TEMPLATE="${config_source}/igra-devnet.ini"
  HYPERLANE_KEYS_SRC="${config_source}/hyperlane-keys.json"
  KEYSET_JSON_TEMPLATE="${config_source}/devnet-keys.json"

  log_info "Using config templates from: ${config_source}"

  # Verify ENV_FILE exists (critical for later checks)
  if [[ ! -f "${ENV_FILE}" ]]; then
    log_error "Missing ${ENV_FILE}; cannot proceed."
    exit 1
  fi

  # Rest of ensure_binaries function...
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] Skipping binary resolution"
    return
  fi
  KASPAD_BIN="$(resolve_bin kaspad "${BIN_DIR}/kaspad" KASPAD_BIN "${DEFAULT_KASPAD_BIN:-}")"
  KASPA_MINER_BIN="$(resolve_bin kaspa-miner "${BIN_DIR}/kaspa-miner" KASPA_MINER_BIN "${DEFAULT_MINER_BIN:-}")"
  IGRA_BIN="$(resolve_bin kaspa-threshold-service "${BIN_DIR}/kaspa-threshold-service" IGRA_BIN "${DEFAULT_IGRA_BIN:-}")"
  FAKE_HYPERLANE_BIN="$(resolve_bin fake_hyperlane_ism_api "${BIN_DIR}/fake_hyperlane_ism_api" FAKE_HYPERLANE_BIN "${DEFAULT_FAKE_HYPERLANE_BIN:-}")"
  ROTHSCHILD_BIN="$(resolve_bin rothschild "${BIN_DIR}/rothschild" ROTHSCHILD_BIN "${DEFAULT_ROTHSCHILD_BIN:-}")"
}
```

**Also need to move load_env call** (currently at line 214):

```bash
# REMOVE from line 193-220:
# if [[ ! -f "${ENV_FILE}" ]]; then
#   echo "Missing ${ENV_FILE}; copy .env.example first." >&2
#   exit 1
# fi
#
# load_env()
# ...
# load_env
#
# if [[ -z "${KASPA_MINING_ADDRESS:-}" ]]; then
#   echo "KASPA_MINING_ADDRESS is not set; update ${ENV_FILE}." >&2
#   exit 1
# fi

# ADD to ensure_binaries AFTER config paths are set:
ensure_binaries() {
  prepare_sources

  # Set config source...
  # (code from above)

  # NOW load the env file
  load_env

  if [[ -z "${KASPA_MINING_ADDRESS:-}" ]]; then
    log_error "KASPA_MINING_ADDRESS is not set; update ${ENV_FILE}."
    exit 1
  fi

  # Rest of function...
}
```

**Impact**:
- ✅ Clone mode = pure GitHub experience (code + configs)
- ✅ Local mode = uses your local repo configs
- ✅ Fallback if cloned repo lacks configs

---

### Option 2: Keep Current Behavior, Just Document It

**If you want to keep using local configs even with GitHub code** (allows customization):

```bash
# Add comment at line 171:
# NOTE: Config templates always come from the local repo (${DEVNET_DIR}), even in clone mode.
# This allows you to customize configs while testing the latest GitHub code.
# To use configs from the cloned repo, use --config-source clone (not yet implemented).
ENV_FILE="${DEVNET_DIR}/.env"
IGRA_CONFIG_TEMPLATE="${DEVNET_DIR}/igra-devnet.ini"
HYPERLANE_KEYS_SRC="${DEVNET_DIR}/hyperlane-keys.json"
KEYSET_JSON_TEMPLATE="${DEVNET_DIR}/devnet-keys.json"
```

**Also add to usage()** (around line 45):
```bash
Commands:
  (no command)        Build binaries from GitHub, generate keys (uses local config templates)
  setup               Build binaries from GitHub, generate keys (uses local config templates)
  ...

Note: In clone mode, binary code comes from GitHub but config templates (.env, *.ini, *.json)
      come from your local repo. Use --build local to build everything from local sources.
```

---

### Option 3: Add Configuration Flag

**If you want both options**:

```bash
# Add new variable (around line 75):
BUILD_MODE="${BUILD_MODE:-clone}"
CONFIG_SOURCE="${CONFIG_SOURCE:-auto}"  # auto, local, clone
DRY_RUN=false

# Add flag parsing (around line 104):
--config-source)
  case "${2:-}" in
    auto|local|clone) CONFIG_SOURCE="$2"; shift 2 ;;
    *) echo "Unknown --config-source value: ${2:-<missing>} (expected auto|local|clone)" >&2; usage; exit 1 ;;
  esac
  ;;

# In ensure_binaries, set config source:
if [[ "${CONFIG_SOURCE}" == "clone" ]] || [[ "${CONFIG_SOURCE}" == "auto" && "${BUILD_MODE}" == "clone" ]]; then
  config_source="${RUSTY_SRC}/wallet/igra/orchestration/devnet"
  # ... with fallback
else
  config_source="${DEVNET_DIR}"
fi
```

**Usage**:
```bash
# Pure GitHub (default in clone mode):
./run_local_devnet.sh

# GitHub code, local configs:
./run_local_devnet.sh --config-source local

# Everything local:
./run_local_devnet.sh --build local
```

---

## 📋 **Implementation Checklist**

### For Issue #1 (Missing Binaries)
- [x] Enable debug mode (`set -euxo pipefail`)
- [ ] Run build command with debug output
- [ ] Analyze debug log to find root cause
- [ ] Implement fix based on findings
- [ ] Test fix
- [ ] Disable debug mode (change back to `set -euo pipefail`)

### For Issue #2 (Config Source)
- [ ] **Decide which option** to implement:
  - [ ] Option 1: Use cloned configs in clone mode
  - [ ] Option 2: Keep current, document it
  - [ ] Option 3: Add --config-source flag

- [ ] If Option 1:
  - [ ] Move config path setup into `ensure_binaries()`
  - [ ] Set paths after `prepare_sources()`
  - [ ] Add fallback to local if cloned configs missing
  - [ ] Move `load_env()` call into `ensure_binaries()`
  - [ ] Update log messages to show config source
  - [ ] Test clone mode with cloned configs
  - [ ] Test local mode still works

- [ ] If Option 2:
  - [ ] Add comment explaining behavior
  - [ ] Update usage documentation
  - [ ] Test and verify docs are clear

- [ ] If Option 3:
  - [ ] Add CONFIG_SOURCE variable
  - [ ] Add --config-source flag parsing
  - [ ] Implement logic in ensure_binaries
  - [ ] Update usage documentation
  - [ ] Test all combinations

---

## 🧪 **Testing Protocol**

### After Fixing Issue #1
```bash
# Test 1: Clean build
./run_local_devnet.sh clean
./run_local_devnet.sh build
ls -la /tmp/igra_devnet/target/release/kaspad  # Should exist
ls -la /tmp/igra_devnet/target/release/rothschild  # Should exist

# Test 2: Full cycle
./run_local_devnet.sh clean
./run_local_devnet.sh setup
./run_local_devnet.sh start kaspad
./run_local_devnet.sh status
./run_local_devnet.sh stop
```

### After Fixing Issue #2 (Option 1)
```bash
# Test 1: Clone mode uses cloned configs
./run_local_devnet.sh clean
./run_local_devnet.sh --build clone setup 2>&1 | grep "Using config templates"
# Should show: Using config templates from: /tmp/igra_devnet/sources/rusty-kaspa/wallet/igra/orchestration/devnet

# Test 2: Verify configs from cloned repo
diff /tmp/igra_devnet/sources/rusty-kaspa/wallet/igra/orchestration/devnet/.env \
     /path/to/your/local/rusty-kaspa/wallet/igra/orchestration/devnet/.env
# Should show differences if you have local customizations

# Test 3: Local mode uses local configs
./run_local_devnet.sh clean
./run_local_devnet.sh --build local setup 2>&1 | grep "Using config templates"
# Should show: Using config templates from: /path/to/your/local/rusty-kaspa/wallet/igra/orchestration/devnet

# Test 4: Fallback works
# Temporarily rename cloned config:
mv /tmp/igra_devnet/sources/rusty-kaspa/wallet/igra/orchestration/devnet/.env \
   /tmp/igra_devnet/sources/rusty-kaspa/wallet/igra/orchestration/devnet/.env.bak
./run_local_devnet.sh --build clone setup
# Should fallback to local configs with warning
```

---

## 🔧 **Quick Actions**

### To Get Debug Output Now

```bash
# Clean and rebuild with full debug trace:
cd /Users/user/Source/personal/rusty-kaspa/wallet/igra/orchestration/devnet/scripts
./run_local_devnet.sh clean 2>&1 | tee /tmp/clean.log
./run_local_devnet.sh build 2>&1 | tee /tmp/build.log

# Then share /tmp/build.log (or relevant parts)
```

### To Disable Debug Mode After

```bash
# Edit line 2 of run_local_devnet.sh:
# FROM: set -euxo pipefail
# TO:   set -euo pipefail
```

---

## 🎯 **Priority Order**

1. **First**: Get debug log for Issue #1 (missing binaries)
2. **Second**: ✅ **DECIDED** - Implement Option 1 for Issue #2 (use cloned configs)
3. **Third**: Implement fixes:
   - Fix Issue #1 based on debug log findings
   - Implement Option 1 for Issue #2 (code provided above)
4. **Fourth**: Test thoroughly (test protocols provided above)
5. **Fifth**: Disable debug mode (change back to `set -euo pipefail`)

---

## ✅ **DECISION: Option 1 (Use Cloned Configs)**

### User Workflow Clarification

**User customization method**: Running `generate-keys` (NOT manual template edits)

**How it works**:
```
1. Template files (starting point):
   - .env (has placeholders)
   - igra-devnet.ini (has placeholders)

2. generate-keys command:
   - Runs devnet-keygen → generates random keys
   - Python script reads templates
   - Writes NEW configs with generated keys to:
     → ${CONFIG_DIR}/.env (actual config with real keys)
     → ${CONFIG_DIR}/igra-config.ini (actual config)
     → ${CONFIG_DIR}/devnet-keys.json (keyset)
     → ${CONFIG_DIR}/hyperlane-keys.json (validator keys)
```

**Key Insight**: Template files are just starting points for key generation. User's actual customizations live in `${CONFIG_DIR}/` as generated configs, NOT as manual template edits.

### Why Option 1 is Perfect for This Workflow

Since templates are only used as input to `generate-keys` (not manually edited):

✅ **Templates from GitHub** = Pure GitHub experience
✅ **Generated configs in CONFIG_DIR** = User's custom keys
✅ **No conflict** = Templates and configs are separate

**Comparison**:
```
Current Behavior:
├─ Templates: Local repo → Input to keygen
└─ Configs: ${CONFIG_DIR}/ → User's generated keys ✅

Option 1 (Recommended):
├─ Templates: GitHub clone → Input to keygen ✅ Pure GitHub
└─ Configs: ${CONFIG_DIR}/ → User's generated keys ✅

Result: Best of both worlds!
```

### User's Typical Workflow
```bash
# Pure GitHub build:
./run_local_devnet.sh setup
# → Clones from GitHub
# → Uses GitHub templates
# → Generates fresh keys → writes to ${CONFIG_DIR}/

./run_local_devnet.sh start
# → Uses your generated configs from ${CONFIG_DIR}/

./run_local_devnet.sh restart
# → Preserves your generated configs ✅

./run_local_devnet.sh generate-keys
# → Regenerates keys, backs up old ones
# → Templates still from GitHub (or local in current impl)
```

### Recommendation

**IMPLEMENT OPTION 1** - Use cloned configs in clone mode

**Rationale**:
1. User doesn't manually edit templates
2. Customizations come from `generate-keys` output
3. Using GitHub templates = true GitHub experience
4. Generated configs are always preserved in `${CONFIG_DIR}/`
5. No downside since templates are just keygen input

---

## 📝 **Notes**

- Debug mode (`-x`) is currently **ENABLED** - remember to disable after debugging
- Issue #1 requires the debug log to diagnose properly
- Issue #2 has clear solutions, just need to pick the right one for your workflow

---

**Status**:
- Issue #1: 🔍 Investigating (need debug log)
- Issue #2: 💡 Solutions ready (need user decision)

**Next Step**: Run build with debug enabled and share the log!
