# run_local_devnet.sh - Bugs, Issues & Fixes

Comprehensive analysis of `run_local_devnet.sh` with examples of bugs, security issues, and improvement recommendations.

---

## 🐛 Critical Bugs

### 1. Unsafe `.env` Parsing (Lines 115-119)

**Severity**: High
**Impact**: Values with spaces, quotes, or special characters break

**Current Code**:
```bash
load_env() {
  while IFS='=' read -r key value; do
    [[ -z "${key}" || "${key}" =~ ^[[:space:]]*# ]] && continue
    # Preserve everything after the first '=' (including spaces).
    export "${key}=${value}"
  done < "${ENV_FILE}"
}
```

**Problem**: If `.env` contains `FOO="bar baz"`, the exported value includes quotes.

**Fixed Code**:
```bash
load_env() {
  while IFS='=' read -r key value; do
    [[ -z "${key}" || "${key}" =~ ^[[:space:]]*# ]] && continue

    # Strip leading/trailing whitespace
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"

    # Strip surrounding quotes (both single and double)
    if [[ "${value}" =~ ^\"(.*)\"$ ]] || [[ "${value}" =~ ^\'(.*)\'$ ]]; then
      value="${BASH_REMATCH[1]}"
    fi

    export "${key}=${value}"
  done < "${ENV_FILE}"
}
```

---

### 2. Missing Error Handling on Builds (Lines 200-204, 220-222)

**Severity**: Critical
**Impact**: Build failures go unnoticed, leading to runtime errors

**Current Code**:
```bash
build_rusty_repo() {
  require_cmd cargo
  local repo_path="$1"
  echo "Building kaspa binaries from ${repo_path}..."
  (cd "${repo_path}" && CARGO_TARGET_DIR="${TARGET_DIR}" \
    cargo build --release \
      -p kaspad \
      -p rothschild \
      -p igra-service --bin kaspa-threshold-service --bin fake_hyperlane_ism_api)
  # No check if build succeeded!
}
```

**Fixed Code**:
```bash
build_rusty_repo() {
  require_cmd cargo
  local repo_path="$1"
  echo "Building kaspa binaries from ${repo_path}..."

  if ! (cd "${repo_path}" && CARGO_TARGET_DIR="${TARGET_DIR}" \
    cargo build --release \
      -p kaspad \
      -p rothschild \
      -p igra-service --bin kaspa-threshold-service --bin fake_hyperlane_ism_api); then
    echo "ERROR: Failed to build kaspa binaries from ${repo_path}" >&2
    echo "  Check ${LOG_DIR}/build.log for details" >&2
    exit 1
  fi

  # Build devnet-keygen separately
  local keygen_repo="${repo_path}"
  if [[ ! -f "${repo_path}/wallet/igra/igra-core/src/bin/devnet-keygen.rs" && -f "${REPO_ROOT}/wallet/igra/igra-core/src/bin/devnet-keygen.rs" ]]; then
    keygen_repo="${REPO_ROOT}"
  fi

  if [[ -f "${keygen_repo}/wallet/igra/igra-core/src/bin/devnet-keygen.rs" ]]; then
    if ! (cd "${keygen_repo}" && CARGO_TARGET_DIR="${TARGET_DIR}" \
      cargo build --release -p igra-core --bin devnet-keygen); then
      echo "WARNING: Failed to build devnet-keygen, key generation may not work" >&2
    fi
  fi
}
```

**Apply Same Fix to**:
```bash
build_miner_repo() {
  require_cmd cargo
  local repo_path="$1"
  echo "Building kaspa-miner from ${repo_path}..."

  if ! (cd "${repo_path}" && CARGO_TARGET_DIR="${TARGET_DIR}" \
    cargo build --release -p kaspa-miner --locked --features no-asm); then
    echo "ERROR: Failed to build kaspa-miner from ${repo_path}" >&2
    exit 1
  fi
}
```

---

### 3. Process Termination Without Force-Kill Timeout (Line 360)

**Severity**: High
**Impact**: Zombie processes if service ignores SIGTERM

**Current Code**:
```bash
stop_process() {
  local name="$1"
  local pid_file="${PIDS_DIR}/${name}.pid"
  if [[ ! -f "${pid_file}" ]]; then
    echo "No pid file for ${name} (${pid_file}); skipping."
    return
  fi
  local pid
  pid=$(cat "${pid_file}")
  if kill "${pid}" >/dev/null 2>&1; then
    echo "Stopped ${name} (pid ${pid})"
  fi
  rm -f "${pid_file}"
}
```

**Problem**: No timeout, no SIGKILL fallback

**Fixed Code**:
```bash
stop_process() {
  local name="$1"
  local pid_file="${PIDS_DIR}/${name}.pid"

  if [[ ! -f "${pid_file}" ]]; then
    echo "No pid file for ${name}; skipping."
    return
  fi

  local pid
  pid=$(cat "${pid_file}")

  # Check if process is still running
  if ! kill -0 "${pid}" 2>/dev/null; then
    echo "${name} already stopped"
    rm -f "${pid_file}"
    return
  fi

  echo "Stopping ${name} (pid ${pid})..."
  kill "${pid}" 2>/dev/null || true

  # Wait up to 10 seconds for graceful shutdown
  local timeout=10
  for i in $(seq 1 ${timeout}); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      echo "✓ Stopped ${name}"
      rm -f "${pid_file}"
      return
    fi
    sleep 1
  done

  # Force kill if still running
  echo "⚠ ${name} did not stop gracefully, force killing..."
  kill -9 "${pid}" 2>/dev/null || true
  sleep 1

  if kill -0 "${pid}" 2>/dev/null; then
    echo "ERROR: Failed to kill ${name} (pid ${pid})" >&2
  else
    echo "✓ Force killed ${name}"
  fi

  rm -f "${pid_file}"
}
```

---

### 4. Missing Python3 Check

**Severity**: High
**Impact**: Script fails at line 459 with cryptic error

**Current Code**: No early check for python3

**Fixed Code** (add after other `require_cmd` calls around line 176):
```bash
# Early check for Python3 since it's required for key generation
require_cmd python3

# Verify Python version is 3.6+
if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,6) else 1)" 2>/dev/null; then
  echo "ERROR: Python 3.6+ required, but found:" >&2
  python3 --version >&2
  exit 1
fi
```

---

### 5. Keygen Output Not Validated (Lines 450-454)

**Severity**: High
**Impact**: Invalid JSON causes Python script to fail with unclear error

**Current Code**:
```bash
run_keygen() {
  local repo_path
  repo_path="${REPO_ROOT}"
  require_cmd cargo
  (cd "${repo_path}" && CARGO_TARGET_DIR="${TARGET_DIR}" cargo run --quiet --release -p igra-core --bin devnet-keygen)
}

# In generate_keys():
local keygen_json
keygen_json="$(run_keygen)"
if [[ -z "${keygen_json}" ]]; then
  echo "Key generation failed (empty output)" >&2
  exit 1
fi
```

**Problem**: Doesn't check exit code or validate JSON

**Fixed Code**:
```bash
run_keygen() {
  local repo_path="${REPO_ROOT}"
  require_cmd cargo

  local output
  local exit_code

  output=$(cd "${repo_path}" && CARGO_TARGET_DIR="${TARGET_DIR}" \
    cargo run --quiet --release -p igra-core --bin devnet-keygen 2>&1)
  exit_code=$?

  if [[ ${exit_code} -ne 0 ]]; then
    echo "ERROR: devnet-keygen failed with exit code ${exit_code}" >&2
    echo "Output: ${output}" >&2
    return 1
  fi

  # Validate JSON output
  if ! echo "${output}" | python3 -m json.tool >/dev/null 2>&1; then
    echo "ERROR: devnet-keygen produced invalid JSON" >&2
    echo "Output: ${output}" >&2
    return 1
  fi

  echo "${output}"
}

# In generate_keys():
local keygen_json
if ! keygen_json="$(run_keygen)"; then
  echo "Key generation failed" >&2
  exit 1
fi

if [[ -z "${keygen_json}" ]]; then
  echo "ERROR: Key generation produced empty output" >&2
  exit 1
fi
```

---

## ⚠️ Logic Issues

### 6. Inconsistent Build Flags (Lines 201-204 vs 222)

**Severity**: Medium
**Impact**: Potential dependency version mismatches

**Current Code**:
```bash
# Rusty-kaspa build: No --locked flag
cargo build --release -p kaspad -p rothschild -p igra-service ...

# Miner build: Uses --locked flag
cargo build --release -p kaspa-miner --locked --features no-asm
```

**Recommendation**: Use `--locked` consistently for reproducible builds

**Fixed Code**:
```bash
build_rusty_repo() {
  # ...
  (cd "${repo_path}" && CARGO_TARGET_DIR="${TARGET_DIR}" \
    cargo build --release --locked \  # ADD --locked
      -p kaspad \
      -p rothschild \
      -p igra-service --bin kaspa-threshold-service --bin fake_hyperlane_ism_api)
}
```

---

### 7. `copy_if_changed` Doesn't Check Changes (Lines 313-319)

**Severity**: Low
**Impact**: Misleading function name, unnecessary file copies

**Current Code**:
```bash
copy_if_changed() {
  local src="$1" dest="$2"
  if [[ "${src}" == "${dest}" ]]; then
    return
  fi
  cp -f "${src}" "${dest}"
}
```

**Problem**: Name implies it checks file differences, but it doesn't

**Option 1 - Rename**:
```bash
copy_bin() {
  local src="$1" dest="$2"
  [[ "${src}" == "${dest}" ]] && return
  cp -f "${src}" "${dest}"
}
```

**Option 2 - Actually Check Changes**:
```bash
copy_if_changed() {
  local src="$1" dest="$2"

  # Same path, nothing to do
  [[ "${src}" == "${dest}" ]] && return

  # Destination doesn't exist or files differ
  if [[ ! -f "${dest}" ]] || ! cmp -s "${src}" "${dest}"; then
    echo "Updating ${dest##*/}..."
    cp -f "${src}" "${dest}"
  fi
}
```

---

### 8. Template Files Overwritten (Python Lines 598-599, 614)

**Severity**: Medium
**Impact**: Git working directory contaminated with generated configs

**Current Code** (in embedded Python):
```python
ini_out.write_text(new_text)
dest = config_dir / ini_out.name
if ini_out != dest:
    shutil.copy2(ini_out, dest)
ini_template.write_text(new_text)  # ⚠ OVERWRITES SOURCE FILE
```

**Problem**: Modifies files that might be in version control

**Fixed Code**:
```python
# Write to config dir only
ini_out.write_text(new_text)
dest = config_dir / ini_out.name
if ini_out != dest:
    shutil.copy2(ini_out, dest)

# DON'T overwrite template - only write to run directory
# ini_template.write_text(new_text)  # REMOVED

print(f"Generated config: {dest}")
print(f"Template unchanged: {ini_template}")
```

**Apply same fix to `write_hyperlane_keys()` and `write_keyset()`**:
```python
def write_hyperlane_keys():
    # ... build content ...
    hyperlane_out.write_text(content)
    dest = config_dir / hyperlane_out.name
    if hyperlane_out != dest:
        shutil.copy2(hyperlane_out, dest)
    # hyperlane_template.write_text(content)  # REMOVED

def write_keyset():
    # ... build content ...
    keyset_out.write_text(content)
    # if keyset_template != keyset_out:
    #     keyset_template.write_text(content)  # REMOVED
    dest = config_dir / keyset_out.name
    if dest != keyset_out:
        shutil.copy2(keyset_out, dest)
```

---

### 9. Unnecessary Bash Wrapper (Line 377)

**Severity**: Low
**Impact**: Extra process overhead

**Current Code**:
```bash
start_kaspad() {
  start_process "kaspad" \
    bash -c "cd \"${RUN_ROOT}\" && exec \"${KASPAD_BIN}\" \
    --devnet \
    --utxoindex \
    --appdir=\"${KASPAD_APPDIR}\" \
    --rpcserver=127.0.0.1:16110 \
    --listen=0.0.0.0:16111"
}
```

**Problem**: Extra bash process, and the script already cd's to RUN_ROOT at line 78

**Fixed Code**:
```bash
start_kaspad() {
  start_process "kaspad" \
    "${KASPAD_BIN}" \
    --devnet \
    --utxoindex \
    --appdir="${KASPAD_APPDIR}" \
    --rpcserver=127.0.0.1:16110 \
    --listen=0.0.0.0:16111
}
```

---

## 🔒 Security Issues

### 10. Secrets in Log Files (Line 344)

**Severity**: Medium
**Impact**: Mnemonics and private keys may be exposed in logs

**Current Code**:
```bash
start_process() {
  local name="$1"
  shift
  echo "Starting ${name}..."
  "$@" >"${LOG_DIR}/${name}.log" 2>&1 &
  # ...
}
```

**Problem**: If processes log sensitive data (mnemonics, keys), it's written to disk

**Mitigations**:

**Option 1 - Add Warning**:
```bash
# Add to script header
cat <<'WARNING'
⚠️  WARNING: Process logs may contain sensitive data (mnemonics, private keys).
    Logs location: ${LOG_DIR}
    Ensure proper file permissions and secure deletion when done.
WARNING
```

**Option 2 - Filter Sensitive Patterns** (complex, not recommended):
```bash
# Too error-prone for this use case
# Better to rely on applications not logging secrets
```

**Option 3 - Document Log Security**:
```bash
mkdir -p "${LOG_DIR}"
chmod 700 "${LOG_DIR}"  # Only owner can read/write/execute

# Add to help text
usage() {
  cat <<'EOF'
...
Security Notes:
  - Logs in ${LOG_DIR} may contain sensitive cryptographic material
  - Ensure log directory has restricted permissions (700)
  - Securely delete logs after debugging: shred -u ${LOG_DIR}/*.log
EOF
}
```

---

### 11. No Validation of Clone URLs (Lines 183-186)

**Severity**: Low
**Impact**: Malicious URLs from environment variables

**Current Code**:
```bash
clone_repo() {
  local url="$1"
  local ref="$2"
  local dest="$3"

  # Normalize SSH-style GitHub URLs to HTTPS
  if [[ "${url}" =~ ^git@github.com:(.*)\.git$ ]]; then
    url="https://github.com/${BASH_REMATCH[1]}.git"
  fi

  if [[ -d "${dest}/.git" ]]; then
    echo "Using existing clone at ${dest}"
    return
  fi
  mkdir -p "$(dirname "${dest}")"
  git clone --depth 1 --branch "${ref}" "${url}" "${dest}"
}
```

**Fixed Code**:
```bash
clone_repo() {
  local url="$1"
  local ref="$2"
  local dest="$3"

  # Normalize SSH-style GitHub URLs to HTTPS
  if [[ "${url}" =~ ^git@github.com:(.*)\.git$ ]]; then
    url="https://github.com/${BASH_REMATCH[1]}.git"
  fi

  # Warn if cloning from non-GitHub source
  if [[ ! "${url}" =~ ^https://github\.com/ ]]; then
    echo "⚠️  WARNING: Cloning from non-GitHub URL: ${url}" >&2
    echo "   Only clone from trusted sources." >&2
    read -p "Continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      echo "Clone cancelled by user" >&2
      return 1
    fi
  fi

  if [[ -d "${dest}/.git" ]]; then
    echo "Using existing clone at ${dest}"
    return
  fi

  mkdir -p "$(dirname "${dest}")"

  echo "Cloning ${url}#${ref} to ${dest}..."
  if ! git clone --depth 1 --branch "${ref}" "${url}" "${dest}"; then
    echo "ERROR: Failed to clone ${url}" >&2
    return 1
  fi
}
```

---

## 💡 Improvements

### 12. Add Health Checks After Starting Processes

**Benefit**: Detect startup failures early

**Add New Functions**:
```bash
wait_for_kaspad() {
  local max_wait=30
  echo "Waiting for kaspad to be ready..."

  for i in $(seq 1 ${max_wait}); do
    # Check if process is still running
    if [[ -f "${PIDS_DIR}/kaspad.pid" ]]; then
      local pid=$(cat "${PIDS_DIR}/kaspad.pid")
      if ! kill -0 "${pid}" 2>/dev/null; then
        echo "ERROR: kaspad process died during startup" >&2
        echo "Check ${LOG_DIR}/kaspad.log for details" >&2
        return 1
      fi
    fi

    # Check if RPC is responding
    if command -v grpcurl >/dev/null 2>&1; then
      if grpcurl -plaintext 127.0.0.1:16110 list >/dev/null 2>&1; then
        echo "✓ kaspad is ready"
        return 0
      fi
    else
      # Fallback: check if port is listening
      if command -v nc >/dev/null 2>&1; then
        if nc -z 127.0.0.1 16110 2>/dev/null; then
          echo "✓ kaspad is listening on 127.0.0.1:16110"
          return 0
        fi
      fi
    fi

    sleep 1
  done

  echo "ERROR: kaspad did not start within ${max_wait} seconds" >&2
  return 1
}

wait_for_igra() {
  local profile="$1"
  local rpc_port="$2"
  local max_wait=20

  echo "Waiting for igra-${profile} to be ready..."

  for i in $(seq 1 ${max_wait}); do
    if [[ -f "${PIDS_DIR}/igra-${profile}.pid" ]]; then
      local pid=$(cat "${PIDS_DIR}/igra-${profile}.pid")
      if ! kill -0 "${pid}" 2>/dev/null; then
        echo "ERROR: igra-${profile} process died during startup" >&2
        return 1
      fi
    fi

    # Check if RPC endpoint responds
    if curl -s -f "http://127.0.0.1:${rpc_port}/rpc" >/dev/null 2>&1; then
      echo "✓ igra-${profile} is ready"
      return 0
    fi

    sleep 1
  done

  echo "WARNING: igra-${profile} health check timed out (may still be starting)" >&2
  return 0  # Don't fail, just warn
}
```

**Update `start_targets()`**:
```bash
start_targets() {
  local target
  for target in "${TARGETS[@]}"; do
    case "${target}" in
      kaspad)
        start_kaspad
        wait_for_kaspad || exit 1
        ;;
      kaspaminer)
        # Wait for kaspad first
        if [[ ! -f "${PIDS_DIR}/kaspad.pid" ]]; then
          echo "ERROR: Cannot start miner without kaspad running" >&2
          exit 1
        fi
        start_miner
        ;;
      signer-1)
        start_igra "signer-1" "8088"
        wait_for_igra "signer-1" "8088"
        ;;
      signer-2)
        start_igra "signer-2" "8089"
        wait_for_igra "signer-2" "8089"
        ;;
      signer-3)
        start_igra "signer-3" "8090"
        wait_for_igra "signer-3" "8090"
        ;;
    esac
  done
}
```

---

### 13. Better Error Messages with Context

**Current**: Generic errors without helpful context
**Improved**: Contextual errors with suggestions

**Example - Improve `require_cmd`**:
```bash
require_cmd() {
  local cmd="$1"
  local reason="${2:-required by this script}"
  local install_hint="${3:-}"

  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
    echo "ERROR: Required command '${cmd}' not found" >&2
    echo "  Context: ${reason}" >&2
    if [[ -n "${install_hint}" ]]; then
      echo "  Install: ${install_hint}" >&2
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
    exit 1
  fi
}

# Usage examples:
require_cmd git "for cloning repositories" "brew install git (macOS) or apt install git (Ubuntu)"
require_cmd cargo "for building Rust binaries" "Install from https://rustup.rs"
require_cmd python3 "for key generation and config updates" "brew install python3 or apt install python3"
```

---

### 14. Add `--dry-run` Flag

**Benefit**: Preview actions without executing

**Implementation**:
```bash
# At top of script, add:
DRY_RUN=false

# In argument parsing (around line 34):
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      echo "🔍 DRY RUN MODE: Commands will be printed but not executed"
      shift
      ;;
    --build)
      # ... existing code ...
      ;;
    # ... rest of cases ...
  esac
done

# Update usage():
usage() {
  cat <<'EOF'
Usage: run_local_devnet.sh [OPTIONS] [COMMAND] [TARGET]

Options:
  --build clone|local  Build mode (default: clone)
  --root PATH          Root working directory
  --target-dir PATH    Build target directory
  --dry-run           Show what would be done without executing
  -h, --help          Show this help
EOF
}

# Wrap critical operations:
start_process() {
  local name="$1"
  shift

  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "[DRY-RUN] Would start ${name}: $*"
    echo "[DRY-RUN]   Log: ${LOG_DIR}/${name}.log"
    return
  fi

  echo "Starting ${name}..."
  "$@" >"${LOG_DIR}/${name}.log" 2>&1 &
  local pid=$!
  PIDS+=("${pid}")
  echo "${pid}" > "${PIDS_DIR}/${name}.pid"
  echo "  pid=${pid} log=${LOG_DIR}/${name}.log"
}

stop_process() {
  local name="$1"

  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "[DRY-RUN] Would stop ${name}"
    return
  fi

  # ... existing implementation ...
}

# For builds:
build_rusty_repo() {
  require_cmd cargo
  local repo_path="$1"

  local cmd="cargo build --release --locked -p kaspad -p rothschild -p igra-service"

  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "[DRY-RUN] Would build from ${repo_path}:"
    echo "[DRY-RUN]   cd ${repo_path} && CARGO_TARGET_DIR=${TARGET_DIR} ${cmd}"
    return
  fi

  echo "Building kaspa binaries from ${repo_path}..."
  # ... actual build ...
}
```

---

### 15. Add Process Status Command

**Benefit**: Quick overview of running services

**Implementation**:
```bash
# Update usage to include 'status' command:
usage() {
  cat <<'EOF'
Commands:
  setup               Build binaries and prepare configs
  build               Build binaries only
  start [target]      Start services (default: all)
  stop [target]       Stop services
  restart [target]    Restart services
  status [target]     Show status of services
  generate-keys       Regenerate devnet keys
  clean               Remove all devnet data
  help                Show this help
EOF
}

# Add status command handler:
show_status() {
  local target="$1"
  local pids=()

  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Devnet Status (root: ${RUN_ROOT})"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  for process in kaspad kaspaminer igra-signer-1 igra-signer-2 igra-signer-3 fake-hyperlane-signer-1 fake-hyperlane-signer-2 fake-hyperlane-signer-3; do
    local pid_file="${PIDS_DIR}/${process}.pid"
    local status_symbol="✗"
    local status_text="Not running"
    local pid_info=""

    if [[ -f "${pid_file}" ]]; then
      local pid=$(cat "${pid_file}")

      if kill -0 "${pid}" 2>/dev/null; then
        status_symbol="✓"
        status_text="Running"
        pid_info=" (pid ${pid})"

        # Get uptime if available
        if command -v ps >/dev/null 2>&1; then
          local uptime=$(ps -p "${pid}" -o etime= 2>/dev/null | tr -d ' ')
          if [[ -n "${uptime}" ]]; then
            pid_info+=" [uptime: ${uptime}]"
          fi
        fi

        pids+=("${pid}")
      else
        status_symbol="⚠"
        status_text="Stale PID file"
        pid_info=" (pid ${pid} not found)"
      fi
    fi

    printf "  %-25s %s %s%s\n" "${process}" "${status_symbol}" "${status_text}" "${pid_info}"

    # Show last few log lines if error detected
    if [[ "${status_symbol}" == "⚠" ]] && [[ -f "${LOG_DIR}/${process}.log" ]]; then
      echo "    Last error:"
      tail -3 "${LOG_DIR}/${process}.log" 2>/dev/null | sed 's/^/      /'
    fi
  done

  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Running processes: ${#pids[@]}"
  echo "Logs directory: ${LOG_DIR}"
  echo "Data directory: ${DATA_ROOT}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Add to command case statement (around line 683):
case "${COMMAND}" in
  setup)
    # ... existing ...
    ;;
  status)
    show_status "${TARGET_ARG}"
    exit 0
    ;;
  # ... rest ...
esac

# Also update the command validation (line 55):
case "${COMMAND}" in
  help|-h|--help) usage; exit 0 ;;
  setup|build|start|stop|restart|clean|generate-keys|status) ;;
  default) ;;
  *) echo "Unknown command: ${COMMAND}" >&2; usage; exit 1 ;;
esac
```

---

### 16. Extract Embedded Python to Separate File

**Benefit**: Easier to maintain, test, and read

**Create `scripts/update_devnet_config.py`**:
```python
#!/usr/bin/env python3
"""
Update devnet configuration files with generated keys.

Usage:
    update_devnet_config.py ENV_FILE INI_TEMPLATE HYPERLANE_TEMPLATE \\
        CONFIG_DIR INI_OUT HYPERLANE_OUT KEYGEN_JSON \\
        IGRA_DATA RUN_ROOT KEYSET_TEMPLATE KEYSET_OUT
"""

import json
import sys
import pathlib
import hashlib
import datetime
import shutil


def main():
    if len(sys.argv) != 12:
        print(__doc__, file=sys.stderr)
        sys.exit(1)

    env_path = pathlib.Path(sys.argv[1])
    ini_template = pathlib.Path(sys.argv[2])
    hyperlane_template = pathlib.Path(sys.argv[3])
    config_dir = pathlib.Path(sys.argv[4])
    ini_out = pathlib.Path(sys.argv[5])
    hyperlane_out = pathlib.Path(sys.argv[6])
    keygen_path = pathlib.Path(sys.argv[7])
    igra_data = pathlib.Path(sys.argv[8])
    run_root = pathlib.Path(sys.argv[9])
    keyset_template = pathlib.Path(sys.argv[10])
    keyset_out = pathlib.Path(sys.argv[11])

    try:
        raw = keygen_path.read_text()
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in {keygen_path}: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to read {keygen_path}: {e}", file=sys.stderr)
        sys.exit(1)

    generated_ts = datetime.datetime.utcnow().isoformat() + "Z"
    config_dir.mkdir(parents=True, exist_ok=True)

    write_env(env_path, config_dir, data)
    rewrite_ini(ini_template, ini_out, config_dir, data, generated_ts, igra_data, run_root)
    write_hyperlane_keys(hyperlane_out, config_dir, data)
    write_keyset(keyset_out, config_dir, data, generated_ts)

    print(f"✓ Configuration updated in {config_dir}")


def write_env(env_path, config_dir, data):
    """Update .env file with wallet credentials."""
    env_vars = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if not line.strip() or line.strip().startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env_vars[k.strip()] = v.strip()

    env_vars["KASPA_DEVNET_WALLET_MNEMONIC"] = data["wallet"]["mnemonic"]
    env_vars["KASPA_DEVNET_WALLET_PASSWORD"] = data["wallet"]["password"]
    env_vars["KASPA_DEVNET_WALLET_NAME"] = data["wallet"]["name"]
    env_vars["KASPA_MINING_ADDRESS"] = data["wallet"]["mining_address"]

    lines = [f"{k}={v}" for k, v in env_vars.items()]
    env_path.write_text("\n".join(lines) + "\n")
    shutil.copy2(env_path, config_dir / ".env")


def rewrite_ini(ini_template, ini_out, config_dir, data, generated_ts, igra_data, run_root):
    """Rewrite INI template with generated keys."""
    # ... (same logic as embedded Python, but in a proper file)
    # See existing implementation in lines 496-600
    pass  # Implementation omitted for brevity


def write_hyperlane_keys(hyperlane_out, config_dir, data):
    """Write hyperlane validator keys."""
    validators = []
    for key in data["hyperlane_keys"]:
        validators.append({
            "name": key["name"],
            "private_key_hex": key["private_key_hex"],
            "public_key_hex": key["public_key_hex"],
        })

    content = json.dumps({"validators": validators}, indent=2) + "\n"
    hyperlane_out.write_text(content)

    dest = config_dir / hyperlane_out.name
    if hyperlane_out != dest:
        shutil.copy2(hyperlane_out, dest)


def write_keyset(keyset_out, config_dir, data, generated_ts):
    """Write complete keyset JSON."""
    payload = {
        "generated_at": generated_ts,
        "wallet": data["wallet"],
        "signers": data["signers"],
        "member_pubkeys": data["member_pubkeys"],
        "redeem_script_hex": data["redeem_script_hex"],
        "source_addresses": data["source_addresses"],
        "change_address": data["change_address"],
        "hyperlane_keys": data["hyperlane_keys"],
    }

    content = json.dumps(payload, indent=2) + "\n"
    keyset_out.write_text(content)

    dest = config_dir / keyset_out.name
    if dest != keyset_out:
        shutil.copy2(keyset_out, dest)


if __name__ == "__main__":
    main()
```

**Update bash script (line 459)**:
```bash
# Replace embedded Python with:
python3 "${SCRIPT_DIR}/update_devnet_config.py" \
  "$ENV_FILE" "$IGRA_CONFIG_TEMPLATE" "$HYPERLANE_KEYS_SRC" \
  "$CONFIG_DIR" "$IGRA_CONFIG" "$HYPERLANE_KEYS" \
  "$keygen_tmp" "$IGRA_DATA" "$RUN_ROOT" \
  "$KEYSET_JSON_TEMPLATE" "$KEYSET_JSON"

if [[ $? -ne 0 ]]; then
  echo "ERROR: Failed to update devnet configuration" >&2
  exit 1
fi
```

---

### 17. Add Logging with Timestamps

**Benefit**: Better debugging and audit trail

**Implementation**:
```bash
# Add at top of script after set -euo pipefail:

# Color codes (only if stdout is a terminal)
if [[ -t 1 ]]; then
  COLOR_RESET='\033[0m'
  COLOR_RED='\033[0;31m'
  COLOR_GREEN='\033[0;32m'
  COLOR_YELLOW='\033[0;33m'
  COLOR_BLUE='\033[0;34m'
  COLOR_GRAY='\033[0;90m'
else
  COLOR_RESET=''
  COLOR_RED=''
  COLOR_GREEN=''
  COLOR_YELLOW=''
  COLOR_BLUE=''
  COLOR_GRAY=''
fi

# Logging functions
log() {
  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  echo -e "${COLOR_GRAY}[${timestamp}]${COLOR_RESET} $*"
}

log_info() {
  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  echo -e "${COLOR_GRAY}[${timestamp}]${COLOR_RESET} ${COLOR_BLUE}ℹ${COLOR_RESET} $*"
}

log_success() {
  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  echo -e "${COLOR_GRAY}[${timestamp}]${COLOR_RESET} ${COLOR_GREEN}✓${COLOR_RESET} $*"
}

log_warn() {
  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  echo -e "${COLOR_GRAY}[${timestamp}]${COLOR_RESET} ${COLOR_YELLOW}⚠${COLOR_RESET} $*" >&2
}

log_error() {
  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  echo -e "${COLOR_GRAY}[${timestamp}]${COLOR_RESET} ${COLOR_RED}✗${COLOR_RESET} $*" >&2
}

# Usage examples throughout script:
# Replace: echo "Starting kaspad..."
# With:    log_info "Starting kaspad..."

# Replace: echo "Stopped ${name} (pid ${pid})"
# With:    log_success "Stopped ${name} (pid ${pid})"

# Replace: echo "Missing required command: ${cmd}" >&2
# With:    log_error "Missing required command: ${cmd}"
```

---

### 18. Validate JSON from Keygen

**Already covered in Critical Bug #5**, but here's a standalone function:

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

# Usage in generate_keys():
if ! keygen_json="$(run_keygen)"; then
  log_error "Key generation failed"
  exit 1
fi

if ! validate_json "${keygen_json}" "Keygen output"; then
  exit 1
fi
```

---

## 📊 Priority Summary

### 🔴 Critical (Fix Immediately)
1. **Build error handling** - Prevents silent build failures
2. **Process termination timeout** - Prevents zombie processes
3. **Python3 early check** - Better error messages
4. **Keygen validation** - Catch generation failures early
5. **`.env` parsing** - Handles quoted values correctly

### 🟡 High Priority
6. **Template file overwrites** - Prevents git pollution
7. **Health checks** - Detect startup failures
8. **Status command** - Operational visibility
9. **Consistent build flags** - Reproducible builds

### 🟢 Medium Priority
10. **Better error messages** - Improved debugging
11. **Dry-run mode** - Safer testing
12. **Logging with timestamps** - Better audit trail
13. **Clone URL validation** - Security

### 🔵 Nice to Have
14. **Extract Python script** - Code maintainability
15. **Remove bash wrapper** - Minor optimization
16. **Rename `copy_if_changed`** - Code clarity

---

## 🚀 Quick Win Patches

### Minimal Patch (Top 5 Critical Fixes)

Apply these changes for immediate improvement:

1. **Add build error checks** (2 locations)
2. **Fix `stop_process` with timeout**
3. **Add early `require_cmd python3`**
4. **Fix `run_keygen` with error handling**
5. **Fix `.env` parsing for quoted values**

**Estimated time**: 15 minutes
**Impact**: High - catches most common failure modes

### Comprehensive Patch (All High Priority)

Include critical + high priority fixes:
- All critical fixes above
- Don't overwrite template files
- Add health checks
- Add status command
- Make build flags consistent

**Estimated time**: 1-2 hours
**Impact**: Very high - production-ready script

---

## 📝 Testing Recommendations

After applying fixes, test these scenarios:

### 1. Fresh Setup
```bash
./run_local_devnet.sh clean
./run_local_devnet.sh setup
./run_local_devnet.sh start
./run_local_devnet.sh status
```

### 2. Build Failures
```bash
# Simulate build failure
export KASPAD_BIN="/path/to/nonexistent/binary"
./run_local_devnet.sh build  # Should fail gracefully with clear error
```

### 3. Process Management
```bash
./run_local_devnet.sh start kaspad
./run_local_devnet.sh status
./run_local_devnet.sh stop kaspad
./run_local_devnet.sh status  # Should show stopped
```

### 4. Quoted Values in .env
```bash
echo 'KASPA_MINING_ADDRESS="kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3"' >> ../devnet/.env
./run_local_devnet.sh generate-keys
# Should not include quotes in exported values
```

### 5. Graceful Shutdown
```bash
./run_local_devnet.sh start all
# Press Ctrl+C
# All processes should stop within 10 seconds
```

---

## 📚 Additional Resources

- **Bash Best Practices**: https://mywiki.wooledge.org/BashGuide/Practices
- **ShellCheck**: https://www.shellcheck.net/ (automated script analysis)
- **Process Management**: `man trap`, `man kill`, `man wait`
- **Cargo Build Options**: `cargo build --help`

---

## ✅ Validation Checklist

Before deploying the fixed script:

- [ ] All critical bugs addressed
- [ ] Build failures are detected and reported
- [ ] Process cleanup works reliably
- [ ] Status command shows accurate information
- [ ] Logs have restricted permissions (700)
- [ ] Template files not modified in version control
- [ ] Health checks validate successful startup
- [ ] Error messages are clear and actionable
- [ ] Dry-run mode works for all commands
- [ ] Python3 and required tools are validated early
- [ ] JSON validation prevents cryptic errors
- [ ] Documentation updated with new features

---

**Generated**: 2026-01-07
**Script Version**: run_local_devnet.sh (analyzed from commit context)
**Severity Scale**: Critical > High > Medium > Low
