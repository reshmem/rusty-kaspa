# Review: run_local_devnet_with_avail_and_hyperlane.sh

**Reviewed:** 2026-01-27
**Script:** `orchestration/devnet/scripts/run_local_devnet_with_avail_and_hyperlane.sh`
**Status:** Production-Ready with Minor Improvements Needed

---

## Executive Summary

**Overall Assessment:** Well-structured script with good error handling, proper port management, and comprehensive functionality. Ready for use with minor improvements.

**Strengths:**
- ✅ Good error handling and validation
- ✅ Proper port conflict detection
- ✅ DRY_RUN mode support
- ✅ Comprehensive logging with timestamps
- ✅ Graceful process shutdown
- ✅ Secrets redaction in dry-run mode
- ✅ Proper integration with Hyperlane monorepo

**Issues Found:**
- ⚠️ Minor security issue: secrets passphrase handling
- ⚠️ Documentation gaps
- ⚠️ Hard-to-debug Python inline code
- ⚠️ Missing health checks for validators/relayers

---

## Critical Review

### 1. Security Issues

#### 1.1 Secrets Passphrase Exposure (Line 218-229)

**Current Implementation:**
```bash
for arg in "$@"; do
  if [[ "${prev}" == "--secrets-passphrase" ]]; then
    redacted+=("<redacted>")
    prev=""
    continue
  fi
  if [[ "${arg}" == --secrets-passphrase=* ]]; then
    redacted+=("--secrets-passphrase=<redacted>")
    prev=""
    continue
  fi
  redacted+=("${arg}")
  prev="${arg}"
done
```

**Issue:** Redaction only works in DRY_RUN mode. In normal execution, the passphrase is passed to subcommands and could leak via:
- Process listing (`ps auxe`)
- Shell history if commands are logged
- Error messages

**Severity:** MEDIUM - devnet only, but still a security best practice

**Recommendation:**
```bash
# Instead of passing via CLI args, use environment variable
run env IGRA_SECRETS_PASSPHRASE="${secrets_passphrase}" \
  "${IGRA_RUNNER}" "${args[@]}" default
```

---

### 2. Error Handling

#### 2.1 Python Inline Code Error Messages (Lines 787-830, 868-927)

**Current Implementation:**
Extensive Python code embedded in heredocs for config generation.

**Issue:**
- If Python fails, error messages are minimal
- Hard to debug which line in the Python code failed
- No line numbers in error output

**Example (Line 787):**
```bash
python3 - <<PY
import json
from pathlib import Path
# ... 40+ lines of Python
PY
```

**Severity:** LOW - but impacts debuggability

**Recommendation:**
1. Move Python code to separate `.py` files in `scripts/` directory
2. Add better error messages with context
3. Consider using `set -x` or `python3 -u` for better debugging

**Alternative (keep inline):**
```bash
if ! python3 - <<'PY'
import json
import sys
try:
    # ... existing code ...
except Exception as e:
    print(f"ERROR in write_validator_config: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc()
    sys.exit(1)
PY
then
  log_error "Failed to write validator config for idx=${idx}"
  exit 1
fi
```

---

#### 2.2 Missing Health Checks for Hyperlane Agents (Lines 930-968)

**Current Implementation:**
Validators and relayers are started but no readiness check.

**Issue:**
- Agents could crash immediately after start
- No verification they're actually running
- Metrics ports might not be available

**Severity:** MEDIUM - affects reliability

**Recommendation:**
Add health checks similar to `wait_for_igra()`:

```bash
wait_for_validator() {
  local idx="$1"
  local metrics_port="$2"
  local max_wait=30

  log_info "Waiting for validator-${idx} metrics..."
  for _ in $(seq 1 ${max_wait}); do
    if curl -s -f "http://127.0.0.1:${metrics_port}/metrics" >/dev/null 2>&1; then
      log_success "validator-${idx} is ready"
      return 0
    fi
    sleep 1
  done
  log_warn "validator-${idx} health check timed out (may still be starting)"
  return 0
}

wait_for_relayer() {
  local idx="$1"
  local metrics_port="$2"
  local max_wait=30

  log_info "Waiting for relayer-${idx} metrics..."
  for _ in $(seq 1 ${max_wait}); do
    if curl -s -f "http://127.0.0.1:${metrics_port}/metrics" >/dev/null 2>&1; then
      log_success "relayer-${idx} is ready"
      return 0
    fi
    sleep 1
  done
  log_warn "relayer-${idx} health check timed out (may still be starting)"
  return 0
}
```

Then call after starting each agent:
```bash
start_process "validator-$((idx + 1))" bash -lc "cd \"${workdir}\" && \"${validator_bin}\""
wait_for_validator "$((idx + 1))" "${metrics_port}"
```

---

### 3. Configuration Issues

#### 3.1 Validator Announce Funding (Lines 712-735)

**Current Implementation:**
Funds validator accounts with 10 ETH each.

**Issue:**
- Hardcoded amount (10 ETH)
- No verification of successful funding
- No check if already funded (wastes gas on restart)

**Severity:** LOW - devnet only

**Recommendation:**
```bash
fund_validator_accounts() {
  local keys_json="${RUN_ROOT}/config/hyperlane-keys.json"
  local keyset_json="${RUN_ROOT}/config/devnet-keys.json"
  if [[ ! -f "${keys_json}" || ! -f "${keyset_json}" ]]; then
    log_error "Missing keys under ${RUN_ROOT}/config; run 'default' first"
    exit 1
  fi

  local evm_priv
  evm_priv="$(read_json_field "${keyset_json}" "data['evm']['private_key_hex']")"

  local funding_amount="${VALIDATOR_FUNDING_AMOUNT:-10ether}"

  for idx in 0 1; do
    local vpriv
    vpriv="$(read_json_field "${keys_json}" "data['validators'][${idx}]['private_key_hex']")"
    local vaddr
    vaddr="$(cast wallet address --private-key "0x${vpriv}" 2>/dev/null | tr -d '\r' | tr 'A-Z' 'a-z')"
    if [[ -z "${vaddr}" ]]; then
      log_error "Failed to derive validator address for validator index ${idx}"
      exit 1
    fi

    # Check current balance
    local balance
    balance="$(cast balance "${vaddr}" --rpc-url "${ANVIL_RPC_URL}" 2>/dev/null || echo "0")"
    if [[ "${balance}" == "0" || "${balance}" == "0x0" ]]; then
      log_info "Funding validator-${idx} address=${vaddr} amount=${funding_amount}"
      if ! run cast send --private-key "0x${evm_priv}" --rpc-url "${ANVIL_RPC_URL}" "${vaddr}" --value "${funding_amount}"; then
        log_error "Failed to fund validator-${idx}"
        exit 1
      fi
      log_success "Funded validator-${idx}"
    else
      log_info "validator-${idx} already funded balance=${balance} address=${vaddr}"
    fi
  done
}
```

---

#### 3.2 Hardcoded Validator Count (Lines 723, 950)

**Current Implementation:**
```bash
for idx in 0 1; do  # Hardcoded to 2 validators
```

**Issue:**
- Not configurable
- Threshold is hardcoded to 2 (line 668)
- Difficult to test different threshold configurations

**Severity:** LOW - devnet flexibility

**Recommendation:**
```bash
VALIDATOR_COUNT="${VALIDATOR_COUNT:-2}"
VALIDATOR_THRESHOLD="${VALIDATOR_THRESHOLD:-2}"

# In deploy_hyperlane_core:
threshold: ${VALIDATOR_THRESHOLD}

# In fund_validator_accounts and start_hyperlane_agents:
for idx in $(seq 0 $((VALIDATOR_COUNT - 1))); do
```

---

#### 3.3 Relayer Count Mismatch (Lines 960-967)

**Current Implementation:**
```bash
local relayer_rpc_urls=("http://127.0.0.1:8088" "http://127.0.0.1:8089" "http://127.0.0.1:8090")
for idx in 0 1 2; do  # Hardcoded to 3 relayers
```

**Issue:**
- Assumes exactly 3 Igra signers
- If Igra devnet runs with different number of signers, mismatch occurs

**Severity:** LOW - devnet flexibility

**Recommendation:**
Derive from Igra config or make configurable:
```bash
# Read from igra-config.toml or use env var
RELAYER_COUNT="${RELAYER_COUNT:-3}"
IGRA_BASE_PORT="${IGRA_BASE_PORT:-8088}"

# Generate RPC URLs dynamically
local -a relayer_rpc_urls=()
for i in $(seq 0 $((RELAYER_COUNT - 1))); do
  local port=$((IGRA_BASE_PORT + i))
  relayer_rpc_urls+=("http://127.0.0.1:${port}")
done

for idx in $(seq 0 $((RELAYER_COUNT - 1))); do
  local metrics_port="$((9920 + idx))"
  # ... rest
done
```

---

### 4. Robustness Issues

#### 4.1 HYPERLANE_CLI_MODE Default (Line 356)

**Current Implementation:**
```bash
HYPERLANE_CLI_MODE="${HYPERLANE_CLI_MODE:-npm}"
```

**Issue:**
- `npm` mode requires internet access to download `@hyperlane-xyz/cli`
- Version pinned to `21.1.0` (line 357) might become unavailable
- No offline fallback

**Severity:** LOW - devnet convenience

**Recommendation:**
Auto-detect based on repo presence:
```bash
if [[ -d "${HYP_REPO}/typescript/cli" ]]; then
  HYPERLANE_CLI_MODE="${HYPERLANE_CLI_MODE:-repo}"
else
  HYPERLANE_CLI_MODE="${HYPERLANE_CLI_MODE:-npm}"
fi
```

---

#### 4.2 Missing Prereq: jq (Not Checked)

**Current Implementation:**
```bash
require_prereqs() {
  require_cmd git "clone Hyperlane repo"
  require_cmd anvil "run local EVM chain" "brew install foundry"
  require_cmd cast "fund accounts / debug contracts" "brew install foundry"
  require_cmd node "run Hyperlane CLI" "brew install node"
  require_cmd pnpm "run Hyperlane CLI" "npm i -g pnpm"
  require_cmd cargo "build Hyperlane agents"
  require_cmd python3 "write configs / parse json"
  require_cmd curl "readiness checks"
}
```

**Issue:**
- `jq` is mentioned in Hyperlane README as required
- Not checked by this script
- Hyperlane CLI might need it

**Severity:** LOW - might cause cryptic errors

**Recommendation:**
```bash
require_cmd jq "parse JSON data" "brew install jq"
```

---

#### 4.3 Node Version Check Missing (Lines 522-526)

**Current Implementation:**
```bash
local node_ver
node_ver="$(node -v 2>/dev/null || true)"
if [[ "${node_ver}" != v20* ]]; then
  log_warn "Hyperlane recommends Node v20 (.nvmrc); current node=${node_ver} (if build fails, run: nvm use 20)"
fi
```

**Issue:**
- Only a warning, not enforced
- Could lead to subtle build failures
- No `.nvmrc` check

**Severity:** LOW - already has warning

**Recommendation:**
Add stricter check in `require_prereqs()`:
```bash
check_node_version() {
  local node_ver
  node_ver="$(node -v 2>/dev/null || echo "none")"
  if [[ "${node_ver}" != v20* ]]; then
    log_error "Hyperlane requires Node v20; current: ${node_ver}"
    if [[ -f "${HYP_REPO}/.nvmrc" ]]; then
      local recommended
      recommended="$(cat "${HYP_REPO}/.nvmrc" | tr -d 'v\r\n')"
      log_warn "Install hint: nvm install ${recommended} && nvm use ${recommended}"
    else
      log_warn "Install hint: nvm install 20 && nvm use 20"
    fi
    exit 1
  fi
}
```

---

### 5. Code Quality Issues

#### 5.1 Magic Numbers (Throughout)

**Current Implementation:**
```bash
ANVIL_CHAIN_ID="31337"  # Line 348
KASPA_DOMAIN_ID="7"     # Line 353
# Hardcoded ports:
# 8545 (Anvil)
# 9910-9911 (validator metrics)
# 9920-9922 (relayer metrics)
# 8088-8090 (Igra RPC)
```

**Issue:**
- Domain IDs hardcoded without explanation
- Why is Kaspa domain 7?
- Why Anvil domain 31337?

**Severity:** LOW - but impacts understanding

**Recommendation:**
Add comments explaining the choices:
```bash
# Anvil uses its chain ID as domain ID (Hyperlane convention for EVM test chains)
ANVIL_CHAIN_ID="31337"
ANVIL_DOMAIN_ID="31337"
# Hyperlane agent crates map domain 31337 to chain name "test4"
ANVIL_DOMAIN_NAME="test4"

# Kaspa domain ID (registered in Hyperlane domain registry)
# See: https://github.com/hyperlane-xyz/hyperlane-registry or local registry
KASPA_DOMAIN_ID="7"
```

---

#### 5.2 Incomplete Status Display (Lines 994-1014)

**Current Implementation:**
```bash
status() {
  log_info "Igra devnet status:"
  run "${IGRA_RUNNER}" --root "${RUN_ROOT}" status || true

  log_info "Hyperlane status (root: ${HYP_ROOT})"
  local processes=(anvil validator-1 validator-2 relayer-1 relayer-2 relayer-3)
  for name in "${processes[@]}"; do
    local pid_file="${HYP_PIDS_DIR}/${name}.pid"
    if [[ -f "${pid_file}" ]]; then
      local pid
      pid=$(cat "${pid_file}" 2>/dev/null || true)
      if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
        log_success "${name} running pid=${pid}"
      else
        log_warn "${name} pidfile present but not running pid=${pid}"
      fi
    else
      log_warn "${name} not running"
    fi
  done
}
```

**Missing:**
- Port status (which ports are in use)
- Metrics endpoints availability
- Contract deployment status
- No uptime info

**Recommendation:**
```bash
status() {
  log_info "Igra devnet status:"
  run "${IGRA_RUNNER}" --root "${RUN_ROOT}" status || true

  log_info "Hyperlane status (root: ${HYP_ROOT})"

  # Anvil
  local pid_file="${HYP_PIDS_DIR}/anvil.pid"
  if [[ -f "${pid_file}" ]]; then
    local pid=$(cat "${pid_file}" 2>/dev/null || true)
    if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
      log_success "anvil running pid=${pid} port=8545"
      # Check if RPC is responding
      if curl -s -f -X POST "${ANVIL_RPC_URL}" -H 'content-type: application/json' \
        --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' >/dev/null 2>&1; then
        log_success "  RPC responding at ${ANVIL_RPC_URL}"
      else
        log_warn "  RPC not responding at ${ANVIL_RPC_URL}"
      fi
    else
      log_warn "anvil pidfile present but not running"
    fi
  else
    log_warn "anvil not running"
  fi

  # Validators
  for idx in 1 2; do
    local pid_file="${HYP_PIDS_DIR}/validator-${idx}.pid"
    local metrics_port="$((9909 + idx))"
    if [[ -f "${pid_file}" ]]; then
      local pid=$(cat "${pid_file}" 2>/dev/null || true)
      if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
        log_success "validator-${idx} running pid=${pid} metrics=:${metrics_port}"
        if curl -s -f "http://127.0.0.1:${metrics_port}/metrics" >/dev/null 2>&1; then
          log_success "  Metrics responding"
        else
          log_warn "  Metrics not responding"
        fi
      else
        log_warn "validator-${idx} pidfile present but not running"
      fi
    else
      log_warn "validator-${idx} not running"
    fi
  done

  # Relayers
  for idx in 1 2 3; do
    local pid_file="${HYP_PIDS_DIR}/relayer-${idx}.pid"
    local metrics_port="$((9919 + idx))"
    if [[ -f "${pid_file}" ]]; then
      local pid=$(cat "${pid_file}" 2>/dev/null || true)
      if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
        log_success "relayer-${idx} running pid=${pid} metrics=:${metrics_port}"
        if curl -s -f "http://127.0.0.1:${metrics_port}/metrics" >/dev/null 2>&1; then
          log_success "  Metrics responding"
        else
          log_warn "  Metrics not responding"
        fi
      else
        log_warn "relayer-${idx} pidfile present but not running"
      fi
    else
      log_warn "relayer-${idx} not running"
    fi
  done

  # Contract deployment status
  local addresses_yaml="${HYP_REGISTRY}/chains/anvil1/addresses.yaml"
  if [[ -f "${addresses_yaml}" ]]; then
    local mailbox=$(read_yaml_key "${addresses_yaml}" "mailbox")
    log_success "Core contracts deployed mailbox=${mailbox}"
  else
    log_warn "Core contracts not deployed"
  fi
}
```

---

### 6. Documentation Issues

#### 6.1 Missing Comments on Kaspa-Specific Config (Lines 909-921)

**Current Implementation:**
```python
"kaspa": {
  "name": "kaspa",
  "domainId": ${KASPA_DOMAIN_ID},
  "protocol": "kaspa",
  "rpcUrls": [{"http": kaspa_rpc_url}],
  "mailbox": kaspa_group_h256,
  "interchainGasPaymaster": kaspa_group_h256,
  "validatorAnnounce": kaspa_group_h256,
  "merkleTreeHook": kaspa_group_h256,
  "blocks": { "estimateBlockTime": 1, "reorgPeriod": 1 },
  "index": { "from": 0, "chunk": 1999, "mode": "sequence" },
}
```

**Missing:**
- Why all contract addresses point to `group_h256`?
- What is `mode: "sequence"` vs `mode: "block"`?
- Why `chunk: 1999`?

**Recommendation:**
Add comments:
```python
"kaspa": {
  "name": "kaspa",
  "domainId": ${KASPA_DOMAIN_ID},
  "protocol": "kaspa",
  "rpcUrls": [{"http": kaspa_rpc_url}],
  # Kaspa uses Igra group ID as the "contract address" for all Hyperlane components.
  # The group_id acts as a pseudo-address for the threshold multisig group.
  "mailbox": kaspa_group_h256,
  "interchainGasPaymaster": kaspa_group_h256,
  "validatorAnnounce": kaspa_group_h256,
  "merkleTreeHook": kaspa_group_h256,
  # Kaspa targets ~1 second block time
  "blocks": { "estimateBlockTime": 1, "reorgPeriod": 1 },
  # Index mode "sequence" uses Igra event sequence numbers instead of block numbers.
  # Chunk size 1999 is well below the typical RPC response size limit.
  "index": { "from": 0, "chunk": 1999, "mode": "sequence" },
}
```

---

#### 6.2 Unclear Script Purpose (Lines 4-10)

**Current Implementation:**
```bash
# Local EVM+Hyperlane devnet runner:
# - Starts existing Kaspa+Igra devnet (via run_local_devnet.sh) without fake-hyperlane
# - Starts an Anvil node
# - Clones/builds the Hyperlane fork
# - Deploys Hyperlane core contracts to Anvil
# - Starts 2 validators (threshold=2) with local checkpoint storage + on-chain announce
# - Starts 3 relayers targeting the 3 Igra RPC instances
```

**Missing:**
- What is the message flow? (EVM → Kaspa or bidirectional?)
- What is Avail? (mentioned in filename but not explained)
- How does this differ from `run_local_devnet.sh`?

**Recommendation:**
```bash
# Local EVM+Hyperlane+Kaspa+Igra Devnet Runner
#
# PURPOSE:
#   Full integration test environment for cross-chain messaging between Anvil (EVM) and Kaspa.
#   Messages flow: Anvil (EVM) → Hyperlane Validators → Hyperlane Relayers → Igra (Kaspa threshold multisig).
#
# ARCHITECTURE:
#   1. Kaspa devnet (kaspad + 3 Igra threshold signers)
#   2. Anvil EVM chain (local Ethereum testnet)
#   3. Hyperlane core contracts deployed to Anvil
#   4. Hyperlane validators (2-of-2) monitoring Anvil chain
#   5. Hyperlane relayers (3) delivering messages to Igra
#
# COMPONENTS STARTED:
#   - kaspad (Kaspa node)
#   - kaspaminer (block production)
#   - igra-signer-1, igra-signer-2, igra-signer-3 (threshold multisig)
#   - anvil (EVM chain)
#   - validator-1, validator-2 (Hyperlane validators)
#   - relayer-1, relayer-2, relayer-3 (Hyperlane relayers)
#
# NOTES:
#   - "Avail" in filename is historical; currently focuses on Hyperlane integration
#   - Uses local checkpoint syncers (file://) for validators (devnet only, not production-safe)
#   - Hyperlane fork required: https://github.com/reshmem/hyperlane-monorepo.git (branch: devel)
```

---

### 7. Best Practices Violations

#### 7.1 Direct Modification of User Cargo/pnpm State (Lines 106-134)

**Current Implementation:**
```bash
prepare_cargo_dirs() {
  # Force Cargo to use a directory under `--root` to avoid user-global config pointing at
  # unavailable locations (e.g. `/Volumes/...`), and to keep devnet reproducible.
  run mkdir -p "${HYP_ROOT}/cargo-home"
}
```

**Issue:**
The comment explains isolation, but the function only creates the directory and doesn't actually set `CARGO_HOME`.

**Severity:** MEDIUM - affects reproducibility

**Recommendation:**
Actually use the isolated Cargo home:
```bash
prepare_cargo_dirs() {
  run mkdir -p "${HYP_ROOT}/cargo-home"
  export CARGO_HOME="${HYP_ROOT}/cargo-home"
  log_info "Using isolated CARGO_HOME=${CARGO_HOME}"
}
```

Same issue with pnpm - `prepare_pnpm_dirs()` creates directories but `run_pnpm()` actually uses them. Consider making this more explicit:
```bash
# Call prepare_pnpm_dirs early, then all run_pnpm calls automatically use isolated dirs
prepare_pnpm_dirs
export PNPM_HOME="${HYP_ROOT}/pnpm-home"
# etc.
```

---

#### 7.2 Validator Checkpoint Syncer Security Warning (Line 806)

**Current Implementation:**
```python
"checkpointSyncer": { "type": "localStorage", "path": checkpoints },
```

**Issue:**
- No warning that this is devnet-only
- Production validators should use S3 or GCS
- Local storage checkpoints are not shared (validators can't see each other's checkpoints)

**Severity:** LOW - documentation

**Recommendation:**
Add comment in script:
```bash
write_validator_config() {
  # ...
  # NOTE: localStorage checkpoint syncer is for devnet ONLY.
  # Production validators must use S3, GCS, or another shared storage backend
  # so that relayers can fetch checkpoints from all validators.
```

And add comment in generated JSON:
```python
cfg = {
  # ...
  # DEVNET ONLY: localStorage is not suitable for production.
  # Validators need shared checkpoint storage (S3/GCS) so relayers can fetch from all validators.
  "checkpointSyncer": { "type": "localStorage", "path": checkpoints },
```

---

#### 7.3 Relayer Config: Kaspa Chain Missing Critical Fields (Lines 909-921)

**Current Implementation:**
```python
"kaspa": {
  "name": "kaspa",
  "domainId": ${KASPA_DOMAIN_ID},
  "protocol": "kaspa",
  "rpcUrls": [{"http": kaspa_rpc_url}],
  "mailbox": kaspa_group_h256,
  "interchainGasPaymaster": kaspa_group_h256,
  "validatorAnnounce": kaspa_group_h256,
  "merkleTreeHook": kaspa_group_h256,
  "blocks": { "estimateBlockTime": 1, "reorgPeriod": 1 },
  "index": { "from": 0, "chunk": 1999, "mode": "sequence" },
}
```

**Missing:**
- No `signer` field (does Kaspa need one for relayer to submit transactions?)
- Confirm with Hyperlane Rust code if Kaspa protocol requires special fields

**Severity:** UNKNOWN - need to verify with hyperlane-kaspa integration

**Recommendation:**
Check `hyperlane-monorepo/rust/main/chains/hyperlane-kaspa` (if exists) or the integration code for required config fields.

---

### 8. Improvement Opportunities

#### 8.1 Add Cleanup Trap (Missing)

**Current Implementation:**
No trap to cleanup processes if script is interrupted during startup.

**Issue:**
If script fails or is Ctrl+C'd during agent startup, processes are left running.

**Severity:** LOW - operator can manually clean up

**Recommendation:**
```bash
cleanup() {
  if [[ ${#PIDS[@]} -gt 0 ]]; then
    log_warn "Script interrupted; stopping ${#PIDS[@]} processes..."
    for pid in "${PIDS[@]}"; do
      kill "${pid}" >/dev/null 2>&1 || true
    done
  fi
}
trap cleanup EXIT INT TERM

PIDS=()
# When starting processes, add to PIDS array
```

---

#### 8.2 No Smoke Test After Startup (Missing)

**Current Implementation:**
Starts all components but doesn't verify end-to-end functionality.

**Recommendation:**
Add optional smoke test:
```bash
smoke_test() {
  log_info "Running smoke test (send 1 message and verify delivery)"

  # Send test message
  send_messages --count 1 --amount-sompi 10000000

  # Wait for delivery (check Igra logs or RPC)
  log_info "Waiting for message delivery..."
  local max_wait=60
  for i in $(seq 1 ${max_wait}); do
    # Query Igra for recent events
    # Check if message was delivered
    # If yes, break
    sleep 1
  done

  log_success "Smoke test passed"
}

# Add to default/start commands:
case "${COMMAND}" in
  default)
    start_igra_devnet_default
    start_anvil
    start_hyperlane_agents
    if [[ "${SKIP_SMOKE_TEST:-false}" != "true" ]]; then
      smoke_test
    fi
    ;;
esac
```

---

#### 8.3 Build Caching Not Optimal (Lines 565-580)

**Current Implementation:**
```bash
build_hyperlane() {
  ensure_hyperlane_repo
  verify_hyperlane_kaspa_support
  ensure_hyperlane_generated_bindings
  prepare_cargo_dirs

  if [[ "${HYPERLANE_CLI_MODE}" == "repo" ]]; then
    prepare_pnpm_dirs
    log_info "Installing Hyperlane JS deps (pnpm install)"
    run_pnpm -C "${HYP_REPO}" install
  fi

  log_info "Building Hyperlane Rust agents (validator + relayer)"
  run bash -lc "cd \"${HYP_REPO}/rust/main\" && CARGO_HOME=\"${HYP_ROOT}/cargo-home\" CARGO_TARGET_DIR=\"${HYP_TARGET_DIR}\" RUSTC_WRAPPER= SCCACHE_DISABLE=1 cargo build --release -p validator"
  run bash -lc "cd \"${HYP_REPO}/rust/main\" && CARGO_HOME=\"${HYP_ROOT}/cargo-home\" CARGO_TARGET_DIR=\"${HYP_TARGET_DIR}\" RUSTC_WRAPPER= SCCACHE_DISABLE=1 cargo build --release -p relayer --features kaspa"
}
```

**Issue:**
- Builds validator and relayer in separate commands (rebuilds shared dependencies twice)
- Uses `bash -lc` which loads login profile (unnecessary overhead)

**Recommendation:**
```bash
build_hyperlane() {
  # ... setup ...

  log_info "Building Hyperlane Rust agents (validator + relayer)"
  # Build both in one command to share dependency builds
  run env \
    CARGO_HOME="${HYP_ROOT}/cargo-home" \
    CARGO_TARGET_DIR="${HYP_TARGET_DIR}" \
    RUSTC_WRAPPER= \
    SCCACHE_DISABLE=1 \
    cargo build --release \
      --manifest-path "${HYP_REPO}/rust/main/Cargo.toml" \
      -p validator \
      -p relayer --features kaspa

  # Verify binaries exist
  if [[ "${DRY_RUN}" != "true" ]]; then
    if [[ ! -x "${HYP_TARGET_DIR}/release/validator" ]]; then
      log_error "validator binary not found after build"
      exit 1
    fi
    if [[ ! -x "${HYP_TARGET_DIR}/release/relayer" ]]; then
      log_error "relayer binary not found after build"
      exit 1
    fi
  fi
}
```

---

## Minor Issues

### 9.1 Inconsistent Error Messages

Some errors use `log_error` and `exit 1`, others use `return 1`. Be consistent:

```bash
# Good pattern (used in most places):
if [[ ! -f "${file}" ]]; then
  log_error "Missing ${file}"
  exit 1
fi

# Inconsistent (line 447):
if [[ ! -f "${cargo_toml}" ]]; then
  log_error "Missing relayer Cargo.toml at ${cargo_toml}"
  exit 1
fi
```

This is actually already consistent! Good.

---

### 9.2 Git Safety (Lines 413-439)

**Current Implementation:**
```bash
if [[ -n "${dirty}" ]]; then
  log_warn "Hyperlane checkout is dirty; discarding local changes to keep devnet reproducible repo=${HYP_REPO}"
  if [[ "${DRY_RUN}" != "true" ]]; then
    run git -C "${HYP_REPO}" reset --hard
    run git -C "${HYP_REPO}" clean -fd
  fi
fi
```

**Issue:**
Silently discards uncommitted work without confirmation.

**Severity:** LOW - devnet script, but could surprise users

**Recommendation:**
Add confirmation for interactive sessions:
```bash
if [[ -n "${dirty}" ]]; then
  log_warn "Hyperlane checkout is dirty; local changes will be discarded to keep devnet reproducible repo=${HYP_REPO}"
  if [[ -t 0 && "${DRY_RUN}" != "true" ]]; then
    read -p "Continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      log_error "Cancelled by user"
      exit 1
    fi
  fi
  if [[ "${DRY_RUN}" != "true" ]]; then
    run git -C "${HYP_REPO}" reset --hard
    run git -C "${HYP_REPO}" clean -fd
  fi
fi
```

Or add `--force` flag to skip confirmation.

---

## Hyperlane Integration Best Practices

### 10.1 allowLocalCheckpointSyncers (Line 888) ✅

**Current Implementation:**
```python
"allowLocalCheckpointSyncers": True,
```

**Assessment:** CORRECT

This is a required flag for using `localStorage` checkpoint syncers. From `relayer/src/settings/mod.rs:64`:
```rust
/// If true, allows local storage based checkpoint syncers.
/// Not intended for production use.
pub allow_local_checkpoint_syncers: bool,
```

**Note:** This is correctly documented as devnet-only (line 69 of script).

---

### 10.2 Validator Config Structure ✅

**Current Implementation (Lines 800-830):**
Uses correct Hyperlane agent JSON schema:
- `originChainName`: Correct (must match domain name)
- `validator.type: hexKey`: Correct for local devnet
- `checkpointSyncer.type: localStorage`: Correct for devnet
- `chains.<name>`: Correct structure

**Assessment:** Matches Hyperlane expectations.

---

### 10.3 Relayer Config Structure ✅

**Current Implementation (Lines 883-927):**
- `relayChains`: Correct comma-separated list
- `allowLocalCheckpointSyncers`: Required for localStorage
- `chains` object: Correct structure
- Anvil uses `submitter: Classic`: Reasonable for devnet

**Assessment:** Looks good.

---

## Recommendations Summary

### High Priority
1. ✅ Add health checks for validators and relayers (after startup, verify metrics endpoints respond)
2. ✅ Use env var for secrets passphrase instead of CLI arg (security)
3. ⚠️ Verify Kaspa chain config completeness (check if `signer` field needed)

### Medium Priority
4. ✅ Move Python code to external files or add better error handling
5. ✅ Add validator funding balance check (skip if already funded)
6. ✅ Make validator/relayer counts configurable
7. ✅ Export CARGO_HOME in prepare_cargo_dirs (actually use isolated environment)

### Low Priority
8. ✅ Add `jq` to prereqs
9. ✅ Improve status command (show ports, metrics availability, contract deployment)
10. ✅ Add comments explaining Kaspa-specific config
11. ✅ Add smoke test (optional, via flag)
12. ✅ Build validator + relayer in one cargo command (faster)
13. ✅ Add git reset confirmation for interactive sessions

---

## Conclusion

**Overall Quality: 8/10**

The script is well-written, handles edge cases properly, and integrates correctly with Hyperlane. The main areas for improvement are:

1. **Health checks** for Hyperlane agents
2. **Better error messages** for Python inline code
3. **Documentation** of Kaspa-specific configuration

**Production Readiness (for devnet):** Ready to use, with recommended improvements for better debugging and reliability.

**Security:** Good for devnet. Secrets passphrase should use env var instead of CLI arg.

**Maintainability:** Good structure, but Python inline code is hard to debug. Consider extracting to separate files.
