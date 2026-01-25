#!/usr/bin/env bash
set -euo pipefail

# Local EVM+Hyperlane devnet runner:
# - Starts existing Kaspa+Igra devnet (via run_local_devnet.sh) without fake-hyperlane
# - Starts an Anvil node
# - Clones/builds the Hyperlane fork
# - Deploys Hyperlane core contracts to Anvil
# - Starts 2 validators (threshold=2) with local checkpoint storage + on-chain announce
# - Starts 3 relayers targeting the 3 Igra RPC instances

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

log() {
  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  echo -e "${COLOR_GRAY}[${timestamp}]${COLOR_RESET} $*"
}

log_info() { log "${COLOR_BLUE}ℹ${COLOR_RESET} $*"; }
log_success() { log "${COLOR_GREEN}✓${COLOR_RESET} $*"; }
log_warn() { log "${COLOR_YELLOW}⚠${COLOR_RESET} $*" >&2; }
log_error() { log "${COLOR_RED}✗${COLOR_RESET} $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEVNET_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
IGRA_RUNNER="${SCRIPT_DIR}/run_local_devnet.sh"
REPO_ROOT="$(cd "${DEVNET_DIR}/../../../.." && pwd)"

usage() {
  cat <<'EOF'
Usage: run_local_devnet_with_avail_and_hyperlane.sh [--build clone|local] [--root PATH] [--secrets-passphrase PASS] [--dry-run] [help|default|start|stop|restart|status|clean|send]

Commands:
  default   Build+stage+generate keys/configs, then start everything (Igra+Anvil+Hyperlane agents).
  start     Start everything (assumes configs exist; may still build Hyperlane).
  stop      Stop everything (Hyperlane agents + Anvil + Igra devnet).
  restart   Stop then start.
  status    Show status.
  clean     Remove all data under --root.
  send      Dispatch messages on Anvil Mailbox (requires core deployed).

Options:
  --build clone|local   Passed through to `run_local_devnet.sh` for Igra devnet.
  --root PATH          Root working dir (default: $(pwd)/igra_devnet)
  --secrets-passphrase PASS  Passed through to `run_local_devnet.sh` (otherwise auto-generated and stored under config/).
  --dry-run            Print actions without executing.

Send options:
  --count N            Number of dispatches (default: 1)
  --amount-sompi N     Amount embedded in body (default: 20000000)

Notes:
  - Uses Anvil domain id 31337 and Kaspa domain id 7.
  - Uses local checkpoint syncers (file://) and requires `allowLocalCheckpointSyncers=true` in relayer config.
  - Hyperlane fork: https://github.com/reshmem/hyperlane-monorepo.git (branch: devel)
EOF
}

BUILD_MODE="clone"
DRY_RUN=false
ROOT_ARG=""
SECRETS_PASSPHRASE_ARG=""
COMMAND=""
SEND_COUNT=1
SEND_AMOUNT_SOMPI=20000000
POSITIONAL=()

require_cmd() {
  local cmd="$1"
  local reason="${2:-required}"
  local install_hint="${3:-}"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    log_error "Required command '${cmd}' not found (context: ${reason})"
    if [[ -n "${install_hint}" ]]; then
      log_warn "Install hint: ${install_hint}"
    fi
    exit 1
  fi
}

run() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    local -a redacted=()
    local prev=""
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
    log_info "[DRY-RUN] ${redacted[*]}"
    return 0
  fi
  "$@"
}

start_process() {
  local name="$1"
  shift
  local pid_file="${HYP_PIDS_DIR}/${name}.pid"
  local log_file="${HYP_LOG_DIR}/${name}.log"
  mkdir -p "${HYP_PIDS_DIR}" "${HYP_LOG_DIR}"

  if [[ -f "${pid_file}" ]]; then
    local pid
    pid=$(cat "${pid_file}" 2>/dev/null || true)
    if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
      log_info "${name} already running (pid ${pid})"
      return 0
    fi
    rm -f "${pid_file}"
  fi

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] start ${name}: $*"
    return 0
  fi

  log_info "Starting ${name}..."
  ("$@" >"${log_file}" 2>&1 & echo $! >"${pid_file}")
  local pid
  pid=$(cat "${pid_file}")
  log_success "${name} started (pid ${pid}); log: ${log_file}"
}

stop_process() {
  local name="$1"
  local pid_file="${HYP_PIDS_DIR}/${name}.pid"
  if [[ ! -f "${pid_file}" ]]; then
    return 0
  fi
  local pid
  pid=$(cat "${pid_file}" 2>/dev/null || true)
  rm -f "${pid_file}"
  if [[ -z "${pid}" ]]; then
    return 0
  fi
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] stop ${name} pid=${pid}"
    return 0
  fi
  if kill -0 "${pid}" >/dev/null 2>&1; then
    log_info "Stopping ${name} (pid ${pid})..."
    kill "${pid}" >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do
      if ! kill -0 "${pid}" >/dev/null 2>&1; then
        log_success "${name} stopped"
        return 0
      fi
      sleep 0.2
    done
    log_warn "${name} did not stop gracefully; killing"
    kill -9 "${pid}" >/dev/null 2>&1 || true
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --build)
      case "${2:-}" in
        clone|local) BUILD_MODE="$2"; shift 2 ;;
        *) echo "Unknown --build value: ${2:-<missing>} (expected clone|local)" >&2; usage; exit 1 ;;
      esac
      ;;
    --root) ROOT_ARG="${2:-}"; shift 2 ;;
    --secrets-passphrase=*)
      SECRETS_PASSPHRASE_ARG="${1#*=}"
      shift
      ;;
    --secrets-passphrase)
      SECRETS_PASSPHRASE_ARG="${2:-}"
      shift 2
      ;;
    --count) SEND_COUNT="${2:-}"; shift 2 ;;
    --amount-sompi) SEND_AMOUNT_SOMPI="${2:-}"; shift 2 ;;
    help|default|start|stop|restart|status|clean|send)
      if [[ -z "${COMMAND}" ]]; then
        COMMAND="$1"
      else
        POSITIONAL+=("$1")
      fi
      shift
      ;;
    -h|--help) usage; exit 0 ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done

COMMAND="${COMMAND:-${POSITIONAL[0]:-}}"
if [[ -z "${COMMAND}" ]]; then
  usage
  exit 0
fi

RUN_ROOT="${ROOT_ARG:-$(pwd)/igra_devnet}"
HYP_ROOT="${RUN_ROOT}/hyperlane"
HYP_LOG_DIR="${HYP_ROOT}/logs"
HYP_PIDS_DIR="${HYP_ROOT}/pids"
HYP_REGISTRY="${HYP_ROOT}/registry"
HYP_CORE_DIR="${HYP_ROOT}/core"
HYP_ANVIL_STATE="${HYP_ROOT}/anvil/state"
HYP_SOURCES="${RUN_ROOT}/sources"
HYP_REPO="${HYP_SOURCES}/hyperlane-monorepo"
HYP_TARGET_DIR="${RUN_ROOT}/target-hyperlane"

ANVIL_RPC_URL="http://127.0.0.1:8545"
ANVIL_CHAIN_ID="31337"
ANVIL_DOMAIN_ID="31337"
KASPA_DOMAIN_ID="7"
HYPERLANE_REF="devel"
HYPERLANE_REPO_URL="https://github.com/reshmem/hyperlane-monorepo.git"

if [[ -n "${SECRETS_PASSPHRASE_ARG}" && -z "${SECRETS_PASSPHRASE_ARG//[[:space:]]/}" ]]; then
  log_error "--secrets-passphrase must not be empty"
  exit 1
fi

igra_runner_args() {
  local -a args=()
  args+=(--build "${BUILD_MODE}" --root "${RUN_ROOT}" --no-fake-hyperlane)
  if [[ -n "${SECRETS_PASSPHRASE_ARG}" ]]; then
    args+=(--secrets-passphrase "${SECRETS_PASSPHRASE_ARG}")
  fi
  printf '%s\0' "${args[@]}"
}

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

read_json_field() {
  local file="$1"
  local py_expr="$2"
  python3 - <<PY
import json
path = r"""${file}"""
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
try:
    val = ${py_expr}
except Exception as e:
    raise SystemExit(f"missing field in {path}: {e}")
print(val)
PY
}

read_yaml_key() {
  local file="$1"
  local key="$2"
  if [[ ! -f "${file}" ]]; then
    echo "" >&2
    return 1
  fi
  local line=""
  line=$(grep -E "^${key}:" "${file}" 2>/dev/null | head -n 1 | sed -E "s/^${key}:[[:space:]]*//")
  line=$(echo "${line}" | sed -E "s/[\"']//g" | tr -d '\r')
  echo "${line}"
}

ensure_hyperlane_repo() {
  mkdir -p "${HYP_SOURCES}"
  if [[ -d "${HYP_REPO}/.git" ]]; then
    log_info "Updating Hyperlane repo at ${HYP_REPO}"
    run git -C "${HYP_REPO}" fetch --all --prune
    run git -C "${HYP_REPO}" checkout "${HYPERLANE_REF}"
    run git -C "${HYP_REPO}" pull --ff-only || true
  else
    log_info "Cloning Hyperlane repo into ${HYP_REPO}"
    run git clone --branch "${HYPERLANE_REF}" --depth 1 "${HYPERLANE_REPO_URL}" "${HYP_REPO}"
  fi
}

ensure_relayer_kaspa_feature() {
  local cargo_toml="${HYP_REPO}/rust/main/agents/relayer/Cargo.toml"
  if [[ ! -f "${cargo_toml}" ]]; then
    log_error "Missing relayer Cargo.toml at ${cargo_toml}"
    exit 1
  fi
  if grep -E '^[[:space:]]*kaspa[[:space:]]*=' "${cargo_toml}" >/dev/null 2>&1; then
    return 0
  fi
  log_warn "Hyperlane relayer missing kaspa feature; patching local checkout (root-scoped) to enable hyperlane-base/kaspa"
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] Would patch ${cargo_toml}"
    return 0
  fi
  CARGO_TOML="${cargo_toml}" python3 - <<'PY'
from __future__ import annotations
from pathlib import Path

path = Path(__import__("os").environ["CARGO_TOML"])
text = path.read_text(encoding="utf-8").splitlines(True)

out: list[str] = []
in_features = False
inserted = False
for line in text:
    if line.strip() == "[features]":
        in_features = True
        out.append(line)
        continue
    if in_features and line.startswith("[") and line.strip().startswith("[") and line.strip().endswith("]") and line.strip() != "[features]":
        if not inserted:
            out.append('kaspa = ["hyperlane-base/kaspa"]\n')
            inserted = True
        in_features = False
        out.append(line)
        continue
    out.append(line)

if in_features and not inserted:
    out.append('kaspa = ["hyperlane-base/kaspa"]\n')
    inserted = True

if not inserted:
    raise SystemExit("failed to insert kaspa feature")

path.write_text("".join(out), encoding="utf-8")
PY
}

build_hyperlane() {
  ensure_hyperlane_repo
  ensure_relayer_kaspa_feature

  log_info "Installing Hyperlane JS deps (pnpm install)"
  run pnpm -C "${HYP_REPO}" install

  log_info "Building Hyperlane Rust agents (validator + relayer)"
  run bash -lc "cd \"${HYP_REPO}/rust/main\" && CARGO_TARGET_DIR=\"${HYP_TARGET_DIR}\" cargo build --release -p validator"
  run bash -lc "cd \"${HYP_REPO}/rust/main\" && CARGO_TARGET_DIR=\"${HYP_TARGET_DIR}\" cargo build --release -p relayer --features kaspa"
}

start_igra_devnet_default() {
  # Use Anvil domain id for hyperlane.domains[0].domain in Igra config generation.
  local -a args=()
  while IFS= read -r -d '' v; do args+=("${v}"); done < <(igra_runner_args)
  run env HYPERLANE_DOMAIN="${ANVIL_DOMAIN_ID}" "${IGRA_RUNNER}" "${args[@]}" default
}

start_igra_devnet_start() {
  local -a args=()
  while IFS= read -r -d '' v; do args+=("${v}"); done < <(igra_runner_args)
  run "${IGRA_RUNNER}" "${args[@]}" start all
}

stop_igra_devnet() {
  run "${IGRA_RUNNER}" --root "${RUN_ROOT}" stop all
}

start_anvil() {
  mkdir -p "${HYP_ANVIL_STATE}"
  start_process "anvil" anvil -p 8545 --chain-id "${ANVIL_CHAIN_ID}" --state "${HYP_ANVIL_STATE}" --gas-price 1

  if [[ "${DRY_RUN}" == "true" ]]; then
    return 0
  fi
  log_info "Waiting for Anvil JSON-RPC at ${ANVIL_RPC_URL}"
  for _ in $(seq 1 30); do
    if curl -s -f -X POST "${ANVIL_RPC_URL}" -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' >/dev/null 2>&1; then
      log_success "Anvil is ready"
      return 0
    fi
    sleep 0.5
  done
  log_error "Anvil did not become ready"
  exit 1
}

prepare_registry() {
  mkdir -p "${HYP_REGISTRY}/chains/anvil1"
  mkdir -p "${HYP_CORE_DIR}"
  local src_meta="${HYP_REPO}/typescript/cli/test-configs/anvil/chains/anvil1/metadata.yaml"
  local dst_meta="${HYP_REGISTRY}/chains/anvil1/metadata.yaml"
  if [[ ! -f "${src_meta}" ]]; then
    log_error "Missing anvil metadata.yaml in Hyperlane repo: ${src_meta}"
    exit 1
  fi
  run cp -f "${src_meta}" "${dst_meta}"
}

deploy_hyperlane_core() {
  prepare_registry

  local keyset_json="${RUN_ROOT}/config/devnet-keys.json"
  if [[ ! -f "${keyset_json}" ]]; then
    log_error "Missing ${keyset_json}; run 'default' first"
    exit 1
  fi
  local evm_priv
  evm_priv="$(read_json_field "${keyset_json}" "data['evm']['private_key_hex']")"
  local evm_addr
  evm_addr="$(read_json_field "${keyset_json}" "data['evm']['address_hex']")"
  if [[ -z "${evm_priv}" || -z "${evm_addr}" ]]; then
    log_error "Missing evm fields in ${keyset_json}; regenerate keys with updated devnet-keygen"
    exit 1
  fi

  local core_cfg="${HYP_CORE_DIR}/core-config.yaml"
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] Would write ${core_cfg}"
  else
    cat >"${core_cfg}" <<EOF
owner: "0x${evm_addr}"
defaultIsm:
  type: "testIsm"
  threshold: 1
  validators:
    - "0x${evm_addr}"
defaultHook:
  type: protocolFee
  maxProtocolFee: "1000000000000000000"
  protocolFee: "200000000000000"
  beneficiary: "0x${evm_addr}"
  owner: "0x${evm_addr}"
requiredHook:
  type: protocolFee
  maxProtocolFee: "1000000000000000000"
  protocolFee: "200000000000000"
  beneficiary: "0x${evm_addr}"
  owner: "0x${evm_addr}"
EOF
  fi

  # Reset core deployment outputs (addresses.yaml) so deploy is deterministic and idempotent.
  run rm -rf "${HYP_REGISTRY}/deployments" || true
  run rm -f "${HYP_REGISTRY}/chains/anvil1/addresses.yaml" || true

  log_info "Deploying Hyperlane core contracts to Anvil (this may take a bit)..."
  run pnpm -C "${HYP_REPO}" --filter @hyperlane-xyz/cli run hyperlane core deploy \
    --registry "${HYP_REGISTRY}" \
    --config "${core_cfg}" \
    --chain anvil1 \
    --key "0x${evm_priv}" \
    --verbosity debug \
    --yes

  local addresses_yaml="${HYP_REGISTRY}/chains/anvil1/addresses.yaml"
  if [[ "${DRY_RUN}" == "true" ]]; then
    return 0
  fi
  if [[ ! -f "${addresses_yaml}" ]]; then
    log_error "core deploy did not produce ${addresses_yaml}"
    exit 1
  fi
  log_success "Core deployed; addresses written to ${addresses_yaml}"
}

fund_validator_accounts() {
  local keys_json="${RUN_ROOT}/config/hyperlane-keys.json"
  local keyset_json="${RUN_ROOT}/config/devnet-keys.json"
  if [[ ! -f "${keys_json}" || ! -f "${keyset_json}" ]]; then
    log_error "Missing keys under ${RUN_ROOT}/config; run 'default' first"
    exit 1
  fi

  local evm_priv
  evm_priv="$(read_json_field "${keyset_json}" "data['evm']['private_key_hex']")"

  for idx in 0 1; do
    local vpriv
    vpriv="$(read_json_field "${keys_json}" "data['validators'][${idx}]['private_key_hex']")"
    local vaddr
    vaddr="$(cast wallet address --private-key "0x${vpriv}" 2>/dev/null | tr -d '\r' | tr 'A-Z' 'a-z')"
    if [[ -z "${vaddr}" ]]; then
      log_error "Failed to derive validator address for validator index ${idx}"
      exit 1
    fi
    log_info "Funding validator-${idx} address=${vaddr}"
    run cast send --private-key "0x${evm_priv}" --rpc-url "${ANVIL_RPC_URL}" "${vaddr}" --value 10ether >/dev/null
  done
}

read_core_addresses() {
  local addresses_yaml="${HYP_REGISTRY}/chains/anvil1/addresses.yaml"
  if [[ ! -f "${addresses_yaml}" ]]; then
    log_error "Missing ${addresses_yaml}; deploy core first"
    exit 1
  fi
  local mailbox
  mailbox="$(read_yaml_key "${addresses_yaml}" "mailbox")"
  local igp
  igp="$(read_yaml_key "${addresses_yaml}" "interchainGasPaymaster")"
  local va
  va="$(read_yaml_key "${addresses_yaml}" "validatorAnnounce")"
  local mth
  mth="$(read_yaml_key "${addresses_yaml}" "merkleTreeHook")"

  if [[ -z "${mailbox}" || -z "${igp}" || -z "${va}" || -z "${mth}" ]]; then
    log_error "addresses.yaml missing required keys (mailbox/interchainGasPaymaster/validatorAnnounce/merkleTreeHook)"
    exit 1
  fi

  echo "${mailbox}|${igp}|${va}|${mth}"
}

write_validator_config() {
  local idx="$1"
  local vpriv_hex="$2"
  local mailbox="$3"
  local igp="$4"
  local va="$5"
  local mth="$6"

  local workdir="${HYP_ROOT}/validator-$((idx + 1))"
  local cfg_dir="${workdir}/config"
  local checkpoints="${workdir}/checkpoints"
  local db="${workdir}/db"
  local metrics_port="$((9910 + idx))"

  run mkdir -p "${cfg_dir}" "${checkpoints}" "${db}"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] Would write validator config to ${cfg_dir}/agent.json"
    return 0
  fi

  python3 - <<PY
import json
from pathlib import Path

cfg = {
  "metricsPort": ${metrics_port},
  "log": { "level": "info", "format": "pretty" },
  "originChainName": "anvil1",
  "db": ${db!r},
  "validator": { "type": "hexKey", "key": "0x${vpriv_hex}" },
  "checkpointSyncer": { "type": "localStorage", "path": ${checkpoints!r} },
  "chains": {
    "anvil1": {
      "name": "anvil1",
      "chainId": ${ANVIL_CHAIN_ID},
      "domainId": ${ANVIL_DOMAIN_ID},
      "protocol": "ethereum",
      "rpcUrls": [{"http": ${ANVIL_RPC_URL!r}}],
      "mailbox": ${mailbox!r},
      "interchainGasPaymaster": ${igp!r},
      "validatorAnnounce": ${va!r},
      "merkleTreeHook": ${mth!r},
      "blocks": { "estimateBlockTime": 1, "reorgPeriod": 1 },
      "index": { "from": 0, "chunk": 1999, "mode": "block" },
    }
  }
}

out = Path(${cfg_dir!r}) / "agent.json"
out.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
print(f"Wrote {out}")
PY
}

write_relayer_config() {
  local idx="$1"
  local rpc_url="$2"
  local mailbox="$3"
  local igp="$4"
  local va="$5"
  local mth="$6"

  local workdir="${HYP_ROOT}/relayer-$((idx + 1))"
  local cfg_dir="${workdir}/config"
  local db="${workdir}/db"
  local metrics_port="$((9920 + idx))"

  local keyset_json="${RUN_ROOT}/config/devnet-keys.json"
  local group_id
  group_id="$(read_json_field "${keyset_json}" "data['group_id']")"
  if [[ -z "${group_id}" ]]; then
    log_error "Missing group_id in ${keyset_json}"
    exit 1
  fi
  local group_h256="0x${group_id}"

  run mkdir -p "${cfg_dir}" "${db}"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] Would write relayer config to ${cfg_dir}/agent.json"
    return 0
  fi

  python3 - <<PY
import json
from pathlib import Path

cfg = {
  "metricsPort": ${metrics_port},
  "log": { "level": "info", "format": "pretty" },
  "relayChains": "anvil1,kaspa",
  "db": ${db!r},
  "allowLocalCheckpointSyncers": True,
  "chains": {
    "anvil1": {
      "name": "anvil1",
      "chainId": ${ANVIL_CHAIN_ID},
      "domainId": ${ANVIL_DOMAIN_ID},
      "protocol": "ethereum",
      "rpcUrls": [{"http": ${ANVIL_RPC_URL!r}}],
      "mailbox": ${mailbox!r},
      "interchainGasPaymaster": ${igp!r},
      "validatorAnnounce": ${va!r},
      "merkleTreeHook": ${mth!r},
      "blocks": { "estimateBlockTime": 1, "reorgPeriod": 1 },
      "index": { "from": 0, "chunk": 1999, "mode": "block" },
    },
    "kaspa": {
      "name": "kaspa",
      "domainId": ${KASPA_DOMAIN_ID},
      "protocol": "kaspa",
      "rpcUrls": [{"http": ${rpc_url!r}}],
      "mailbox": ${group_h256!r},
      "interchainGasPaymaster": ${group_h256!r},
      "validatorAnnounce": ${group_h256!r},
      "merkleTreeHook": ${group_h256!r},
      "blocks": { "estimateBlockTime": 1, "reorgPeriod": 1 },
      "index": { "from": 0, "chunk": 1999, "mode": "sequence" },
    }
  }
}

out = Path(${cfg_dir!r}) / "agent.json"
out.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
print(f"Wrote {out}")
PY
}

start_hyperlane_agents() {
  build_hyperlane
  deploy_hyperlane_core
  fund_validator_accounts

  local addr_bundle
  addr_bundle="$(read_core_addresses)"
  local mailbox igp va mth
  IFS='|' read -r mailbox igp va mth <<<"${addr_bundle}"

  local validator_bin="${HYP_TARGET_DIR}/release/validator"
  local relayer_bin="${HYP_TARGET_DIR}/release/relayer"
  if [[ "${DRY_RUN}" != "true" ]]; then
    if [[ ! -x "${validator_bin}" || ! -x "${relayer_bin}" ]]; then
      log_error "Missing Hyperlane binaries: validator=${validator_bin} relayer=${relayer_bin}"
      exit 1
    fi
  fi

  local keys_json="${RUN_ROOT}/config/hyperlane-keys.json"
  for idx in 0 1; do
    local vpriv
    vpriv="$(read_json_field "${keys_json}" "data['validators'][${idx}]['private_key_hex']")"
    write_validator_config "${idx}" "${vpriv}" "${mailbox}" "${igp}" "${va}" "${mth}"
    local workdir="${HYP_ROOT}/validator-$((idx + 1))"
    start_process "validator-$((idx + 1))" bash -lc "cd \"${workdir}\" && \"${validator_bin}\""
  done

  local relayer_rpc_urls=("http://127.0.0.1:8088" "http://127.0.0.1:8089" "http://127.0.0.1:8090")
  for idx in 0 1 2; do
    write_relayer_config "${idx}" "${relayer_rpc_urls[${idx}]}" "${mailbox}" "${igp}" "${va}" "${mth}"
    local workdir="${HYP_ROOT}/relayer-$((idx + 1))"
    start_process "relayer-$((idx + 1))" bash -lc "cd \"${workdir}\" && \"${relayer_bin}\""
  done
}

send_messages() {
  local sender_bin="${RUN_ROOT}/bin/hyperlane_anvil_sender"
  if [[ ! -x "${sender_bin}" ]]; then
    log_error "Missing ${sender_bin}; run Igra devnet build first (or run 'default')"
    exit 1
  fi
  local keyset_json="${RUN_ROOT}/config/devnet-keys.json"
  if [[ ! -f "${keyset_json}" ]]; then
    log_error "Missing ${keyset_json}; run 'default' first"
    exit 1
  fi
  local evm_priv
  evm_priv="$(read_json_field "${keyset_json}" "data['evm']['private_key_hex']")"
  run "${sender_bin}" \
    --rpc-url "${ANVIL_RPC_URL}" \
    --registry "${HYP_REGISTRY}" \
    --chain anvil1 \
    --private-key "0x${evm_priv}" \
    --destination-domain "${KASPA_DOMAIN_ID}" \
    --igra-root "${RUN_ROOT}" \
    --count "${SEND_COUNT}" \
    --amount-sompi "${SEND_AMOUNT_SOMPI}"
}

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

stop_all() {
  stop_process "relayer-3"
  stop_process "relayer-2"
  stop_process "relayer-1"
  stop_process "validator-2"
  stop_process "validator-1"
  stop_process "anvil"
  stop_igra_devnet
}

clean_all() {
  if [[ -z "${RUN_ROOT}" || "${RUN_ROOT}" == "/" ]]; then
    log_error "Refusing to clean RUN_ROOT='${RUN_ROOT}'"
    exit 1
  fi
  stop_all || true
  run rm -rf "${RUN_ROOT}"
  log_success "Cleaned ${RUN_ROOT}"
}

require_prereqs

case "${COMMAND}" in
  help) usage ;;
  default)
    start_igra_devnet_default
    start_anvil
    start_hyperlane_agents
    ;;
  start)
    start_igra_devnet_start
    start_anvil
    start_hyperlane_agents
    ;;
  stop) stop_all ;;
  restart) stop_all; start_igra_devnet_start; start_anvil; start_hyperlane_agents ;;
  status) status ;;
  clean) clean_all ;;
  send) send_messages ;;
  *)
    log_error "Unknown command: ${COMMAND}"
    usage
    exit 1
    ;;
esac
