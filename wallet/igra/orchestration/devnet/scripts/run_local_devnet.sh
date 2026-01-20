#!/usr/bin/env bash
set -euo pipefail

# Basic logging helpers with timestamps and optional color (only if stdout is a TTY)
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
REPO_ROOT="$(cd "${DEVNET_DIR}/../../../.." && pwd)"

usage() {
  cat <<'EOF'
Usage: run_local_devnet.sh [--build clone|local] [--root PATH] [--target-dir PATH] [--dry-run] [--fake-hyperlane-legacy] [--no-fake-hyperlane] [--unordered-events N] [help|setup|build|start|stop|restart|status|clean|generate-keys] [all|kaspad|kaspaminer|signer-1|signer-2|signer-3|igra]

Options:
  --build clone    Default. Clone sources (per dockerfiles) and build binaries under ROOT/sources.
  --build local    Build from the current rusty-kaspa checkout without git clones.
  --dry-run        Print what would be done without executing.
  --fake-hyperlane-legacy  Run legacy fake Hyperlane binary (fake_hyperlane_ism_api) instead of the relayer-style binary.
  --no-fake-hyperlane      Do not start any fake Hyperlane process (use real Hyperlane agents).
  --unordered-events N     Shuffle nonces within each batch of N messages (simulates out-of-order delivery).

Commands:
  (no command)        Show this help
  build               Clone (if needed), build, and stage binaries into bin/
  setup               Assume binaries are staged; prepare configs and validate (no build/keygen)
  default             Build + stage + generate keys/configs (one-shot init)
  generate-keys       Regenerate keys/configs (requires binaries already built)
  start [target]      Start services (expects staged binaries/configs)
  stop [target]       Stop services
  restart [target]    Restart services (no build)
  status              Show process status
  clean               Remove all devnet data
  help                Show this help

Environment overrides:
  --root PATH              Root working dir (default: $(pwd)/igra_devnet)
  --target-dir PATH        Target dir for builds/binaries (default: ROOT/target for --clone, repo target for --local)
  KASPAD_BIN               Path to kaspad binary (skip build/clone)
  KASPA_MINER_BIN          Path to kaspa-miner binary (skip build/clone)
  KASPA_MINER_PATH         Local path to kaspa-miner sources for --local mode
  IGRA_BIN                 Path to kaspa-threshold-service binary (skip build/clone)
  FAKE_HYPERLANE_BIN       Path to legacy fake_hyperlane_ism_api binary (skip build/clone)
  FAKE_HYPERLANE_RELAYER_BIN  Path to fake_hyperlane_relayer binary (skip build/clone)
  ROTHSCHILD_BIN           Path to rothschild binary (skip build/clone)
IGRA_REPO / IGRA_REF     Clone source for --clone mode (default: https://github.com/reshmem/rusty-kaspa.git / devel)
  KASPA_MINER_REPO/REF     Clone source for --clone mode (default: https://github.com/IgraLabs/kaspa-miner.git / main)

Security notes:
  - Logs in ${LOG_DIR:-<root>/logs} may contain sensitive material (mnemonics/keys). Logs directory is restricted to 700 permissions.
  - Only clone from trusted sources; non-GitHub URLs will prompt for confirmation.
EOF
}

BUILD_MODE="${BUILD_MODE:-clone}"
DRY_RUN=false
ROOT_ARG=""
TARGET_DIR_ARG=""
COMMAND=""
TARGET_ARG="all"
FAKE_HYPERLANE_LEGACY=false
NO_FAKE_HYPERLANE=false
FAKE_HYPERLANE_UNORDERED_EVENTS=""
POSITIONAL=()

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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      log_warn "DRY RUN MODE: actions will be printed but not executed"
      shift
      ;;
    --fake-hyperlane-legacy|fake-hyperlane-legacy)
      FAKE_HYPERLANE_LEGACY=true
      shift
      ;;
    --no-fake-hyperlane|no-fake-hyperlane)
      NO_FAKE_HYPERLANE=true
      shift
      ;;
    --unordered-events=*)
      FAKE_HYPERLANE_UNORDERED_EVENTS="${1#*=}"
      shift
      ;;
    --unordered-events)
      FAKE_HYPERLANE_UNORDERED_EVENTS="${2:-}"
      shift 2
      ;;
    --build)
      case "${2:-}" in
        clone|local) BUILD_MODE="$2"; shift 2 ;;
        *) echo "Unknown --build value: ${2:-<missing>} (expected clone|local)" >&2; usage; exit 1 ;;
      esac
      ;;
    --root) ROOT_ARG="$2"; shift 2 ;;
    --target-dir) TARGET_DIR_ARG="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    help|setup|build|start|stop|restart|status|clean|generate-keys|default)
      if [[ -z "${COMMAND}" ]]; then
        COMMAND="$1"
      else
        POSITIONAL+=("$1")
      fi
      shift
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [[ -n "${FAKE_HYPERLANE_UNORDERED_EVENTS}" ]]; then
  if [[ "${FAKE_HYPERLANE_UNORDERED_EVENTS}" =~ ^[0-9]+$ ]]; then
    if [[ "${FAKE_HYPERLANE_UNORDERED_EVENTS}" -lt 1 || "${FAKE_HYPERLANE_UNORDERED_EVENTS}" -gt 1024 ]]; then
      echo "--unordered-events must be between 1 and 1024" >&2
      exit 1
    fi
  else
    echo "--unordered-events must be a number" >&2
    exit 1
  fi
fi

if [[ ${#POSITIONAL[@]} -eq 0 && -z "${COMMAND}" ]]; then
  usage
  exit 0
fi

COMMAND="${COMMAND:-${POSITIONAL[0]:-}}"
TARGET_ARG="${POSITIONAL[1]:-all}"

case "${COMMAND}" in
  help|-h|--help) usage; exit 0 ;;
  setup|build|start|stop|restart|clean|generate-keys|status) ;;
  default) ;;
  *) echo "Unknown command: ${COMMAND}" >&2; usage; exit 1 ;;
esac

# Default working directory for this run (current dir / igra_devnet unless overridden).
RUN_ROOT="${ROOT_ARG:-$(pwd)/igra_devnet}"

if [[ "${COMMAND}" == "clean" ]]; then
  if [[ -z "${RUN_ROOT}" || "${RUN_ROOT}" == "/" ]]; then
    echo "Refusing to clean RUN_ROOT='${RUN_ROOT}'" >&2
    exit 1
  fi
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] Would remove ${RUN_ROOT}"
    exit 0
  fi
  if [[ -d "${RUN_ROOT}" ]]; then
    log_info "Removing ${RUN_ROOT}"
    rm -rf "${RUN_ROOT}"
  else
    log_info "Nothing to clean at ${RUN_ROOT}"
  fi
  exit 0
fi

mkdir -p "${RUN_ROOT}"
cd "${RUN_ROOT}"

LOG_DIR="${RUN_ROOT}/logs"
PIDS_DIR="${RUN_ROOT}/pids"
KASPAD_DATA="${RUN_ROOT}/kaspad"
KASPAD_APPDIR="${RUN_ROOT}/.rusty-kaspa"
IGRA_DATA="${RUN_ROOT}/igra"
WALLET_DATA="${RUN_ROOT}/wallet"
CONFIG_DIR="${RUN_ROOT}/config"
BIN_DIR="${RUN_ROOT}/bin"

ENV_FILE="${CONFIG_DIR}/.env"
IGRA_CONFIG_TEMPLATE=""
IGRA_CONFIG="${CONFIG_DIR}/igra-config.toml"
HYPERLANE_KEYS_SRC=""
HYPERLANE_KEYS="${CONFIG_DIR}/hyperlane-keys.json"
KEYSET_JSON_TEMPLATE=""
KEYSET_JSON="${CONFIG_DIR}/devnet-keys.json"
SRC_ROOT="${RUN_ROOT}/sources"
RUSTY_SRC="${SRC_ROOT}/rusty-kaspa"
MINER_SRC="${SRC_ROOT}/kaspa-miner"
# Use CLI-provided target dir when set, otherwise pick a sensible default per mode later.
if [[ -n "${TARGET_DIR_ARG}" ]]; then
  TARGET_DIR="${TARGET_DIR_ARG}"
elif [[ "${BUILD_MODE}" == "local" ]]; then
  TARGET_DIR="${REPO_ROOT}/target"
else
  TARGET_DIR="${RUN_ROOT}/target"
fi
# Honor user-provided CARGO_TARGET_DIR if set elsewhere by letting TARGET_DIR be explicit above,
# and ensure cargo uses our resolved target dir for all child commands.
export CARGO_TARGET_DIR="${TARGET_DIR}"

# Hardcoded clone sources (env overrides intentionally ignored for reproducibility).
IGRA_REPO="https://github.com/reshmem/rusty-kaspa.git"
IGRA_REF="devel"
KASPA_MINER_REPO="${KASPA_MINER_REPO:-https://github.com/IgraLabs/kaspa-miner.git}"
KASPA_MINER_REF="${KASPA_MINER_REF:-main}"

load_env() { :; } # no-op; repo/ref and keys are hardcoded/auto-generated now

require_cmd python3 "required for key generation and config rewriting" "brew install python3 or apt install python3"
if ! python3 - <<'PY' 2>/dev/null; then
import sys
sys.exit(0 if sys.version_info >= (3,6) else 1)
PY
  log_error "Python 3.6+ required; found $(python3 --version 2>/dev/null || echo unknown)"
  exit 1
fi

KASPA_IGRA_WALLET_SECRET="${KASPA_IGRA_WALLET_SECRET:-devnet-secret}"
FAKE_HYPERLANE_INTERVAL="${HYPERLANE_INTERVAL_SECS:-10}"
FAKE_HYPERLANE_START="${HYPERLANE_START_EPOCH_SECS:-0}"
# 10_000_000 sompi (0.1 KAS) is right at the edge of the mempool "standard tx mass" limit (KIP-0009 storage mass),
# and can be rejected as non-standard depending on tx overhead. Use a safer default for devnet.
FAKE_HYPERLANE_AMOUNT="${HYPERLANE_AMOUNT_SOMPI:-20000000}"
FAKE_HYPERLANE_DEST="${HYPERLANE_DESTINATION:-kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3}"
FAKE_HYPERLANE_DOMAIN="${HYPERLANE_DOMAIN:-5}"
FAKE_HYPERLANE_DEST_DOMAIN="${HYPERLANE_DESTINATION_DOMAIN:-7}"
FAKE_HYPERLANE_SENDER="${HYPERLANE_SENDER:-0x0}"
FAKE_HYPERLANE_COORDINATOR="${HYPERLANE_COORDINATOR_PEER_ID:-coordinator-1}"
# Derivation is optional; default is empty (root) unless explicitly provided.
FAKE_HYPERLANE_PATH="${HYPERLANE_DERIVATION_PATH:-}"
PROCESS_STOP_TIMEOUT="${PROCESS_STOP_TIMEOUT:-10}"
KASPAD_STARTUP_TIMEOUT="${KASPAD_STARTUP_TIMEOUT:-30}"
IGRA_STARTUP_TIMEOUT="${IGRA_STARTUP_TIMEOUT:-20}"
WRPC_BORSH_PORT="${WRPC_BORSH_PORT:-17110}"
WRPC_JSON_PORT="${WRPC_JSON_PORT:-17111}"

resolve_bin() {
  local name="$1"
  local primary="$2"
  local env_var="$3"
  local secondary="${4:-}"
  local override="${!env_var:-}"

  if [[ -n "${override}" ]]; then
    if [[ ! -x "${override}" ]]; then
      echo "Set ${env_var} to an executable ${name} binary (got: ${override})." >&2
      exit 1
    fi
    echo "${override}"
    return
  fi

  for candidate in "${primary}" "${secondary}"; do
    if [[ -n "${candidate}" && -x "${candidate}" ]]; then
      echo "${candidate}"
      return
    fi
  done

  if command -v "${name}" >/dev/null 2>&1; then
    command -v "${name}"
    return
  fi

  echo "Missing ${name}; build it or set ${env_var}. Tried: ${primary}${secondary:+ , }${secondary}" >&2
  exit 1
}

clone_repo() {
  local url="$1"
  local ref="$2"
  local dest="$3"

  # Normalize SSH-style GitHub URLs to HTTPS to avoid SSH requirements.
  if [[ "${url}" =~ ^git@github.com:(.*)\.git$ ]]; then
    url="https://github.com/${BASH_REMATCH[1]}.git"
  fi

  # Warn for non-GitHub sources
  if [[ ! "${url}" =~ ^https://github\.com/ ]]; then
    log_warn "Cloning from non-GitHub URL: ${url}"
    read -p "Continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      log_error "Clone cancelled by user"
      return 1
    fi
  fi

  if [[ -d "${dest}/.git" ]]; then
    log_info "Using existing clone at ${dest}; pulling latest ${ref}"
    (cd "${dest}" && git fetch --all --prune && git checkout "${ref}" && git pull --ff-only origin "${ref}") || log_warn "git pull failed in ${dest}; continuing with existing checkout"
    return
  fi
  mkdir -p "$(dirname "${dest}")"
  log_info "Cloning ${url}#${ref} into ${dest}"
  if ! git clone --depth 1 --branch "${ref}" "${url}" "${dest}"; then
    log_error "Failed to clone ${url}"
    return 1
  fi
}

build_rusty_repo() {
  require_cmd cargo
  local repo_path="$1"
  local igra_repo_path="${repo_path}"
  # In clone mode the remote ref may lag local config refactors (e.g. TOML profiles).
  # Always prefer building Igra crates from the current checkout when available.
  if [[ "${repo_path}" != "${REPO_ROOT}" && -f "${REPO_ROOT}/wallet/igra/Cargo.toml" ]]; then
    igra_repo_path="${REPO_ROOT}"
    log_warn "Building Igra binaries from local checkout (${igra_repo_path}) instead of ${repo_path}"
  fi
  log_info "Building kaspa binaries from ${repo_path}..."
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] cd ${repo_path} && CARGO_TARGET_DIR=${TARGET_DIR} cargo build --release --locked -p kaspad -p rothschild -p kaspa-cli -p kaspa-wallet"
    log_info "[DRY-RUN] cd ${igra_repo_path} && CARGO_TARGET_DIR=${TARGET_DIR} cargo build --release --locked -p igra-core --bin devnet-balance"
    log_info "[DRY-RUN] cd ${igra_repo_path} && CARGO_TARGET_DIR=${TARGET_DIR} cargo build --release --locked -p igra-service --bin kaspa-threshold-service --bin fake_hyperlane_ism_api --bin fake_hyperlane_relayer --bin hyperlane_anvil_sender"
  else
    # Clear RUSTC_WRAPPER to avoid sccache/wrappers interfering with target dir
    if ! (cd "${repo_path}" && RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" \
      cargo build --release --locked \
        -p kaspad \
        -p rothschild \
        -p kaspa-cli \
        -p kaspa-wallet); then
      log_error "Failed to build kaspad/rothschild/kaspa-cli/kaspa-wallet from ${repo_path}"
      exit 1
    fi

    if ! (cd "${igra_repo_path}" && RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" \
      cargo build --release --locked \
        -p igra-core --bin devnet-balance); then
      log_error "Failed to build devnet-balance from ${igra_repo_path}"
      exit 1
    fi

    if ! (cd "${igra_repo_path}" && RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" \
      cargo build --release --locked \
        -p igra-service --bin kaspa-threshold-service --bin fake_hyperlane_ism_api --bin fake_hyperlane_relayer --bin hyperlane_anvil_sender); then
      log_error "Failed to build igra-service binaries from ${igra_repo_path}"
      exit 1
    fi

    for binary in kaspad rothschild kaspa-cli kaspa-wallet devnet-balance kaspa-threshold-service fake_hyperlane_ism_api fake_hyperlane_relayer hyperlane_anvil_sender; do
      if [[ ! -x "${TARGET_DIR}/release/${binary}" ]]; then
        log_error "${binary} not found after build (expected at ${TARGET_DIR}/release/${binary})"
        exit 1
      fi
    done
  fi
  # Build devnet-keygen separately to avoid cargo target filtering issues across packages.
  local keygen_repo="${igra_repo_path}"
  if [[ -f "${keygen_repo}/wallet/igra/igra-core/src/bin/devnet-keygen.rs" ]]; then
    if [[ "${DRY_RUN}" == "true" ]]; then
      log_info "[DRY-RUN] cd ${keygen_repo} && CARGO_TARGET_DIR=${TARGET_DIR} cargo build --release --locked -p igra-core --bin devnet-keygen"
    else
      if ! (cd "${keygen_repo}" && RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" \
        cargo build --release --locked -p igra-core --bin devnet-keygen); then
        log_warn "Failed to build devnet-keygen; key regeneration may fail"
      fi
    fi
  fi
}

build_miner_repo() {
  require_cmd cargo
  local repo_path="$1"
  log_info "Building kaspa-miner from ${repo_path}..."
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] cd ${repo_path} && CARGO_TARGET_DIR=${TARGET_DIR} cargo build --release --locked -p kaspa-miner --features no-asm"
  else
    if ! (cd "${repo_path}" && RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" \
      cargo build --release --locked -p kaspa-miner --features no-asm); then
      log_error "Failed to build kaspa-miner from ${repo_path}"
      exit 1
    fi
  fi
}

required_bins=(kaspad rothschild kaspa-cli kaspa-wallet kaspa-threshold-service fake_hyperlane_ism_api fake_hyperlane_relayer hyperlane_anvil_sender devnet-keygen kaspa-miner)

have_all_binaries() {
  for bin in "${required_bins[@]}"; do
    if [[ ! -x "${BIN_DIR}/${bin}" ]]; then
      return 1
    fi
  done
  return 0
}

prepare_sources() {
  case "${BUILD_MODE}" in
    clone)
      require_cmd git
      mkdir -p "${SRC_ROOT}"
      local fallback_local=""
      if ! clone_repo "${IGRA_REPO}" "${IGRA_REF}" "${RUSTY_SRC}"; then
        echo "Clone failed for rusty-kaspa; falling back to --build local if sources are available." >&2
        fallback_local="yes"
      fi
      if [[ -z "${fallback_local}" ]] && ! clone_repo "${KASPA_MINER_REPO}" "${KASPA_MINER_REF}" "${MINER_SRC}"; then
        echo "Clone failed for kaspa-miner; falling back to --build local if sources are available." >&2
        fallback_local="yes"
      fi

      if [[ -n "${fallback_local}" ]]; then
        BUILD_MODE="local"
        prepare_sources
        return
      fi

      build_rusty_repo "${RUSTY_SRC}"
      build_miner_repo "${MINER_SRC}"
      DEFAULT_KASPAD_BIN="${TARGET_DIR}/release/kaspad"
      DEFAULT_ROTHSCHILD_BIN="${TARGET_DIR}/release/rothschild"
      DEFAULT_KASPA_CLI_BIN="${TARGET_DIR}/release/kaspa-cli"
      DEFAULT_KASPA_WALLET_BIN="${TARGET_DIR}/release/kaspa-wallet"
      DEFAULT_IGRA_BIN="${TARGET_DIR}/release/kaspa-threshold-service"
      DEFAULT_FAKE_HYPERLANE_BIN="${TARGET_DIR}/release/fake_hyperlane_ism_api"
      DEFAULT_FAKE_HYPERLANE_RELAYER_BIN="${TARGET_DIR}/release/fake_hyperlane_relayer"
      DEFAULT_MINER_BIN="${TARGET_DIR}/release/kaspa-miner"
      ;;
    local)
      local local_rusty="${REPO_ROOT}"
      local local_miner="${KASPA_MINER_PATH:-}"
      if [[ -z "${local_miner}" && -d "${REPO_ROOT}/../kaspa-miner" ]]; then
        local_miner="${REPO_ROOT}/../kaspa-miner"
      fi
      build_rusty_repo "${local_rusty}"
      DEFAULT_KASPAD_BIN="${TARGET_DIR}/release/kaspad"
      DEFAULT_ROTHSCHILD_BIN="${TARGET_DIR}/release/rothschild"
       DEFAULT_KASPA_CLI_BIN="${TARGET_DIR}/release/kaspa-cli"
       DEFAULT_KASPA_WALLET_BIN="${TARGET_DIR}/release/kaspa-wallet"
      DEFAULT_IGRA_BIN="${TARGET_DIR}/release/kaspa-threshold-service"
      DEFAULT_FAKE_HYPERLANE_BIN="${TARGET_DIR}/release/fake_hyperlane_ism_api"
      DEFAULT_FAKE_HYPERLANE_RELAYER_BIN="${TARGET_DIR}/release/fake_hyperlane_relayer"

      if [[ -n "${local_miner}" ]]; then
        build_miner_repo "${local_miner}"
        DEFAULT_MINER_BIN="${TARGET_DIR}/release/kaspa-miner"
      else
        DEFAULT_MINER_BIN=""
      fi
      ;;
    *)
      echo "Unknown BUILD_MODE=${BUILD_MODE}" >&2
      exit 1
      ;;
  esac
}

setup_config_source() {
  # Always prefer the local repo's orchestration templates.
  # In clone mode, the cloned repo may be on a different ref and not include (or include stale)
  # TOML templates, which breaks config generation.
  local config_source="${DEVNET_DIR}"
  local clone_source="${RUSTY_SRC}/wallet/igra/orchestration/devnet"
  if [[ "${BUILD_MODE}" == "clone" ]]; then
    if [[ -d "${clone_source}" ]]; then
      log_info "Build mode is clone; using local devnet templates from ${DEVNET_DIR} (ignoring ${clone_source})"
    else
      log_info "Build mode is clone; cloned sources not present yet; using local devnet templates from ${DEVNET_DIR}"
    fi
  fi

  IGRA_CONFIG_TEMPLATE="${config_source}/igra-devnet-template.toml"
  HYPERLANE_KEYS_SRC="${config_source}/hyperlane-keys.json"
  KEYSET_JSON_TEMPLATE="${config_source}/devnet-keys.json"

  # Fallback for unusual setups where local templates are missing.
  if [[ ! -f "${IGRA_CONFIG_TEMPLATE}" || ! -f "${HYPERLANE_KEYS_SRC}" || ! -f "${KEYSET_JSON_TEMPLATE}" ]]; then
    if [[ -f "${clone_source}/igra-devnet-template.toml" && -f "${clone_source}/hyperlane-keys.json" && -f "${clone_source}/devnet-keys.json" ]]; then
      log_warn "Local devnet templates missing under ${config_source}; falling back to cloned templates under ${clone_source}"
      config_source="${clone_source}"
      IGRA_CONFIG_TEMPLATE="${config_source}/igra-devnet-template.toml"
      HYPERLANE_KEYS_SRC="${config_source}/hyperlane-keys.json"
      KEYSET_JSON_TEMPLATE="${config_source}/devnet-keys.json"
    else
      log_error "Devnet templates missing under ${config_source} (and not found under ${clone_source})"
      exit 1
    fi
  fi

  log_info "Using config templates from: ${config_source}"
}

resolve_binaries_from_target() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] Skipping binary resolution"
    return
  fi
  KASPAD_BIN="${TARGET_DIR}/release/kaspad"
  KASPA_MINER_BIN="${TARGET_DIR}/release/kaspa-miner"
  KASPA_CLI_BIN="${TARGET_DIR}/release/kaspa-cli"
  KASPA_WALLET_BIN="${TARGET_DIR}/release/kaspa-wallet"
  DEVNET_BALANCE_BIN="${TARGET_DIR}/release/devnet-balance"
  IGRA_BIN="${TARGET_DIR}/release/kaspa-threshold-service"
  FAKE_HYPERLANE_BIN="${TARGET_DIR}/release/fake_hyperlane_ism_api"
  FAKE_HYPERLANE_RELAYER_BIN="${TARGET_DIR}/release/fake_hyperlane_relayer"
  ROTHSCHILD_BIN="${TARGET_DIR}/release/rothschild"
  DEVNET_KEYGEN_BIN="${TARGET_DIR}/release/devnet-keygen"
}

require_binaries_present() {
  if ! have_all_binaries; then
    log_error "Required binaries missing in ${BIN_DIR}. Run 'build', 'setup', or the default command first."
    exit 1
  fi
  KASPAD_BIN="${BIN_DIR}/kaspad"
  KASPA_MINER_BIN="${BIN_DIR}/kaspa-miner"
  KASPA_CLI_BIN="${BIN_DIR}/kaspa-cli"
  KASPA_WALLET_BIN="${BIN_DIR}/kaspa-wallet"
  DEVNET_BALANCE_BIN="${BIN_DIR}/devnet-balance"
  IGRA_BIN="${BIN_DIR}/kaspa-threshold-service"
  FAKE_HYPERLANE_BIN="${BIN_DIR}/fake_hyperlane_ism_api"
  FAKE_HYPERLANE_RELAYER_BIN="${BIN_DIR}/fake_hyperlane_relayer"
  ROTHSCHILD_BIN="${BIN_DIR}/rothschild"
  DEVNET_KEYGEN_BIN="${BIN_DIR}/devnet-keygen"
}

mkdir -p "${LOG_DIR}" "${PIDS_DIR}" "${KASPAD_DATA}" "${KASPAD_APPDIR}" "${IGRA_DATA}" "${WALLET_DATA}" "${BIN_DIR}"
mkdir -p "${CONFIG_DIR}"
chmod 700 "${LOG_DIR}" >/dev/null 2>&1 || true

prepare_igra_config() {
  if [[ ! -f "${HYPERLANE_KEYS}" ]]; then
    log_info "Seeding hyperlane-keys.json from template into ${CONFIG_DIR}"
    cp -f "${HYPERLANE_KEYS_SRC}" "${HYPERLANE_KEYS}"
  fi
  if [[ ! -f "${IGRA_CONFIG}" ]]; then
    log_info "Seeding igra-config.toml from template into ${CONFIG_DIR}"
    sed \
      -e "s|data_dir = \"\"|data_dir = \"${IGRA_DATA}\"|g" \
      -e "s|grpc://kaspad:16110|grpc://127.0.0.1:16110|g" \
      "${IGRA_CONFIG_TEMPLATE}" > "${IGRA_CONFIG}"
  else
    log_info "Using existing igra-config.toml (not overwriting)"
  fi
}

stage_binaries() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] Skipping binary staging"
    return
  fi
  log_info "Staging binaries into ${BIN_DIR} (overwriting if present)"
  cp -f "${KASPAD_BIN}" "${BIN_DIR}/kaspad"
  cp -f "${KASPA_MINER_BIN}" "${BIN_DIR}/kaspa-miner"
  cp -f "${KASPA_CLI_BIN}" "${BIN_DIR}/kaspa-cli"
  cp -f "${KASPA_WALLET_BIN}" "${BIN_DIR}/kaspa-wallet"
  cp -f "${DEVNET_BALANCE_BIN}" "${BIN_DIR}/devnet-balance"
  cp -f "${IGRA_BIN}" "${BIN_DIR}/kaspa-threshold-service"
  cp -f "${FAKE_HYPERLANE_BIN}" "${BIN_DIR}/fake_hyperlane_ism_api"
  cp -f "${FAKE_HYPERLANE_RELAYER_BIN}" "${BIN_DIR}/fake_hyperlane_relayer"
  if [[ -f "${TARGET_DIR}/release/hyperlane_anvil_sender" ]]; then
    cp -f "${TARGET_DIR}/release/hyperlane_anvil_sender" "${BIN_DIR}/hyperlane_anvil_sender"
  fi
  cp -f "${ROTHSCHILD_BIN}" "${BIN_DIR}/rothschild"
  if [[ -n "${DEVNET_KEYGEN_BIN:-}" && -f "${DEVNET_KEYGEN_BIN}" ]]; then
    cp -f "${DEVNET_KEYGEN_BIN}" "${BIN_DIR}/devnet-keygen"
  fi
}

run_keygen() {
  local keygen_bin="${BIN_DIR}/devnet-keygen"
  if [[ ! -x "${keygen_bin}" ]]; then
    log_error "Missing devnet-keygen in ${BIN_DIR}. Run 'build' first to stage binaries."
    return 1
  fi
  "${keygen_bin}"
}

validate_keygen_output() {
  local json_str="$1"
  python3 - <<'PY' <<<"${json_str}"
import json
import re
import sys

data = json.loads(sys.stdin.read())

def die(msg: str) -> None:
    print(msg, file=sys.stderr)
    sys.exit(1)

hex_re = re.compile(r"^[0-9a-fA-F]+$")

member_pubkeys = data.get("member_pubkeys") or []
if not isinstance(member_pubkeys, list) or not member_pubkeys:
    die("missing member_pubkeys")

for idx, pk in enumerate(member_pubkeys):
    if not isinstance(pk, str) or not pk:
        die(f"member_pubkeys[{idx}] is empty")
    s = pk.strip()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) != 64 or not hex_re.match(s):
        die(f"member_pubkeys[{idx}] must be x-only (32-byte) hex, got len={len(s)} value={pk!r}")

redeem = (data.get("redeem_script_hex") or "").strip()
if not redeem or not hex_re.match(redeem):
    die("missing or invalid redeem_script_hex")

multisig_address = (data.get("multisig_address") or "").strip()
if not multisig_address:
    die("missing multisig_address")

source_addresses = data.get("source_addresses") or []
if not isinstance(source_addresses, list) or len(source_addresses) != 1:
    die(f"source_addresses must be a single multisig address, got {source_addresses!r}")
if (source_addresses[0] or "").strip() != multisig_address:
    die("source_addresses[0] must equal multisig_address")

change_address = (data.get("change_address") or "").strip()
if change_address and change_address != multisig_address:
    die("change_address must equal multisig_address for devnet (or be omitted to default)")

sys.exit(0)
PY
}

rebuild_devnet_keygen() {
  log_warn "Rebuilding devnet-keygen to match current multisig config format (x-only pubkeys + Schnorr address)..."
  if ! (cd "${REPO_ROOT}" && RUSTC_WRAPPER= CARGO_TARGET_DIR="${TARGET_DIR}" \
    cargo build --release --locked -p igra-core --bin devnet-keygen); then
    log_error "Failed to rebuild devnet-keygen"
    return 1
  fi
  if [[ ! -x "${TARGET_DIR}/release/devnet-keygen" ]]; then
    log_error "devnet-keygen not found after rebuild (expected at ${TARGET_DIR}/release/devnet-keygen)"
    return 1
  fi
  cp -f "${TARGET_DIR}/release/devnet-keygen" "${BIN_DIR}/devnet-keygen"
  log_success "devnet-keygen rebuilt and staged"
  return 0
}

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

PIDS=()

start_process() {
  local name="$1"
  shift
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] Would start ${name}: $*"
    log_info "[DRY-RUN]   Log: ${LOG_DIR}/${name}.log"
    return
  fi
  log_info "Starting ${name}..."
  mkdir -p "$(dirname "${LOG_DIR}/${name}.log")"
  "$@" >"${LOG_DIR}/${name}.log" 2>&1 &
  local pid=$!
  PIDS+=("${pid}")
  echo "${pid}" > "${PIDS_DIR}/${name}.pid"
  log_info "pid=${pid} log=${LOG_DIR}/${name}.log"
}

stop_process() {
  local name="$1"
  local pid_file="${PIDS_DIR}/${name}.pid"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] Would stop ${name}"
    return
  fi

  if [[ ! -f "${pid_file}" ]]; then
    log_warn "No pid file for ${name} (${pid_file}); skipping."
    return
  fi
  local pid
  pid=$(cat "${pid_file}")
  if ! kill -0 "${pid}" 2>/dev/null; then
    log_warn "${name} already stopped"
    rm -f "${pid_file}"
    return
  fi

  log_info "Stopping ${name} (pid ${pid})..."
  kill "${pid}" >/dev/null 2>&1 || true
  local timeout=${PROCESS_STOP_TIMEOUT}
  for _ in $(seq 1 ${timeout}); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      log_success "Stopped ${name}"
      rm -f "${pid_file}"
      return
    fi
    sleep 1
  done

  log_warn "${name} did not stop gracefully, force killing..."
  kill -9 "${pid}" >/dev/null 2>&1 || true
  sleep 1
  if kill -0 "${pid}" 2>/dev/null; then
    log_error "Failed to kill ${name} (pid ${pid})"
  else
    log_success "Force killed ${name}"
  fi
  rm -f "${pid_file}"
}

cleanup() {
  if [[ ${#PIDS[@]} -gt 0 ]]; then
    echo "Stopping ${#PIDS[@]} processes..."
    kill "${PIDS[@]}" >/dev/null 2>&1 || true
    wait "${PIDS[@]}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

start_kaspad() {
  # Clear stale RocksDB lock files if present.
  if find "${KASPAD_APPDIR}/kaspa-devnet" -name LOCK -type f -print -quit >/dev/null 2>&1; then
    log_warn "Removing stale kaspad lock files under ${KASPAD_APPDIR}/kaspa-devnet"
    find "${KASPAD_APPDIR}/kaspa-devnet" -name LOCK -type f -print -delete || true
  fi
  start_process "kaspad" \
    "${KASPAD_BIN}" \
    --devnet \
    --utxoindex \
    --enable-unsynced-mining \
    --appdir="${KASPAD_APPDIR}" \
    --rpclisten=127.0.0.1:16110 \
    --rpclisten-borsh=127.0.0.1:${WRPC_BORSH_PORT} \
    --rpclisten-json=127.0.0.1:${WRPC_JSON_PORT} \
    --listen=0.0.0.0:16111
}

start_miner() {
  # Ensure mining address aligns with current devnet-keys.json to avoid stale .env values.
  if [[ -f "${KEYSET_JSON}" ]]; then
    local mined_addr
    mined_addr=$(
      KEYSET_JSON="${KEYSET_JSON}" python3 - <<'PY'
import json, sys
import os
path = os.environ.get("KEYSET_JSON")
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
print(data.get("wallet", {}).get("mining_address", ""))
PY
    )
    if [[ -n "${mined_addr}" ]]; then
      KASPA_MINING_ADDRESS="${mined_addr}"
    fi
  fi
  start_process "kaspaminer" \
    "${KASPA_MINER_BIN}" \
    --kaspad-address="grpc://127.0.0.1:16110" \
    --devfund-percent=0 \
    --mining-address="${KASPA_MINING_ADDRESS}" \
    --mine-when-not-synced
}

start_igra() {
  local profile="$1"
  local rpc_port="$2"
  local rpc_url="http://127.0.0.1:${rpc_port}/rpc"

  mkdir -p "${IGRA_DATA}/${profile}"

  local profile_data_dir="${IGRA_DATA}/${profile}"

  start_process "igra-${profile}" \
    env \
      KASPA_CONFIG_PATH="${IGRA_CONFIG}" \
      KASPA_DATA_DIR="${profile_data_dir}" \
      KASPA_NODE_URL="grpc://127.0.0.1:16110" \
      KASPA_IGRA_WALLET_SECRET="${KASPA_IGRA_WALLET_SECRET}" \
      KASPA_IGRA_PROFILE="${profile}" \
      IGRA_RPC_URL="${rpc_url}" \
      HYPERLANE_KEYS_PATH="${HYPERLANE_KEYS}" \
      "${IGRA_BIN}" \
      --config "${IGRA_CONFIG}" \
      --data-dir "${profile_data_dir}" \
      --node-url "grpc://127.0.0.1:16110" \
      --log-level info
}

start_fake_hyperlane() {
  local profile="$1"
  local rpc_port="$2"
  local rpc_url="http://127.0.0.1:${rpc_port}/rpc"
  local log_path="${LOG_DIR}/fake-hyperlane-${profile}.log"
  local destination="${FAKE_HYPERLANE_DEST}"
  local fake_bin=""
  local -a fake_args=()

  if [[ -z "${HYPERLANE_DESTINATION:-}" && -f "${KEYSET_JSON}" ]]; then
    local mined_addr
    mined_addr=$(
      KEYSET_JSON="${KEYSET_JSON}" python3 - <<'PY'
import json
import os
path = os.environ.get("KEYSET_JSON")
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
print(data.get("wallet", {}).get("mining_address", ""))
PY
    )
    if [[ -n "${mined_addr}" ]]; then
      destination="${mined_addr}"
    fi
  fi

  if [[ "${FAKE_HYPERLANE_LEGACY}" == "true" ]]; then
    fake_bin="${FAKE_HYPERLANE_BIN}"
    local -a env_kv=(
      "IGRA_RPC_URL=${rpc_url}"
      "HYPERLANE_KEYS_PATH=${HYPERLANE_KEYS}"
      "HYPERLANE_INTERVAL_SECS=${FAKE_HYPERLANE_INTERVAL}"
      "HYPERLANE_START_EPOCH_SECS=${FAKE_HYPERLANE_START}"
      "HYPERLANE_AMOUNT_SOMPI=${FAKE_HYPERLANE_AMOUNT}"
      "HYPERLANE_DESTINATION=${destination}"
      "HYPERLANE_DOMAIN=${FAKE_HYPERLANE_DOMAIN}"
      "HYPERLANE_SENDER=${FAKE_HYPERLANE_SENDER}"
      "HYPERLANE_COORDINATOR_PEER_ID=${FAKE_HYPERLANE_COORDINATOR}"
    )
    if [[ -n "${FAKE_HYPERLANE_PATH}" ]]; then
      env_kv+=("HYPERLANE_DERIVATION_PATH=${FAKE_HYPERLANE_PATH}")
    fi
	    if [[ -n "${FAKE_HYPERLANE_UNORDERED_EVENTS}" ]]; then
	      fake_args+=(--unordered-events "${FAKE_HYPERLANE_UNORDERED_EVENTS}")
	    fi
	    if [[ ${#fake_args[@]} -gt 0 ]]; then
	      start_process "fake-hyperlane-${profile}" \
	        env "${env_kv[@]}" "${fake_bin}" "${fake_args[@]}"
	    else
	      start_process "fake-hyperlane-${profile}" \
	        env "${env_kv[@]}" "${fake_bin}"
	    fi
	  else
	    fake_bin="${FAKE_HYPERLANE_RELAYER_BIN}"
	    local rpc_base="http://127.0.0.1:${rpc_port}"
	    local -a env_kv=(
      "IGRA_RPC_BASE_URL=${rpc_base}"
      "HYPERLANE_KEYS_PATH=${HYPERLANE_KEYS}"
      "HYPERLANE_INTERVAL_SECS=${FAKE_HYPERLANE_INTERVAL}"
      "HYPERLANE_RETRY_DELAY_SECS=1"
      "HYPERLANE_CLIENT_TIMEOUT_SECS=120"
      "HYPERLANE_AMOUNT_SOMPI=${FAKE_HYPERLANE_AMOUNT}"
      "HYPERLANE_DESTINATION=${destination}"
      "HYPERLANE_ORIGIN_DOMAIN=${FAKE_HYPERLANE_DOMAIN}"
      "HYPERLANE_DESTINATION_DOMAIN=${FAKE_HYPERLANE_DEST_DOMAIN}"
    )
    # Only forward sender if it looks like a full 32-byte H256; otherwise let the binary default to zero.
    if [[ -n "${FAKE_HYPERLANE_SENDER}" ]]; then
      local sender_trim="${FAKE_HYPERLANE_SENDER#0x}"
      if [[ ${#sender_trim} -eq 64 ]]; then
        env_kv+=("HYPERLANE_SENDER=0x${sender_trim}")
      fi
    fi
	    if [[ -n "${FAKE_HYPERLANE_UNORDERED_EVENTS}" ]]; then
	      fake_args+=(--unordered-events "${FAKE_HYPERLANE_UNORDERED_EVENTS}")
	    fi
	    if [[ ${#fake_args[@]} -gt 0 ]]; then
	      start_process "fake-hyperlane-${profile}" \
	        env "${env_kv[@]}" "${fake_bin}" "${fake_args[@]}"
	    else
	      start_process "fake-hyperlane-${profile}" \
	        env "${env_kv[@]}" "${fake_bin}"
	    fi
	  fi

  # Brief liveness check to avoid silent failures.
  sleep 1
  local pid_file="${PIDS_DIR}/fake-hyperlane-${profile}.pid"
  if [[ ! -f "${pid_file}" ]]; then
    log_error "fake-hyperlane-${profile} did not create a pid file (log: ${log_path})"
    return 1
  fi
  local fh_pid
  fh_pid=$(cat "${pid_file}")
  if ! kill -0 "${fh_pid}" >/dev/null 2>&1; then
    log_error "fake-hyperlane-${profile} exited immediately (log: ${log_path})"
    return 1
  fi
  log_info "fake-hyperlane-${profile} running (pid ${fh_pid}); log: ${log_path}"
}

wait_for_kaspad() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] Skipping kaspad health check"
    return 0
  fi
  local max_wait=${KASPAD_STARTUP_TIMEOUT}
  log_info "Waiting for kaspad to be ready..."
  for _ in $(seq 1 ${max_wait}); do
    if [[ -f "${PIDS_DIR}/kaspad.pid" ]]; then
      local pid
      pid=$(cat "${PIDS_DIR}/kaspad.pid")
      if ! kill -0 "${pid}" 2>/dev/null; then
        log_error "kaspad process died during startup"
        log_warn "See ${LOG_DIR}/kaspad.log"
        return 1
      fi
    fi
    if command -v grpcurl >/dev/null 2>&1; then
      if grpcurl -plaintext 127.0.0.1:16110 list >/dev/null 2>&1; then
        log_success "kaspad is ready"
        return 0
      fi
    elif command -v nc >/dev/null 2>&1; then
      if nc -z 127.0.0.1 16110 2>/dev/null; then
        log_success "kaspad is listening on 127.0.0.1:16110"
        return 0
      fi
    fi
    sleep 1
  done
  log_error "kaspad did not start within ${max_wait} seconds"
  return 1
}

wait_for_igra() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] Skipping igra health check for $1"
    return 0
  fi
  local profile="$1"
  local rpc_port="$2"
  local max_wait=${IGRA_STARTUP_TIMEOUT}
  log_info "Waiting for igra-${profile} to be ready..."
  for _ in $(seq 1 ${max_wait}); do
    if [[ -f "${PIDS_DIR}/igra-${profile}.pid" ]]; then
      local pid
      pid=$(cat "${PIDS_DIR}/igra-${profile}.pid")
      if ! kill -0 "${pid}" 2>/dev/null; then
        log_error "igra-${profile} process died during startup"
        return 1
      fi
    fi
    # `/rpc` is POST-only; use `/health` for readiness checks.
    if curl -s -f "http://127.0.0.1:${rpc_port}/health" >/dev/null 2>&1; then
      log_success "igra-${profile} is ready"
      return 0
    fi
    sleep 1
  done
  log_warn "igra-${profile} health check timed out (may still be starting)"
  return 0
}

stop_igra() {
  local profile="$1"
  stop_process "fake-hyperlane-${profile}"
  stop_process "igra-${profile}"
}

generate_keys() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] Would regenerate keys and update configs"
    return
  fi

  # Remove stale data directories so persisted configs don't conflict with regenerated keys.
  if [[ -d "${IGRA_DATA}" ]]; then
    log_warn "Clearing existing IGRA data directory at ${IGRA_DATA} to avoid stale group/config state"
    rm -rf "${IGRA_DATA}"
    mkdir -p "${IGRA_DATA}"
  fi

  local backup_dir
  if [[ -d "${CONFIG_DIR}" && -n "$(ls -A "${CONFIG_DIR}" 2>/dev/null)" ]]; then
    backup_dir="${CONFIG_DIR}/config_bak_$(date +%Y%m%d_%H%M%S)"
    log_info "Backing up existing configs to ${backup_dir}"
    mkdir -p "${backup_dir}"
    if command -v rsync >/dev/null 2>&1; then
      rsync -a --exclude 'config_bak_*' "${CONFIG_DIR}/" "${backup_dir}/"
    else
      find "${CONFIG_DIR}" -maxdepth 1 ! -name 'config_bak_*' -type f -exec cp -a {} "${backup_dir}/" \;
    fi
  fi

  # Force regeneration of igra-config.toml to drop stale bootstrap entries.
  rm -f "${IGRA_CONFIG}"

  local keygen_json
  if ! keygen_json="$(run_keygen)"; then
    log_error "Key generation failed"
    exit 1
  fi
  if ! validate_keygen_output "${keygen_json}" >/dev/null 2>&1; then
    log_warn "Existing devnet-keygen output is not compatible with the current config validator; rebuilding."
    rebuild_devnet_keygen || exit 1
    keygen_json="$(run_keygen)" || exit 1
    validate_keygen_output "${keygen_json}" || {
      log_error "devnet-keygen output still invalid after rebuild"
      exit 1
    }
  fi
  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] Skipping config rewrite"
    return
  fi
  validate_json "${keygen_json}" "Keygen output" || exit 1
  local keygen_tmp
  keygen_tmp=$(mktemp)
  printf '%s\n' "${keygen_json}" > "${keygen_tmp}"

  if ! python3 "${SCRIPT_DIR}/update_devnet_config.py" \
    "$ENV_FILE" "$IGRA_CONFIG_TEMPLATE" "$CONFIG_DIR" "$IGRA_CONFIG" "$HYPERLANE_KEYS" \
    "$keygen_tmp" "$IGRA_DATA" "$RUN_ROOT" "$KEYSET_JSON"; then
    log_error "Failed to update devnet configuration"
    exit 1
  fi
}

ensure_configs() {
  local required_files=("${IGRA_CONFIG}" "${HYPERLANE_KEYS}" "${KEYSET_JSON}")
  for file in "${required_files[@]}"; do
    if [[ ! -f "${file}" ]]; then
      log_error "Missing required config: ${file}"
      log_error "Run 'generate-keys' first or use default/setup for initial generation."
      exit 1
    fi
  done
  if ! grep -q "^threshold[[:space:]]*=" "${IGRA_CONFIG}" 2>/dev/null; then
    log_error "IGRA config missing hyperlane.threshold; regenerate configs with 'generate-keys'."
    exit 1
  fi
  log_info "Verified required configs in ${CONFIG_DIR}"
}

resolve_targets() {
  local target="$1"
  case "${target}" in
    all) TARGETS=("kaspad" "kaspaminer" "signer-1" "signer-2" "signer-3") ;;
    igra) TARGETS=("signer-1" "signer-2" "signer-3") ;;
    kaspad|kaspaminer|signer-1|signer-2|signer-3) TARGETS=("${target}") ;;
    igra-signer-1) TARGETS=("signer-1") ;;
    igra-signer-2) TARGETS=("signer-2") ;;
    igra-signer-3) TARGETS=("signer-3") ;;
    *) echo "Unknown target: ${target}" >&2; exit 1 ;;
  esac
}

start_targets() {
  local target
  for target in "${TARGETS[@]}"; do
    case "${target}" in
      kaspad)
        start_kaspad
        wait_for_kaspad || exit 1
        ;;
      kaspaminer)
        if [[ ! -f "${PIDS_DIR}/kaspad.pid" ]]; then
          log_error "Cannot start miner without kaspad running"
          exit 1
        fi
        start_miner
        ;;
      signer-1)
        start_igra "signer-1" "8088"
        wait_for_igra "signer-1" "8088"
        if [[ "${NO_FAKE_HYPERLANE}" == "true" ]]; then
          log_info "Skipping fake Hyperlane for signer-1 (--no-fake-hyperlane)"
        else
          start_fake_hyperlane "signer-1" "8088"
        fi
        ;;
      signer-2)
        start_igra "signer-2" "8089"
        wait_for_igra "signer-2" "8089"
        if [[ "${NO_FAKE_HYPERLANE}" == "true" ]]; then
          log_info "Skipping fake Hyperlane for signer-2 (--no-fake-hyperlane)"
        else
          start_fake_hyperlane "signer-2" "8089"
        fi
        ;;
      signer-3)
        start_igra "signer-3" "8090"
        wait_for_igra "signer-3" "8090"
        if [[ "${NO_FAKE_HYPERLANE}" == "true" ]]; then
          log_info "Skipping fake Hyperlane for signer-3 (--no-fake-hyperlane)"
        else
          start_fake_hyperlane "signer-3" "8090"
        fi
        ;;
    esac
  done
}

stop_targets() {
  local target
  for target in "${TARGETS[@]}"; do
    case "${target}" in
      kaspad) stop_process "kaspad" ;;
      kaspaminer) stop_process "kaspaminer" ;;
      signer-1) stop_igra "signer-1" ;;
      signer-2) stop_igra "signer-2" ;;
      signer-3) stop_igra "signer-3" ;;
    esac
  done
}

show_status() {
  log_info "Devnet status (root: ${RUN_ROOT})"
  local processes=(kaspad kaspaminer igra-signer-1 igra-signer-2 igra-signer-3 fake-hyperlane-signer-1 fake-hyperlane-signer-2 fake-hyperlane-signer-3)
  for process in "${processes[@]}"; do
    local pid_file="${PIDS_DIR}/${process}.pid"
    local status_symbol="✗"
    local status_text="Not running"
    local pid_info=""
    local cmdline=""
    if [[ -f "${pid_file}" ]]; then
      local pid
      pid=$(cat "${pid_file}")
      if kill -0 "${pid}" 2>/dev/null; then
        status_symbol="✓"
        status_text="Running"
        pid_info=" (pid ${pid})"
        if command -v ps >/dev/null 2>&1; then
          local uptime
          uptime=$(ps -p "${pid}" -o etime= 2>/dev/null | tr -d ' ')
          [[ -n "${uptime}" ]] && pid_info+=" [uptime: ${uptime}]"
          cmdline=$(ps -ww -p "${pid}" -o args= 2>/dev/null | tr -d '\n')
        fi
      else
        status_symbol="⚠"
        status_text="Stale PID file"
      fi
    fi
    printf "  %-28s %s %s%s\n" "${process}" "${status_symbol}" "${status_text}" "${pid_info}"
    if [[ -n "${cmdline}" ]]; then
      printf "    cmd: %s\n" "${cmdline}"
    fi
  done
  log_info "Logs: ${LOG_DIR}"
  log_info "Data: ${RUN_ROOT}"
}

resolve_targets "${TARGET_ARG}"

case "${COMMAND}" in
  setup)
    setup_config_source
    require_binaries_present
    prepare_igra_config
    generate_keys
    ensure_configs
    log_success "Setup complete. Configs in ${CONFIG_DIR}. Binaries expected in ${BIN_DIR}."
    exit 0
    ;;
  build)
    prepare_sources
    setup_config_source
    resolve_binaries_from_target
    stage_binaries
    log_success "Build complete. Binaries staged in ${BIN_DIR}."
    exit 0
    ;;
  default)
    prepare_sources
    setup_config_source
    resolve_binaries_from_target
    stage_binaries
    generate_keys
    log_success "Default completed: built (clone), regenerated keys, staged binaries, updated configs in ${CONFIG_DIR}."
    exit 0
    ;;
  generate-keys)
    setup_config_source
    generate_keys
    log_success "Keys regenerated and configs written to ${CONFIG_DIR}. Existing data dirs may be incompatible with new keys."
    exit 0
    ;;
  start)
    setup_config_source
    require_binaries_present
    ensure_configs
    start_targets
    # Keep processes running after script exits: disable cleanup trap and clear PIDS.
    trap - EXIT INT TERM
    PIDS=()
    ;;
  stop)
    stop_targets
    exit 0
    ;;
  restart)
    stop_targets
    setup_config_source
    require_binaries_present
    ensure_configs
    start_targets
    trap - EXIT INT TERM
    PIDS=()
    ;;
  status)
    show_status
    exit 0
    ;;
esac

echo "Rothschild wallet data directory: ${WALLET_DATA}"
echo "Binary: ${ROTHSCHILD_BIN}"
echo "Example: ROTHSCHILD_WALLET_DIR=${WALLET_DATA} ${ROTHSCHILD_BIN} wallet list --network devnet --wallet \"${KASPA_DEVNET_WALLET_NAME:-devnet}\""

if [[ ${#PIDS[@]} -gt 0 ]]; then
  echo "Processes started: ${PIDS[*]}. Ctrl+C to stop."
  wait -n "${PIDS[@]}" 2>/dev/null || true
fi
