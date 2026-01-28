#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  run_testnet_v1_signer.sh --bundle <path> [--checkpoint-syncer local|s3] start
  run_testnet_v1_signer.sh --bundle <path> stop
  run_testnet_v1_signer.sh --bundle <path> status

Required:
  --bundle PATH   Path to per-signer bundle directory (e.g. orchestration/testnet/bundles/.../signer-01)
  --checkpoint-syncer local|s3  Optional override for HYP_CHECKPOINT_SYNCER

Environment:
  IGRA_BIN                 Path to `kaspa-threshold-service` binary (default: ./target/release/kaspa-threshold-service)
  IGRA_SECRETS_PASSPHRASE   REQUIRED: passphrase for data/secrets.bin (non-interactive start)
  HYP_VALIDATOR_BIN        Path to Hyperlane `validator` binary (default: validator in PATH)
  HYP_RELAYER_BIN          Path to Hyperlane `relayer` binary (default: relayer in PATH)
  IGRA_EVM_RPC_URL         REQUIRED: origin EVM JSON-RPC URL (shared testnet node)
  HYP_REGISTRY_DIR         Optional: local Hyperlane registry dir containing chains/<origin>/addresses.yaml
  HYP_REGISTRY_S3_BUCKET   Required if HYP_REGISTRY_DIR is unset: S3 bucket containing the registry
  HYP_REGISTRY_S3_PREFIX   Optional: S3 prefix (default: empty)
  HYP_CHECKPOINT_SYNCER     Optional: local|s3 (default: s3)
  HYP_CHECKPOINTS_S3_BUCKET Required if HYP_CHECKPOINT_SYNCER=s3: S3 bucket name for checkpoints
  HYP_CHECKPOINTS_S3_REGION Required if HYP_CHECKPOINT_SYNCER=s3: AWS region for checkpoints bucket
  HYP_EVM_SIGNER_KEY_HEX    REQUIRED: funded EVM private key (hex; with or without 0x) for relayer construction

Notes:
  - This script does not run an Igra EVM node (unimplemented in testnet-v1).
  - Kaspa node startup is not automated here; run `kaspad --testnet` separately and ensure grpc is on 127.0.0.1:16110.
  - The bundle contains `.env` with the required env vars.
  - Funding requirement: admin must fund BOTH the validator EVM address (for one-time validatorAnnounce) and the relayer EVM address.
EOF
}

BUNDLE=""
CHECKPOINT_SYNCER_OVERRIDE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle) BUNDLE="$2"; shift 2;;
    --checkpoint-syncer) CHECKPOINT_SYNCER_OVERRIDE="$2"; shift 2;;
    --help|-h) usage; exit 0;;
    *) break;;
  esac
done

cmd="${1:-}"
if [[ -z "${cmd}" ]]; then usage; exit 1; fi
if [[ -z "${BUNDLE}" ]]; then echo "missing --bundle"; exit 1; fi

bundle_dir="$(cd "${BUNDLE}" && pwd)"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
config_dir="${bundle_dir}/config"
data_dir="${bundle_dir}/data"
hyperlane_dir="${bundle_dir}/hyperlane"
logs_dir="${bundle_dir}/logs"
pids_dir="${bundle_dir}/pids"

mkdir -p "${logs_dir}" "${pids_dir}"

hyp_validator_bin="${HYP_VALIDATOR_BIN:-validator}"
hyp_relayer_bin="${HYP_RELAYER_BIN:-relayer}"
igra_bin="${IGRA_BIN:-${repo_root}/target/release/kaspa-threshold-service}"

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "missing required env var: ${name}" >&2
    exit 1
  fi
}

read_yaml_key() {
  local file="$1"
  local key="$2"
  # Very small YAML helper for `key: value` lines (addresses.yaml format).
  # Returns the raw value without surrounding quotes.
  local line
  line="$(grep -E "^${key}:" "${file}" | head -n 1 | sed -E "s/^${key}:[[:space:]]*//")" || true
  echo "${line}" | tr -d '"' | tr -d "'"
}

read_rpc_addr() {
  local file="$1"
  # Extract `[rpc] addr = "127.0.0.1:8088"` from TOML without requiring a TOML parser.
  awk '
    /^\[rpc\]$/ {in=1; next}
    /^\[/ {in=0}
    in && /^[[:space:]]*addr[[:space:]]*=/ {
      line=$0
      sub(/.*=/, "", line)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
      gsub(/"/, "", line)
      print line
      exit
    }
  ' "${file}"
}

start_process() {
  local name="$1"; shift
  local pid_file="${pids_dir}/${name}.pid"
  local log_file="${logs_dir}/${name}.log"
  if [[ -f "${pid_file}" ]]; then
    local pid
    pid="$(cat "${pid_file}")"
    if kill -0 "${pid}" >/dev/null 2>&1; then
      echo "already running: ${name} pid=${pid}"
      return 0
    fi
    rm -f "${pid_file}"
  fi
  echo "starting ${name}..."
  ( "$@" >>"${log_file}" 2>&1 ) &
  echo $! >"${pid_file}"
  echo "pid=$! log=${log_file}"
}

stop_process() {
  local name="$1"
  local pid_file="${pids_dir}/${name}.pid"
  if [[ ! -f "${pid_file}" ]]; then
    echo "not running: ${name}"
    return 0
  fi
  local pid
  pid="$(cat "${pid_file}")"
  if kill -0 "${pid}" >/dev/null 2>&1; then
    echo "stopping ${name} pid=${pid}..."
    kill "${pid}" || true
  fi
  rm -f "${pid_file}"
}

case "${cmd}" in
  start)
    require_env IGRA_SECRETS_PASSPHRASE
    require_env IGRA_EVM_RPC_URL
    hyp_checkpoint_syncer="${CHECKPOINT_SYNCER_OVERRIDE:-${HYP_CHECKPOINT_SYNCER:-s3}}"
    if [[ "${hyp_checkpoint_syncer}" != "local" && "${hyp_checkpoint_syncer}" != "s3" ]]; then
      echo "invalid HYP_CHECKPOINT_SYNCER (expected local|s3): ${hyp_checkpoint_syncer}" >&2
      exit 1
    fi
    if [[ "${hyp_checkpoint_syncer}" == "s3" ]]; then
      require_env HYP_CHECKPOINTS_S3_BUCKET
      require_env HYP_CHECKPOINTS_S3_REGION
    fi

    if [[ ! -x "${igra_bin}" ]]; then
      echo "missing igra binary: ${igra_bin}" >&2
      exit 1
    fi

    bundle_name="$(basename "${bundle_dir}")"
    if [[ "${bundle_name}" =~ ^signer-([0-9]{2})$ ]]; then
      signer_num="${BASH_REMATCH[1]}"
      signer_index=$((10#${signer_num} - 1))
    else
      echo "unexpected bundle dir name (expected signer-XX): ${bundle_name}" >&2
      exit 1
    fi
    validator_name="${bundle_name/signer/validator}"

    rpc_addr="$(read_rpc_addr "${config_dir}/igra-config.toml")"
    if [[ -z "${rpc_addr}" ]]; then
      echo "failed to parse [rpc].addr from: ${config_dir}/igra-config.toml" >&2
      exit 1
    fi
    kaspa_rpc_url="http://${rpc_addr}"

    origin_chain="igratestnet4"
    hyp_registry_dir="${HYP_REGISTRY_DIR:-}"
    if [[ -z "${hyp_registry_dir}" ]]; then
      require_env HYP_REGISTRY_S3_BUCKET
      if ! command -v aws >/dev/null 2>&1; then
        echo "missing required command for S3 registry sync: aws" >&2
        exit 1
      fi
      hyp_registry_dir="${hyperlane_dir}/registry"
      mkdir -p "${hyp_registry_dir}"
      src="s3://${HYP_REGISTRY_S3_BUCKET}"
      if [[ -n "${HYP_REGISTRY_S3_PREFIX:-}" ]]; then
        src="${src%/}/${HYP_REGISTRY_S3_PREFIX#/}"
      fi
      echo "Syncing Hyperlane registry: ${src} -> ${hyp_registry_dir}"
      aws s3 sync --only-show-errors "${src}/" "${hyp_registry_dir}/"
    fi
    origin_addresses="${hyp_registry_dir}/chains/${origin_chain}/addresses.yaml"
    if [[ ! -f "${origin_addresses}" ]]; then
      echo "missing registry addresses.yaml: ${origin_addresses}" >&2
      exit 1
    fi
    mailbox="$(read_yaml_key "${origin_addresses}" "mailbox")"
    igp="$(read_yaml_key "${origin_addresses}" "interchainGasPaymaster")"
    va="$(read_yaml_key "${origin_addresses}" "validatorAnnounce")"
    mth="$(read_yaml_key "${origin_addresses}" "merkleTreeHook")"
    if [[ -z "${mailbox}" || -z "${va}" || -z "${mth}" ]]; then
      echo "addresses.yaml missing required keys (mailbox/validatorAnnounce/merkleTreeHook)" >&2
      exit 1
    fi
    if [[ -z "${igp}" ]]; then
      igp="0x0000000000000000000000000000000000000000"
    fi

    # Start Igra signer first (destination endpoint for relayer -> Kaspa adapter).
    start_process "igra-signer" "${igra_bin}" --network testnet --config "${config_dir}/igra-config.toml"

    # Prepare Hyperlane agent configs (kept inside the bundle dir).
    vkey_hex="$(cat "${hyperlane_dir}/validator-private-key.hex" | tr -d '\n' | tr -d '\r')"
    if [[ -z "${vkey_hex}" ]]; then
      echo "missing hyperlane validator key: ${hyperlane_dir}/validator-private-key.hex" >&2
      exit 1
    fi

    # NOTE: for now, the relayer requires an EVM signer key even when only relaying EVM->Kaspa.
    # Provide it via env to keep it out of the bundle by default.
    require_env HYP_EVM_SIGNER_KEY_HEX
    evm_priv_hex="${HYP_EVM_SIGNER_KEY_HEX#0x}"
    if [[ ! "${evm_priv_hex}" =~ ^[0-9a-fA-F]{64}$ ]]; then
      echo "invalid HYP_EVM_SIGNER_KEY_HEX: expected 32-byte hex (64 chars), got: $(printf '%q' "${HYP_EVM_SIGNER_KEY_HEX}")" >&2
      echo "hint: set HYP_EVM_SIGNER_KEY_HEX to a funded EVM private key (with or without 0x)" >&2
      exit 1
    fi

    # Generate agent.json files via python (avoids fragile here-doc templating).
    python3 - <<PY
import json
from pathlib import Path

bundle = Path(r"""${bundle_dir}""")
hyperlane_dir = bundle / "hyperlane"
validator_dir = hyperlane_dir / "validator"
relayer_dir = hyperlane_dir / "relayer"
cfg_v = validator_dir / "config" / "agent.json"
cfg_r = relayer_dir / "config" / "agent.json"
cfg_v.parent.mkdir(parents=True, exist_ok=True)
cfg_r.parent.mkdir(parents=True, exist_ok=True)
(validator_dir / "validator-db").mkdir(parents=True, exist_ok=True)
(relayer_dir / "relayer-db").mkdir(parents=True, exist_ok=True)
(validator_dir / "checkpoints").mkdir(parents=True, exist_ok=True)

origin_chain = "igratestnet4"
origin_chain_id = 38836
origin_domain_id = 38836
dest_chain = "kaspa-testnet"
dest_domain_id = int("0x4B415354", 16)  # KAST

mailbox = r"""${mailbox}"""
igp = r"""${igp}"""
va = r"""${va}"""
mth = r"""${mth}"""
evm_rpc = r"""${IGRA_EVM_RPC_URL}"""
kaspa_rpc = r"""${kaspa_rpc_url}"""
group_id_hex = (bundle / "group_id.hex").read_text(encoding="utf-8").strip()
group_h256 = "0x" + group_id_hex

vpriv = r"""${vkey_hex}"""
evm_priv = r"""${evm_priv_hex}"""
hyp_checkpoint_syncer = r"""${hyp_checkpoint_syncer}"""
validator_name = r"""${validator_name}"""
signer_index = int(r"""${signer_index}""")

validator_checkpoint_syncer = None
if hyp_checkpoint_syncer == "local":
  validator_checkpoint_syncer = {
    "type": "localStorage",
    "path": str(validator_dir / "checkpoints"),
  }
elif hyp_checkpoint_syncer == "s3":
  validator_checkpoint_syncer = {
    "type": "s3",
    "bucket": r"""${HYP_CHECKPOINTS_S3_BUCKET:-}""",
    "region": r"""${HYP_CHECKPOINTS_S3_REGION:-}""",
    "folder": f"checkpoints/97b4/{validator_name}",
  }
else:
  raise SystemExit(f"unexpected hyp_checkpoint_syncer: {hyp_checkpoint_syncer}")

validator_cfg = {
  "metricsPort": 9910 + signer_index,
  "log": { "level": "info", "format": "pretty" },
  "originChainName": origin_chain,
  "db": str(validator_dir / "validator-db"),
  "validator": { "type": "hexKey", "key": "0x" + vpriv },
  "checkpointSyncer": validator_checkpoint_syncer,
  "chains": {
    origin_chain: {
      "name": origin_chain,
      "chainId": origin_chain_id,
      "domainId": origin_domain_id,
      "protocol": "ethereum",
      "submitter": "Classic",
      "rpcUrls": [{"http": evm_rpc}],
      "mailbox": mailbox,
      "interchainGasPaymaster": igp,
      "validatorAnnounce": va,
      "merkleTreeHook": mth,
      "blocks": { "estimateBlockTime": 2, "reorgPeriod": 2 },
      "index": { "from": 0, "chunk": 1999, "mode": "block" },
    }
  }
}

relayer_cfg = {
  "metricsPort": 9920 + signer_index,
  "log": { "level": "info", "format": "pretty" },
  "allowLocalCheckpointSyncers": hyp_checkpoint_syncer == "local",
  "relayChains": f"{origin_chain},{dest_chain}",
  "db": str(relayer_dir / "relayer-db"),
  "chains": {
    origin_chain: {
      "name": origin_chain,
      "chainId": origin_chain_id,
      "domainId": origin_domain_id,
      "protocol": "ethereum",
      "submitter": "Classic",
      "signer": { "type": "hexKey", "key": "0x" + evm_priv },
      "rpcUrls": [{"http": evm_rpc}],
      "mailbox": mailbox,
      "interchainGasPaymaster": igp,
      "validatorAnnounce": va,
      "merkleTreeHook": mth,
      "blocks": { "estimateBlockTime": 2, "reorgPeriod": 2 },
      "index": { "from": 0, "chunk": 1999, "mode": "block" },
    },
    dest_chain: {
      "name": dest_chain,
      "domainId": dest_domain_id,
      "protocol": "kaspa",
      "rpcUrls": [{"http": kaspa_rpc}],
      "mailbox": group_h256,
      "interchainGasPaymaster": group_h256,
      "validatorAnnounce": group_h256,
      "merkleTreeHook": group_h256,
      "blocks": { "estimateBlockTime": 2, "reorgPeriod": 2 },
      "index": { "from": 0, "chunk": 1999, "mode": "sequence" },
    },
  },
}

cfg_v.write_text(json.dumps(validator_cfg, indent=2) + "\\n", encoding="utf-8")
cfg_r.write_text(json.dumps(relayer_cfg, indent=2) + "\\n", encoding="utf-8")
print("Wrote", cfg_v)
print("Wrote", cfg_r)
PY

    start_process "hyperlane-validator" bash -lc "cd \"${hyperlane_dir}/validator\" && \"${hyp_validator_bin}\""
    start_process "hyperlane-relayer" bash -lc "cd \"${hyperlane_dir}/relayer\" && \"${hyp_relayer_bin}\""
    ;;
  stop)
    stop_process "hyperlane-relayer"
    stop_process "hyperlane-validator"
    stop_process "igra-signer"
    ;;
  status)
    for name in igra-signer hyperlane-validator hyperlane-relayer; do
      pid_file="${pids_dir}/${name}.pid"
      if [[ -f "${pid_file}" ]] && kill -0 "$(cat "${pid_file}")" >/dev/null 2>&1; then
        echo "running: ${name} pid=$(cat "${pid_file}")"
      else
        echo "stopped: ${name}"
      fi
    done
    ;;
  *)
    usage
    exit 1
    ;;
esac
