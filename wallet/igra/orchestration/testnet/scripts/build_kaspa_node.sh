#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  build_kaspa_node.sh [--release] [--target-dir DIR]

Builds the Kaspa node binary (`kaspad`) from the `rusty-kaspa` workspace root.

Notes:
  - This repo layout is `rusty-kaspa/wallet/igra/...`, so the workspace root is two directories above the Igra repo root.
  - If your environment has a global `CARGO_TARGET_DIR` pointing to a protected volume, pass `--target-dir` to avoid EACCES.
EOF
}

release="true"
target_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release) release="true"; shift;;
    --target-dir) target_dir="$2"; shift 2;;
    --help|-h) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 1;;
  esac
done

igra_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
workspace_root="$(cd "${igra_root}/../.." && pwd)"

if [[ ! -f "${workspace_root}/Cargo.toml" ]]; then
  echo "workspace root not found at: ${workspace_root}" >&2
  exit 1
fi

if [[ -z "${target_dir}" ]]; then
  target_dir="${workspace_root}/target-igra-testnet"
fi

profile_args=()
if [[ "${release}" == "true" ]]; then
  profile_args+=(--release)
fi

echo "Building kaspad..."
echo "  workspace_root=${workspace_root}"
echo "  target_dir=${target_dir}"

cd "${workspace_root}"
CARGO_TARGET_DIR="${target_dir}" RUSTC_WRAPPER= SCCACHE_DISABLE=1 cargo build "${profile_args[@]}" -p kaspad

bin_path="${target_dir}/$( [[ "${release}" == "true" ]] && echo release || echo debug )/kaspad"
echo "Built: ${bin_path}"

if [[ -f "${igra_root}/orchestration/testnet/scripts/update_bundle_env_example.py" ]]; then
  python3 "${igra_root}/orchestration/testnet/scripts/update_bundle_env_example.py" || true
fi
