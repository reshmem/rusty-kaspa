#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  build_hyperlane_agents.sh [--clone] [--update] [--repo-dir DIR] [--ref REF] [--target-dir DIR]

Builds Hyperlane Rust agents needed by testnet-v1:
  - validator
  - relayer (built with `--features kaspa`)

Defaults:
  - Repo URL: https://github.com/reshmem/hyperlane-monorepo.git
  - Ref/branch: devel
  - Repo dir: $HOME/Source/personal/hyperlane-monorepo

Notes:
  - testnet-v1 requires the `reshmem/hyperlane-monorepo` fork (Kaspa-enabled + local dev compat).
  - This script only builds Rust agents (no pnpm/typescript).
EOF
}

clone="false"
update="false"
repo_dir="${HOME}/Source/personal/hyperlane-monorepo"
ref="devel"
target_dir=""

repo_url="${HYPERLANE_REPO_URL:-https://github.com/reshmem/hyperlane-monorepo.git}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clone) clone="true"; shift;;
    --update) update="true"; shift;;
    --repo-dir) repo_dir="$2"; shift 2;;
    --ref) ref="$2"; shift 2;;
    --target-dir) target_dir="$2"; shift 2;;
    --help|-h) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 1;;
  esac
done

if [[ "${clone}" == "true" && ! -d "${repo_dir}" ]]; then
  echo "Cloning Hyperlane repo..."
  echo "  url=${repo_url}"
  echo "  dir=${repo_dir}"
  git clone "${repo_url}" "${repo_dir}"
fi

if [[ ! -d "${repo_dir}/.git" ]]; then
  echo "missing hyperlane repo dir (pass --clone or set --repo-dir): ${repo_dir}" >&2
  exit 1
fi

cd "${repo_dir}"

if [[ "${update}" == "true" ]]; then
  echo "Updating Hyperlane repo..."
  git fetch --all --prune
fi

echo "Checking out ref=${ref} ..."
git checkout "${ref}"
if [[ "${update}" == "true" ]]; then
  git pull --ff-only || true
fi

rust_main="${repo_dir}/rust/main"
if [[ ! -f "${rust_main}/Cargo.toml" ]]; then
  echo "missing rust/main Cargo.toml at: ${rust_main}" >&2
  exit 1
fi

cd "${rust_main}"

if [[ -z "${target_dir}" ]]; then
  target_dir="${repo_dir}/target-igra-testnet"
fi

echo "Building Hyperlane agents..."
echo "  repo_dir=${repo_dir}"
echo "  target_dir=${target_dir}"

CARGO_TARGET_DIR="${target_dir}" RUSTC_WRAPPER= SCCACHE_DISABLE=1 cargo build --release -p validator
# testnet-v1 relaying requires Kaspa support (feature-gated in hyperlane-base).
CARGO_TARGET_DIR="${target_dir}" RUSTC_WRAPPER= SCCACHE_DISABLE=1 cargo build --release -p relayer --features kaspa

cat > "${target_dir}/igra-build-info.json" <<JSON
{
  "relayer_features": ["kaspa"],
  "ref": "$(printf '%s' "${ref}")",
  "built_at_unix": $(date +%s)
}
JSON

echo "Built:"
echo "  ${target_dir}/release/validator"
echo "  ${target_dir}/release/relayer"

igra_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export HYPERLANE_REPO_DIR="${repo_dir}"
if [[ -f "${igra_root}/orchestration/testnet/scripts/update_bundle_env_example.py" ]]; then
  python3 "${igra_root}/orchestration/testnet/scripts/update_bundle_env_example.py" || true
fi
