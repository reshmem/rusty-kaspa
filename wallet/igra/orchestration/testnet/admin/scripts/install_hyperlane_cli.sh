#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  install_hyperlane_cli.sh [--version <npm-version>] [--tools-dir <dir>]

Installs Hyperlane CLI (`@hyperlane-xyz/cli`) into a local directory:
  <tools-dir>/hyperlane-cli/node_modules/.bin/hyperlane

Defaults:
  --version 21.1.0
  --tools-dir orchestration/testnet/admin/.tools
EOF
}

version="21.1.0"
igra_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
tools_dir="${igra_root}/orchestration/testnet/admin/.tools"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="$2"; shift 2;;
    --tools-dir) tools_dir="$2"; shift 2;;
    --help|-h) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 1;;
  esac
done

if ! command -v node >/dev/null 2>&1; then
  echo "missing required command: node" >&2
  exit 1
fi
if ! command -v npm >/dev/null 2>&1; then
  echo "missing required command: npm" >&2
  exit 1
fi

mkdir -p "${tools_dir}/hyperlane-cli"
cd "${tools_dir}/hyperlane-cli"

if [[ ! -f package.json ]]; then
  npm init -y >/dev/null 2>&1
fi

echo "Installing Hyperlane CLI..."
echo "  version=@hyperlane-xyz/cli@${version}"
echo "  dir=${tools_dir}/hyperlane-cli"

npm install --no-fund --no-audit "@hyperlane-xyz/cli@${version}"

# Also install `ethers` for small local admin helper scripts (e.g., key -> address).
npm install --no-fund --no-audit "ethers@6"

bin="${tools_dir}/hyperlane-cli/node_modules/.bin/hyperlane"
if [[ ! -x "${bin}" ]]; then
  echo "install succeeded but hyperlane binary not found at: ${bin}" >&2
  exit 1
fi

echo "Installed: ${bin}"
