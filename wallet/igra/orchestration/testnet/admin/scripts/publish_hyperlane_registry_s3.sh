#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  publish_hyperlane_registry_s3.sh [--registry-dir <dir>] [--bucket <name>] [--prefix <s3-prefix>]

Uploads the local Hyperlane registry directory to S3.

Required env:
  AWS_REGION (or AWS_PROFILE + configured region)

Defaults:
  registry-dir = orchestration/testnet/admin/.tmp/registry
  bucket       = $HYP_REGISTRY_S3_BUCKET or igra-hyperlane-registry-testnet
  prefix       = (empty)
EOF
}

igra_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
registry_dir="${igra_root}/orchestration/testnet/admin/.tmp/registry"
bucket="${HYP_REGISTRY_S3_BUCKET:-igra-hyperlane-registry-testnet}"
prefix=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --registry-dir) registry_dir="$2"; shift 2;;
    --bucket) bucket="$2"; shift 2;;
    --prefix) prefix="$2"; shift 2;;
    --help|-h) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 1;;
  esac
done

if ! command -v aws >/dev/null 2>&1; then
  echo "missing required command: aws" >&2
  exit 1
fi

if [[ ! -d "${registry_dir}/chains" ]]; then
  echo "missing registry dir (expected chains/): ${registry_dir}" >&2
  exit 1
fi

dst="s3://${bucket}"
if [[ -n "${prefix}" ]]; then
  dst="${dst%/}/${prefix#/}"
fi

echo "Publishing Hyperlane registry to S3..."
echo "  src=${registry_dir}"
echo "  dst=${dst}"

aws s3 sync --only-show-errors "${registry_dir}/" "${dst}/"
echo "Done"

