#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  sync_hyperlane_registry.sh --bucket <s3-bucket> --dest <local-dir> [--prefix <s3-prefix>]

Example:
  sync_hyperlane_registry.sh --bucket igra-hyperlane-registry-testnet --dest /tmp/igra-hyperlane-registry

Notes:
  - Bucket may be public-read; AWS credentials are not required for public objects.
  - This script uses `aws s3 sync`.
EOF
}

bucket=""
dest=""
prefix=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bucket) bucket="$2"; shift 2;;
    --dest) dest="$2"; shift 2;;
    --prefix) prefix="$2"; shift 2;;
    --help|-h) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 1;;
  esac
done

if [[ -z "${bucket}" || -z "${dest}" ]]; then
  usage
  exit 1
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "missing required command: aws" >&2
  exit 1
fi

src="s3://${bucket}"
if [[ -n "${prefix}" ]]; then
  src="${src%/}/${prefix#/}"
fi

mkdir -p "${dest}"
echo "Syncing ${src} -> ${dest}"
aws s3 sync --only-show-errors "${src}" "${dest}"
echo "Done"

