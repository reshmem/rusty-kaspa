#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bootstrap_aws_s3.sh --region <aws-region> [--registry-bucket <name>] [--checkpoints-bucket <name>]

Creates the S3 buckets for testnet-v1 and applies public-read bucket policies.

WARNING:
  This creates AWS resources. Review before running.

Defaults:
  registry-bucket    = igra-hyperlane-registry-testnet
  checkpoints-bucket = igra-hyperlane-checkpoints-testnet
EOF
}

igra_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
region=""
registry_bucket="igra-hyperlane-registry-testnet"
checkpoints_bucket="igra-hyperlane-checkpoints-testnet"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --region) region="$2"; shift 2;;
    --registry-bucket) registry_bucket="$2"; shift 2;;
    --checkpoints-bucket) checkpoints_bucket="$2"; shift 2;;
    --help|-h) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 1;;
  esac
done

if [[ -z "${region}" ]]; then
  echo "missing --region" >&2
  exit 1
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "missing required command: aws" >&2
  exit 1
fi

aws_dir="${igra_root}/orchestration/testnet/aws"
reg_pol="${aws_dir}/s3-registry-public-read-bucket-policy.json"
chk_pol="${aws_dir}/s3-checkpoints-public-read-bucket-policy.json"

tmp_dir="${igra_root}/orchestration/testnet/admin/.tmp"
mkdir -p "${tmp_dir}"

reg_pol_tmp="${tmp_dir}/registry-policy.json"
chk_pol_tmp="${tmp_dir}/checkpoints-policy.json"

sed "s/igra-hyperlane-registry-testnet/${registry_bucket}/g" "${reg_pol}" > "${reg_pol_tmp}"
sed "s/igra-hyperlane-checkpoints-testnet/${checkpoints_bucket}/g" "${chk_pol}" > "${chk_pol_tmp}"

echo "Creating buckets (if missing)..."
aws s3api create-bucket --bucket "${registry_bucket}" --region "${region}" --create-bucket-configuration LocationConstraint="${region}" 2>/dev/null || true
aws s3api create-bucket --bucket "${checkpoints_bucket}" --region "${region}" --create-bucket-configuration LocationConstraint="${region}" 2>/dev/null || true

echo "Applying public-read bucket policies..."
aws s3api put-bucket-policy --bucket "${registry_bucket}" --policy "file://${reg_pol_tmp}"
aws s3api put-bucket-policy --bucket "${checkpoints_bucket}" --policy "file://${chk_pol_tmp}"

echo "Done"

