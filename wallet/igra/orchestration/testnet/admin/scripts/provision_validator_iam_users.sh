#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  provision_validator_iam_users.sh --bundles-run-dir <dir> --bucket <checkpoints-bucket> --region <aws-region> [--overwrite-env]

Creates one IAM user per bundle (validator writer) with a prefix-scoped policy and writes the resulting
AWS credentials into each bundle's `.env`.

Inputs:
  - Reads `<bundle>/to-admin.json` for:
      - aws.validator_checkpoints_prefix
      - aws.suggested_validator_iam_user

Writes:
  - Updates `<bundle>/.env` with:
      AWS_ACCESS_KEY_ID
      AWS_SECRET_ACCESS_KEY
      AWS_REGION
      HYP_CHECKPOINTS_S3_BUCKET
      HYP_CHECKPOINTS_S3_REGION

WARNING:
  - This creates AWS IAM users and access keys.
  - Secret access keys are only returned once; this script writes them to bundle `.env` (chmod 600).
  - Intended for testnet-v1 convenience. Production-aligned operation should use instance roles or operator-owned creds.
EOF
}

bundles_run_dir=""
bucket=""
region=""
overwrite_env="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundles-run-dir) bundles_run_dir="$2"; shift 2;;
    --bucket) bucket="$2"; shift 2;;
    --region) region="$2"; shift 2;;
    --overwrite-env) overwrite_env="true"; shift;;
    --help|-h) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 1;;
  esac
done

if [[ -z "${bundles_run_dir}" || -z "${bucket}" || -z "${region}" ]]; then
  usage
  exit 1
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "missing required command: aws" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "missing required command: python3" >&2
  exit 1
fi

run_dir="$(cd "${bundles_run_dir}" && pwd)"
if [[ ! -d "${run_dir}" ]]; then
  echo "bundles run dir not found: ${run_dir}" >&2
  exit 1
fi

set_env_kv() {
  local file="$1"
  local key="$2"
  local value="$3"

  if [[ ! -f "${file}" ]]; then
    touch "${file}"
  fi

  if grep -qE "^${key}=" "${file}"; then
    if [[ "${overwrite_env}" != "true" ]]; then
      return 0
    fi
    # Replace line (portable-ish for macOS and GNU sed).
    tmp="$(mktemp)"
    awk -v k="${key}" -v v="${value}" 'BEGIN{FS=OFS="="} $1==k {$0=k"="v} {print}' "${file}" > "${tmp}"
    mv "${tmp}" "${file}"
  else
    printf "%s=%s\n" "${key}" "${value}" >> "${file}"
  fi
}

for bundle in "${run_dir}"/signer-*; do
  [[ -d "${bundle}" ]] || continue
  to_admin="${bundle}/to-admin.json"
  env_file="${bundle}/.env"
  if [[ ! -f "${to_admin}" ]]; then
    echo "skipping (missing to-admin.json): ${bundle}" >&2
    continue
  fi
  if [[ ! -f "${env_file}" ]]; then
    echo "skipping (missing .env): ${bundle}" >&2
    continue
  fi

  iam_user="$(python3 - <<PY
import json
from pathlib import Path
data = json.loads(Path(r"""${to_admin}""").read_text(encoding="utf-8"))
print(data["aws"]["suggested_validator_iam_user"])
PY
)"
  prefix="$(python3 - <<PY
import json
from pathlib import Path
data = json.loads(Path(r"""${to_admin}""").read_text(encoding="utf-8"))
print(data["aws"]["validator_checkpoints_prefix"].rstrip("/"))
PY
)"

  if [[ -z "${iam_user}" || -z "${prefix}" ]]; then
    echo "invalid to-admin.json (missing aws fields): ${to_admin}" >&2
    exit 1
  fi

  echo "Provisioning IAM user for ${bundle##*/}: user=${iam_user} prefix=${prefix}/"

  aws iam create-user --user-name "${iam_user}" >/dev/null 2>&1 || true

  policy_name="igra-testnet-v1-${iam_user}-checkpoints-writer"
  policy_doc="$(cat <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowWriteValidatorPrefix",
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:AbortMultipartUpload"],
      "Resource": ["arn:aws:s3:::${bucket}/${prefix}/*"]
    },
    {
      "Sid": "AllowListValidatorPrefixOnly",
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": ["arn:aws:s3:::${bucket}"],
      "Condition": {
        "StringLike": {
          "s3:prefix": ["${prefix}/*"]
        }
      }
    }
  ]
}
JSON
)"

  aws iam put-user-policy --user-name "${iam_user}" --policy-name "${policy_name}" --policy-document "${policy_doc}" >/dev/null

  # Create a new access key and write it into the bundle.
  # Note: the secret access key is only returned once, here.
  creds_json="$(aws iam create-access-key --user-name "${iam_user}")"
  access_key_id="$(python3 - <<PY
import json, sys
data = json.loads(sys.stdin.read())
print(data["AccessKey"]["AccessKeyId"])
PY
<<<"${creds_json}")"
  secret_access_key="$(python3 - <<PY
import json, sys
data = json.loads(sys.stdin.read())
print(data["AccessKey"]["SecretAccessKey"])
PY
<<<"${creds_json}")"

  if [[ -z "${access_key_id}" || -z "${secret_access_key}" ]]; then
    echo "failed to create access key for user=${iam_user}" >&2
    exit 1
  fi

  set_env_kv "${env_file}" "AWS_ACCESS_KEY_ID" "${access_key_id}"
  set_env_kv "${env_file}" "AWS_SECRET_ACCESS_KEY" "${secret_access_key}"
  set_env_kv "${env_file}" "AWS_REGION" "${region}"
  set_env_kv "${env_file}" "HYP_CHECKPOINTS_S3_BUCKET" "${bucket}"
  set_env_kv "${env_file}" "HYP_CHECKPOINTS_S3_REGION" "${region}"
  chmod 600 "${env_file}" || true

  echo "Updated ${env_file}"
done

echo "Done"

