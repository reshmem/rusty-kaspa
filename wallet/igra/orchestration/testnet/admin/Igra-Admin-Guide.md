# Igra Admin Guide (testnet-v1)

This guide describes what the **Igra admin/deployer** does to:
- deploy Hyperlane core contracts on the origin EVM chain (`igra-testnet-4`)
- publish the Hyperlane **registry** to S3 (canonical shared source of contract addresses)
- prepare the artifacts that signer operators need

Design reference:
- `docs/wip/testnet-v1.md`

Prerequisites checklist:
- `orchestration/testnet/PREREQS.md`

---

## 0) Concepts (1 paragraph)

Hyperlane **registry** is a directory of YAML files (metadata + deployed contract addresses) that validators/relayers use to know which contracts exist on each chain.
For testnet-v1 we publish this registry to S3 so every operator can sync it locally.

**Option A (single machine, no S3):**
- Skip all S3/IAM steps (registry + checkpoints).
- Use the local registry directory produced by `deploy_hyperlane_core.sh`.
- Explicitly set `HYP_CHECKPOINT_SYNCER=local` (bundles default to `s3`).

---

## 0.1 Secrets model (v1 vs future)

**Testnet-v1 (current):**
- For operational speed, we allow the **admin** to generate the per-signer bundles and therefore the admin will temporarily have access to:
  - each signer’s encrypted `secrets.bin` (and the passphrase used at generation time)
  - each signer’s Hyperlane validator private key (`validator-private-key.hex`)
- This is acceptable for an early testnet iteration, but it is **not** the long-term model.

**Future (production-aligned):**
- Each signer operator must generate their own secrets locally (admin must not see private material).
- The only things shared with admin/others should be:
  - public keys (group member pubkeys, iroh verifier keys)
  - validator public keys / EVM addresses
  - group_id (derived from public config)
  - registry + checkpoints (public read)

---

## 1) Prerequisites (admin machine)

Required tools:
- `node` (LTS recommended)
- `npm` (comes with node)
- `aws` CLI

Required access:
- An origin EVM JSON-RPC endpoint for `igra-testnet-4` (shared IGRA EVM testnet node)
- An EVM deployer private key funded with enough ETH on that origin chain
- AWS credentials with permission to write the registry bucket

Environment variables used by scripts:
- `IGRA_EVM_RPC_URL` — origin EVM JSON-RPC URL
- `HYP_EVM_DEPLOYER_KEY_HEX` — origin deployer private key (hex; with or without `0x`)
- `AWS_REGION`
- `HYP_REGISTRY_S3_BUCKET` — e.g. `igra-hyperlane-registry-testnet`

---

## 2) One-time AWS setup (registry + checkpoints buckets)

We use two buckets:
- Registry bucket (admin writes, public reads): `igra-hyperlane-registry-testnet`
- Checkpoints bucket (validators write their own prefix, public reads): `igra-hyperlane-checkpoints-testnet`

We already keep example bucket policies here:
- `orchestration/testnet/aws/s3-registry-public-read-bucket-policy.json`
- `orchestration/testnet/aws/s3-checkpoints-public-read-bucket-policy.json`
- `orchestration/testnet/aws/s3-checkpoints-validator-writer-policy.json` (example for validator-01)

Optional helper script (creates buckets + applies public-read bucket policies):
- `orchestration/testnet/admin/scripts/bootstrap_aws_s3.sh --help`

Notes:
- Do **not** allow public `ListBucket`.
- Enable S3 bucket versioning if you want easy rollback.

---

## 3) Install Hyperlane CLI (admin machine)

We use the published npm package `@hyperlane-xyz/cli` (no monorepo builds).

Install into a local tool dir (recommended; avoids global installs):
- `orchestration/testnet/admin/scripts/install_hyperlane_cli.sh --help`

This writes:
- `orchestration/testnet/admin/.tools/hyperlane-cli/node_modules/.bin/hyperlane`

---

## 4) Deploy Hyperlane core contracts to origin EVM (igra-testnet-4)

This step:
- deploys Hyperlane core contracts to the origin EVM chain
- writes/updates the local registry directory:
  - `chains/igra-testnet-4/metadata.yaml`
  - `chains/igra-testnet-4/addresses.yaml`

Run:
- `orchestration/testnet/admin/scripts/deploy_hyperlane_core.sh --help`

Outputs:
- local registry dir (default): `orchestration/testnet/admin/.tmp/registry`

Important:
- If you redeploy, **addresses change** → you must publish the updated registry.

---

## 4.1 Funding plan (origin EVM) — what to fund, who owns what, when

On the origin EVM chain (`igra-testnet-4`) there are three categories of EVM accounts involved:

1) **Admin deployer account** (1 account)
- Owned by: Igra admin/deployer (you).
- Used for: deploying Hyperlane core contracts (Mailbox, ValidatorAnnounce, etc).
- Must be funded: **before** running `deploy_hyperlane_core.sh`.

2) **Relayer signer accounts** (N accounts; in testnet-v1: 5)
- Owned by: each signer operator (they control their relayer private key).
- Used for: Hyperlane relayer EVM-side transactions when needed (depends on protocol fee/IGP settings and relayer internals).
- Must be funded: **before** the operator starts their relayer.

3) **Validator accounts** (N accounts; in testnet-v1: 5)
- Owned by: each signer operator (they control their validator private key).
- Used for: sending a **one-time** `validatorAnnounce` transaction to the origin EVM `validatorAnnounce` contract.
- Must be funded: **before** the operator starts their validator (or before they attempt announce).

Important security note:
- Admin should fund **addresses**, not handle validator/relayer private keys.
- Each operator should send you two addresses: `relayer_evm_address` and `validator_evm_address`.

### How to compute an EVM address from a private key (admin/operator)

Recommended (if Foundry is installed):
- `cast wallet address --private-key 0x<HEX_KEY>`

Alternative (no Foundry): use the helper script after installing local node tools:
- `orchestration/testnet/admin/scripts/install_hyperlane_cli.sh` (installs node deps into `orchestration/testnet/admin/.tools/`)
- `orchestration/testnet/admin/scripts/evm_address_from_privkey.sh 0x<HEX_KEY>`

### What amounts to fund (rule of thumb)

Testnet-v1 is not cost-sensitive; prefer overfunding to avoid operational stalls:
- Deployer: enough for a full core deploy (often ~0.05–0.2 ETH depending on chain config).
- Each validator: enough for a single announce tx + retries (e.g. 0.01 ETH).
- Each relayer: enough for relayer-side transactions + retries (e.g. 0.05 ETH).

### Where to find the `validatorAnnounce` contract address

After deploy + publish:
- Look in the registry:
  - `chains/igra-testnet-4/addresses.yaml` → `validatorAnnounce: 0x...`

Operators can also use that address to confirm their announce tx landed.

---

## 5) Publish registry to S3 (canonical)

Run:
- `orchestration/testnet/admin/scripts/publish_hyperlane_registry_s3.sh --help`

This uploads `chains/**` to:
- `s3://igra-hyperlane-registry-testnet/`

Operators then run:
- `orchestration/testnet/scripts/sync_hyperlane_registry.sh --bucket igra-hyperlane-registry-testnet --dest <dir>`

---

## 6) Generate + distribute per-signer bundles

Generate bundles:
- `python3 orchestration/testnet/scripts/generate_testnet_v1_bundles.py`

Each operator receives exactly one directory:
- `orchestration/testnet/bundles/<run>/signer-0X/`

Each bundle contains:
- `data/secrets.bin` (encrypted; signer-specific)
- `config/igra-config.toml` (public, but includes validator pubkeys)
- `hyperlane/validator-private-key.hex` (signer-specific)
- `.env` (operator fills in values; can be updated via build scripts)

### Operator action required before starting (v1 vs future)

In a production-aligned model, operators generate their own secrets and then send their public “to-admin” information to the admin.

**Testnet-v1 (current):** this “operator produces to-admin” step is effectively **omitted**, because the **admin generated the bundles** and already has:
- the validator + relayer EVM addresses (from `<bundle>/to-admin.json`)
- the checkpoints S3 prefix and suggested IAM user name

Operators should still:
1) confirm which bundle they received (`signer-0X`)
2) wait for the admin to fund BOTH addresses on the origin EVM chain:
   - validator address (for one-time `validatorAnnounce`)
   - relayer address (relayer gas / retries)

Only after funding should operators start their stack. On startup, each validator should submit a **one-time** `validatorAnnounce` tx.

---

## 7) Validator checkpoint publishing (S3)

Each validator must be able to write only its own prefix:
- `s3://igra-hyperlane-checkpoints-testnet/checkpoints/97b4/validator-0X/*`

Recommended approach for v1:
- One IAM user per validator with an inline policy scoped to its prefix.

Use `orchestration/testnet/aws/s3-checkpoints-validator-writer-policy.json` as a template:
- replace `validator-01` with the real validator name for each signer.

### v1 convenience: admin writes AWS creds into bundles

Since the admin generates bundles in testnet-v1, the admin can also create IAM users and write the resulting
AWS credentials directly into each bundle’s `.env` (to eliminate extra operator setup steps).

Helper script:
- `orchestration/testnet/admin/scripts/provision_validator_iam_users.sh --help`

This reads each `<bundle>/to-admin.json`, provisions the suggested IAM user, and injects:
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_REGION`
into `<bundle>/.env` (chmod 600).

Security note:
- This is acceptable for testnet-v1 convenience.
- For production-aligned operation prefer instance roles (AWS) or operator-managed credentials.
