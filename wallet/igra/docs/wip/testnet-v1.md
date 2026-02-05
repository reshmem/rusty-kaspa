## Testnet v1 (Igra + Hyperlane + Kaspa) — Plan + AWS Requirements

This document defines **testnet-v1** for running Igra in a production-like way across:
- developer laptops
- AWS instances
- Hetzner servers

It is written to be easy to operate for devops/IT, while still mimicking production Hyperlane flows.

Related background:
- `docs/wip/Domain-and-Network-IDs-Hyperlane.md`
Orchestration assets:
- `orchestration/testnet/README.md`
Admin runbook:
- `orchestration/testnet/admin/Igra-Admin-Guide.md`
Operator runbook:
- `orchestration/testnet/scripts/run_testnet_v1_signer.sh --help`

---

## 1) High-level architecture (per signer)

Each signer operator runs a full stack:
- **Igra EVM node** (reth/geth-compatible JSON-RPC; origin chain for Hyperlane) — **unimplemented in v1**
- **Kaspa node** (testnet)
- **Hyperlane Validator** (for the origin chain)
- **Hyperlane Relayer** (origin → destination delivery)
- **Igra Signer** (`kaspa-threshold-service`)

We target **5 signers** with a **3-of-5** signing threshold.

Naming and ordering are strict:
- `signer-01 .. signer-05`
- `validator-01 .. validator-05`
- `validator-XX` runs on the same machine as `signer-XX` (one-to-one mapping).

Discovery / connectivity goals (testnet-v1):
- Use Iroh gossip in a production-like way: **pkarr + relay enabled**, with a small static seed set as a safety net.

### 1.1 Operational roles (admin vs signer operators)

This testnet has two distinct human roles:

#### Admin / deployer (one person / small trusted group)

Primary responsibilities:
- One-time setup and shared infrastructure:
  - Prepare S3 buckets (registry + checkpoints) and policies.
  - Deploy Hyperlane core contracts on the origin EVM chain.
  - Publish the Hyperlane registry to S3 (canonical shared registry).
- Prepare operator artifacts:
  - Generate and distribute one per-signer bundle directory for each signer operator.
- Funding coordination (origin EVM):
  - Fund the deployer account (for contract deployment).
  - Fund each operator’s validator + relayer EVM addresses (operators own the keys; admin should fund addresses, not handle private keys).

Admin scripts (entry points):
- Local smoke stack (recommended): `orchestration/testnet/admin/scripts/boostrap.sh --anvil`
- AWS S3 bucket bootstrap (optional helper): `orchestration/testnet/admin/scripts/bootstrap_aws_s3.sh --help`
- Install Hyperlane CLI (local tool dir): `orchestration/testnet/admin/scripts/install_hyperlane_cli.sh --help`
- Deploy Hyperlane core (writes a local registry dir): `orchestration/testnet/admin/scripts/deploy_hyperlane_core.sh --help`
- Publish registry to S3: `orchestration/testnet/admin/scripts/publish_hyperlane_registry_s3.sh --help`
- Provision per-validator IAM users + inject creds into bundles (v1 convenience): `orchestration/testnet/admin/scripts/provision_validator_iam_users.sh --help`
- Compute EVM address from a private key (no Foundry required): `orchestration/testnet/admin/scripts/evm_address_from_privkey.sh 0x<HEX_KEY>`

Important notes:
- The full admin runbook (with exact env vars, AWS policies, and sequence) lives in:
  - `orchestration/testnet/admin/Igra-Admin-Guide.md`
- Tooling prerequisites are documented in:
  - `orchestration/testnet/PREREQS.md`

#### Signer operator (one per signer; N=5 in v1)

Each signer operator runs the “per signer” stack described above and is responsible for:
- Receiving exactly one bundle dir (`signer-0X`) from the admin.
- Syncing the Hyperlane registry from S3 to the local machine.
- Running their validator + relayer + kaspad + `kaspa-threshold-service` stack.
- Publishing validator checkpoints to S3 (either using IAM creds or instance roles on AWS).

Operator scripts (entry points):
- Sync registry from S3: `orchestration/testnet/scripts/sync_hyperlane_registry.sh --help`
- Run the full signer stack: `orchestration/testnet/scripts/run_testnet_v1_signer.sh --help`

---

## 2) Canonical IDs (testnet-v1)

### 2.1 Igra EVM origin (Hyperlane origin)

We define the origin Hyperlane `domainId` using the Igra testnet family described in
`docs/wip/Domain-and-Network-IDs-Hyperlane.md`:

- **Igra testnet “current”**: `0x97B4`

Testnet-v1 sets:
- Hyperlane **origin `domainId`** = `0x000097B4`

EVM **`chainId`** (EIP-155) should be chosen to avoid collisions and reduce confusion.
Recommendation for testnet-v1:
- EVM `chainId` = `0x000097B4` (decimal 38836) so `chainId == domainId` for the origin chain.

### 2.2 Kaspa destination (Kaspa testnet)

Igra process runtime mode:
- `--network testnet` (address prefix `kaspatest:`)

Kaspa node network:
- Kaspa **testnet** (`kaspad --testnet`)

Hyperlane destination `domainId`:
- Use the **Kaspa tag** style (big-endian ASCII) consistent with Hyperlane-style domain tagging:
  - `KAST` (Kaspa testnet) = `0x4B41_5354`

So testnet-v1 sets:
- Hyperlane **destination `domainId`** = `0x4B41_5354` (`KAST`)

### 2.3 Iroh `network_id`

`iroh.network_id` is a **transport namespace selector** (gossip topic changes when it changes) and also currently drives some
Kaspa consensus parameter selection inside Igra.

Testnet-v1 recommendation:
- `iroh.network_id = 4`

Rationale:
- Keeps testnet traffic isolated from devnet/mainnet gossip.
- Selects “testnet params” in the current `params_for_network_id` mapping.

### 2.4 Iroh discovery / connectivity (pkarr + relay + static seeds)

Testnet-v1 targets a “mainnet-like” experience for peer discovery without requiring full DNS ops on day 1:

- Enable pkarr DHT discovery:
  - `iroh.discovery.enable_pkarr = true`
- Enable relay support (important for laptops / NAT):
  - `iroh.relay.enable = true`
- Keep a small static bootstrap set as a safety net:
  - `iroh.bootstrap` (endpoint IDs)
  - `iroh.bootstrap_addrs` (`<endpoint_id>@host:port`)

**Can we use a domain name (not an IP) for bootstrap?**
Yes. The `host` portion of `iroh.bootstrap_addrs` can be a DNS name, e.g. `stage-roman.igralabs.com`, as long as it resolves (A/AAAA) and the port is reachable.

Important: `iroh.bootstrap_addrs` still requires the **endpoint id** prefix (`<endpoint_id>@...`). We will fill these values after generating signer identities/keys.

Initial seed host for testnet-v1:
- `stage-roman.igralabs.com` (stable seed host)

---

## 3) Hyperlane security model (what we configure in Igra)

Igra is the destination verifier for Hyperlane proofs in this system.

For Hyperlane verification, validator sets are chosen by:
- **destination policy keyed by origin domainId**
- i.e. `(destination, origin) -> validator_set + threshold + mode`

Since testnet-v1 has a single destination (Kaspa/Igra), we configure Igra with:
- `hyperlane.domains[origin_domain_id=0x97B4] = { validators, threshold, mode }`

Important:
- The lookup key is `message.origin` (origin domainId), not `message.destination`.
- This is why testnet-v1 must set the Igra Hyperlane domain entry to `0x97B4`.

---

## 4) Hyperlane registry + checkpoints: AWS setup (minimal)

We use **two S3 buckets**:
- a public-read **registry** bucket (addresses + metadata)
- a public-read **checkpoints** bucket (validators publish; relayers read)

### 4.1 S3 bucket: registry (public read)

Bucket:
- `igra-hyperlane-registry-testnet`

Objects:
- `chains/<chain-name>/metadata.yaml`
- `chains/<chain-name>/addresses.yaml`

Permissions:
- Public read:
  - allow `s3:GetObject` for `arn:aws:s3:::igra-hyperlane-registry-testnet/*`
- Restricted writes:
  - only the deployment/admin principal can `PutObject`/`DeleteObject`

Notes:
- Do not enable public `ListBucket`.
- Enable versioning (recommended).

### 4.2 S3 bucket: checkpoints (public read, restricted writes)

Bucket:
- `igra-hyperlane-checkpoints-testnet`

Prefix structure (prod-like and operator-friendly):
- `checkpoints/<originDomainId>/<validatorName>/...`

For testnet-v1:
- originDomainId = `0x97B4` (use a normalized string form like `97b4` in paths)
- validatorName = `validator-01` .. `validator-05`

Example:
- `s3://igra-hyperlane-checkpoints-testnet/checkpoints/97b4/validator-01/...`

Permissions:
- Public read:
  - allow `s3:GetObject` for `arn:aws:s3:::igra-hyperlane-checkpoints-testnet/*`
- Validator write:
  - create **one IAM user per validator** for cross-platform simplicity:
    - `hyperlane-validator-01-writer` (writes only to `checkpoints/97b4/validator-01/*`)
    - …
    - `hyperlane-validator-05-writer`

Each validator writer user needs:
- `s3:PutObject`, `s3:AbortMultipartUpload` on its prefix
- `s3:ListBucket` on the bucket with a `prefix` condition for its prefix

Relayers:
- do not need AWS credentials (public read).

Notes:
- Enable versioning (recommended).
- Consider lifecycle policies to expire old checkpoint objects (optional).

---

## 5) Naming conventions (canonical)

### 5.1 Hyperlane chain names (registry keys)

Hyperlane registry entries are keyed by chain name. We should use stable names:

- Origin chain name: `igratestnet4` (no hyphens; Hyperlane tooling normalizes keys)
  - `domainId: 0x97B4`
  - `chainId: 38836` (recommended)
  - `protocol: ethereum`

- Destination chain name: `kaspatestnet` (no hyphens; Hyperlane tooling normalizes keys)
  - `domainId: 0x4B415354` (`KAST`)
  - `protocol: kaspa`

### 5.2 Validator names
- `validator-01` .. `validator-05`
- The name must match the S3 checkpoint prefix component.

### 5.3 Signer names
- `signer-01` .. `signer-05`
- Signer index must align with the pubkey order in the redeem script.

---

## 6) Where the real runbooks + scripts live (testnet-v1)

The orchestration assets for testnet-v1 already live under:
- `orchestration/testnet/`

Start here depending on your role:
- Admin/deployer: `orchestration/testnet/admin/Igra-Admin-Guide.md`
- Operator/signer: `orchestration/testnet/scripts/run_testnet_v1_signer.sh --help`
- Directory overview + bundle generation: `orchestration/testnet/README.md`
- Tooling prerequisites: `orchestration/testnet/PREREQS.md`
