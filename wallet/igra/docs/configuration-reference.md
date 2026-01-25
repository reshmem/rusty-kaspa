# Configuration Reference

This document describes **every supported config key**, what happens when it’s omitted, and which parts are cross-checked at startup.

Source of truth: `igra-core/src/infrastructure/config/types.rs`, `igra-core/src/infrastructure/config/loader.rs`, `igra-core/src/infrastructure/config/validation.rs`, and `igra-core/src/infrastructure/network_mode/rules/*`.

## Loading + Precedence

Configuration is layered (lowest → highest precedence):

1. Compiled defaults
2. TOML file (`igra-config.toml`)
3. Profile overrides from `[profiles.<name>]` (when a profile is selected)
4. Environment variables with `IGRA_` prefix (Figment mapping, `__` for nesting)

Profile selection:
- Recommended: CLI `--profile signer-XX`
- Or config: `service.active_profile = "signer-XX"`

## `service.*`

### `service.network` (optional string)
- Purpose: **network confirmation** to prevent drift.
- If omitted:
  - mainnet startup validation can fail (requires explicit confirmation in strict mode)
  - testnet emits a warning (“recommended”)
- If set: must match CLI `--network` (mismatch warns/errors depending on mode).

### `service.active_profile` (optional string)
- Purpose: selects which `[profiles.<name>]` overlay is active (if CLI `--profile` isn’t used).
- If omitted: CLI `--profile` must be provided; otherwise some startup checks fail and the signer identity cannot be derived from the SecretStore.
- Canonical format: `signer-XX` (01–99). Invalid values fail with `profile must match signer-XX (01-99): ...`.

### `service.node_rpc_url` (string)
- Purpose: Kaspa node RPC endpoint for querying UTXOs, submitting transactions, etc.
- Default if empty: `grpc://127.0.0.1:16110` (via loader postprocess).
- Mainnet cross-checks (network-mode validation):
  - Remote endpoints are rejected unless explicitly allowed (and then must use TLS + include authentication).

### `service.data_dir` (string)
- Purpose: base directory for runtime data (RocksDB, secrets/audit defaults, etc).
- Default if empty: the resolved data dir (`KASPA_DATA_DIR`, otherwise a per-platform default).
- Mainnet cross-checks:
  - directory must exist and have strict permissions.

### `service.allow_remote_rpc` (bool, default `false`)
- Purpose: explicit opt-in to use remote Kaspa RPC in mainnet.
- If `false` + mainnet remote URL: startup fails.

### `service.allow_schema_wipe` (bool, default `false`)
- Purpose: devnet escape hatch to wipe RocksDB on schema mismatch.
- If `false`: schema mismatch prevents startup (safer).
- If `true`: schema mismatch can trigger a destructive reset (devnet only).

### `service.node_rpc_circuit_breaker.*` (object)
- Purpose: circuit-breaker policy for RPC calls (timeouts/retries/backoff).
- If omitted: defaults apply (see `crate::infrastructure::rpc::CircuitBreakerConfig`).

### `service.use_encrypted_secrets` (bool, default `false`)
- Purpose:
  - `true`: use a per-signer encrypted secrets file (`secrets.bin`) via `FileSecretStore`
  - `false`: use environment-based secrets (`EnvSecretStore`) **only** when the binary is built with `--features devnet-env-secrets`
- Mainnet cross-check: must be `true`.

### `service.secrets_file` (optional string)
- Purpose: explicit path to `secrets.bin`.
- If omitted and `use_encrypted_secrets=true`: defaults to `${service.data_dir}/secrets.bin`.

### `service.key_audit_log_path` (optional string)
- Purpose: append-only audit log for key access.
- If omitted: defaults to `${service.data_dir}/key-audit.log`.
- Cross-check: empty string is invalid; parent directory existence is validated per network mode.

### `service.passphrase_rotation_*` (optional)
- `service.passphrase_rotation_enabled` (bool)
- `service.passphrase_rotation_warn_days` (u64)
- `service.passphrase_rotation_error_days` (u64)
- Purpose: enforce passphrase rotation for encrypted secrets files.
- Defaults depend on network mode (mainnet+testnet enabled by default; devnet off by default).
- Cross-checks (when enabled):
  - reads `secrets.bin` metadata and emits warnings/errors when age thresholds are exceeded.

## `service.pskt.*` (transaction building)

### `service.pskt.node_rpc_url` (string)
- Purpose: override `service.node_rpc_url` for PSKT-related RPC calls.
- Default if empty: inherits `service.node_rpc_url`.

### `service.pskt.redeem_script_hex` (string, often required)
- Purpose: **source of truth** for multisig spending policy (m-of-n, pubkeys).
- If omitted:
  - signing can still work only if redeem script can be derived from `service.hd` inputs (rare; see below)
  - many cross-checks cannot run (address derivation, signer alignment, etc).
- Cross-checks:
  - If `[group]` is present, config validation verifies `group.threshold_m/n` and `group.member_pubkeys` exactly match the redeem script.

### `service.pskt.source_addresses` (array of strings)
- Purpose: UTXO source address(es) to scan/spend from.
- Recommended: **omit** (or keep empty) and let the service derive from `redeem_script_hex`.
- If omitted/empty:
  - The loader derives it **only** when both are true:
    - `service.pskt.redeem_script_hex` is set
    - `service.network` is set (so the address prefix can be chosen deterministically)
- Cross-checks:
  - When both `redeem_script_hex` and any `source_addresses` are provided, startup validates every `source_addresses[i]` equals the single P2SH address derived from the redeem script (mismatch is an error).
  - This is why “multiple source addresses” generally does not make sense for a single redeem script.

### `service.pskt.change_address` (optional string)
- Purpose: where change returns (if any).
- Default if omitted/empty: first non-empty `source_addresses[0]`.
- Cross-check: must parse as a valid address.

### `service.pskt.sig_op_count` (u8)
- Purpose: signature-operation upper bound for tx mass/standardness checks.
- Default if 0: a safe compiled default.
- Recommended: set to `n` for `m-of-n` CHECKMULTISIG.

### `service.pskt.fee_payment_mode` (string enum)
- Purpose: who pays network fees (recipient vs signer vs split).
- Cross-check: split mode must not have both parts set to 0.

### `service.pskt.fee_sompi` (optional u64)
- Purpose: explicit fee override for PSKT building (if supported by fee mode).

### `service.pskt.outputs` (array)
- Purpose: optional static outputs (most flows provide outputs via events instead).

## `service.hd.*` (per-signer key material policy)

This section controls how the signer derives its **signing key** from SecretStore material.

### `service.hd.key_type` (`hd_mnemonic` | `raw_private_key`)
- Default: `hd_mnemonic`.
- `hd_mnemonic`:
  - reads `igra.signer.mnemonic_<profile>` from the SecretStore
  - derives a secp256k1 key (optionally using `service.hd.derivation_path`)
  - startup validation enforces mainnet forbids this mode
- `raw_private_key`:
  - reads `igra.signer.private_key_<profile>` from the SecretStore (32 bytes)
  - requires `service.pskt.redeem_script_hex` (validated at load time)

### `service.hd.derivation_path` (optional string)
- Purpose: derivation path used when `key_type=hd_mnemonic`.
- If omitted/empty/`"m"`: root key is used (no derivation).
- Cross-check (mainnet/testnet): the path must contain the expected coin type for the selected network.

### `service.hd.xpubs` (array of strings)
- Purpose: optional extra public-only participants (extended public keys).
- If empty: no extra pubkeys are contributed via config.
- Only used when deriving the redeem script from HD inputs (not needed when `service.pskt.redeem_script_hex` is already provided).

### `service.hd.required_sigs` (usize)
- Purpose: the `m` in `m-of-n` when deriving a redeem script from HD pubkeys.
- Redundant if you always pin `service.pskt.redeem_script_hex` and already have `group.threshold_m`.

## `runtime.*`

### `runtime.test_mode` (bool)
- When true: the service can sign “synthetic” test events without requiring real destination+amount inputs.

### `runtime.test_recipient` / `runtime.test_amount_sompi` (optional)
- Used only when `runtime.test_mode=true`.

### `runtime.session_timeout_seconds` (u64)
- Default if 0: compiled default.
- Cross-check: must be > 0; an upper bound is enforced.

### `runtime.session_expiry_seconds` / `runtime.crdt_gc_*` (optional)
- Purpose: CRDT lifecycle/GC behavior.
- Defaults are injected by loader if omitted.

## `signing.*`

### `signing.backend` (string)
- Current expected value: `"threshold"`.

## `rpc.*`

### `rpc.addr` (string)
- Default if empty: compiled default.

### `rpc.enabled` (bool)
- Enable/disable the HTTP RPC server.

### `rpc.token` (optional)
- Optional auth token for RPC (if enabled).

### `rpc.rate_limit_rps` / `rpc.rate_limit_burst` (optional)
- Optional rate limiter.

### `rpc.hyperlane_mailbox_wait_seconds` (optional)
- How long `hyperlane.mailbox_process` waits for tx completion before returning.

## `policy.*`

Enforcement policy for outgoing transfers.

- `policy.allowed_destinations` (array of addresses)
- `policy.min_amount_sompi` / `policy.max_amount_sompi` / `policy.max_daily_volume_sompi` (optional bounds)
- `policy.require_reason` (bool)

## `group.*`

Group is the canonical definition of the signer set and threshold.

- `group.threshold_m` / `group.threshold_n` (u16)
- `group.member_pubkeys` (array of x-only 32-byte secp256k1 pubkeys, hex)
- `group.*` fee/finality/session fields

Cross-checks:
- Load-time validation requires pubkey count to match `threshold_n`.
- If `service.pskt.redeem_script_hex` is present, config validation enforces `group` matches the redeem script exactly.
- Startup validation checks signer alignment: a signer running as `signer-02` must derive the pubkey at position 2 in the redeem script.

## `two_phase.*`

Two-phase coordination defaults are mostly derived from the group:

- `two_phase.commit_quorum = 0` means “derive from `group.threshold_m`”.
- `two_phase.min_input_score_depth = 0` means “derive from finality defaults”.

## `hyperlane.*`

Hyperlane settings for mailbox processing:

- Legacy flat set: `hyperlane.validators` + `hyperlane.threshold`
- Preferred: `[[hyperlane.domains]]` sections, one per destination domain:
  - `domain` (u32)
  - `validators` (hex pubkeys)
  - `threshold` (u8)
  - `mode` (`message_id_multisig` | `merkle_root_multisig`)

## `layerzero.*`

- `layerzero.endpoint_pubkeys` (array)

## `iroh.*`

Iroh P2P transport settings:

- `iroh.peer_id` (optional string): human label (not the iroh endpoint id)
- `iroh.signer_seed_hex` (optional string): used only if you aren’t loading the iroh seed from SecretStore
- `iroh.verifier_keys` (array of `"peer_id:ed25519_pubkey_hex"`): verifier set for peers
- `iroh.group_id` (optional string): group id used by transport layer (often derived from `[group]`)
- `iroh.network_id` (u8): coordination network id
- `iroh.bootstrap` (array): endpoint ids to connect to
- `iroh.bootstrap_addrs` (array): `"<endpoint_id>@host:port"` explicit addresses
- `iroh.bind_port` (optional u16): UDP bind port
- `iroh.discovery.*` / `iroh.relay.*`: discovery/relay toggles

## `profiles.<name>.*`

Profiles are partial overlays. Common per-signer overrides:

- `profiles.signer-XX.service.data_dir`
- `profiles.signer-XX.rpc.addr`
- `profiles.signer-XX.iroh.*` (peer id, seed, bind port, bootstrap)

Compatibility mapping:
- `[profiles.<name>.hd]` is mapped into `service.hd`
- `[profiles.<name>.pskt]` is mapped into `service.pskt`

