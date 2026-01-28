# Config Refactor (WIP)

This document captures a proposal to significantly simplify IGRA’s configuration model. It is intentionally **not implemented yet** and may evolve.

## Goals

- Make **keys/secrets** + **group identity** (group descriptor + group_id) the central trust anchors.
- Reduce redundant config inputs (single source of truth per concept).
- Make it hard to misconfigure signers (clear per-signer vs shared config).
- Keep devnet ergonomics, but prefer explicit config/CLI over implicit env magic.

## Current Behavior (What the Code Does Today)

- Config layering precedence:
  - compiled defaults → TOML file → `[profiles.<name>]` overlay → `IGRA_*` env overrides.
- “Profile” selection:
  - `kaspa-threshold-service` selects a profile via CLI `--profile signer-XX` or `service.active_profile` in the base config.
  - The profile must be `signer-XX` (01–99).
- PSKT config:
  - `service.pskt.redeem_script_hex` is treated as canonical.
  - `service.pskt.source_addresses` can be provided, but when redeem script is set the service enforces it matches the derived P2SH address and normalizes it to a single address.
  - `service.pskt.change_address` defaults to the source address when missing.
- Group config:
  - If `[group]` exists, it is cross-checked against the redeem script:
    - `threshold_m/n` and `member_pubkeys` must match what is encoded in `service.pskt.redeem_script_hex`.
  - `group_id` is configured under `[iroh].group_id` and only verified against `[group]` when `[group]` is present.
- Two-phase commit config:
  - `two_phase.commit_quorum` defaults to `group.threshold_m`, falling back to `service.hd.required_sigs` if `[group]` is missing.

## Problems / Why It Feels Overcomplicated

- Redundant sources of truth:
  - Threshold: `group.threshold_m` vs `service.hd.required_sigs` (fallback).
  - Membership: `group.member_pubkeys` vs `service.pskt.redeem_script_hex` (must match).
  - RPC URL: `service.node_rpc_url` vs `service.pskt.node_rpc_url` (duplicated, cascaded in multiple places).
- Mixed concerns in one file:
  - Shared “group identity” settings and per-signer operational settings are combined and then reshaped via profiles.
- Group identity is split:
  - `group_id` is stored under `[iroh]`, but it is not inherently “transport-only”; it defines who is in the signing group.
- Too many places to “fix” a misconfiguration:
  - Loader defaults, service startup normalization, runtime validation, and devnet generators all participate.

## Refactor Principles

1. **Redeem script is canonical** for (m-of-n + ordered pubkeys).
2. Derive values whenever possible:
   - source address and change address from redeem script + network.
3. **Group identity is explicit and consistent**:
   - Either compute `group_id` from the group descriptor (preferred), or if configured, always verify it.
4. Clear separation:
   - Shared config (group descriptor + policy + integrations)
   - Per-signer config (secrets + local ports/dirs + transport identity)
5. Avoid implicit env-based profile selection; prefer CLI or explicit config value.

## Proposed Simplified Model

### Option A (Minimal disruption): keep single TOML + profiles

- Keep one config file with `[profiles.signer-XX]`.
- Reduce redundant fields and treat many as derived:
  - Drop `service.pskt.node_rpc_url` (use only `service.node_rpc_url`).
  - Make `service.pskt.source_addresses` optional/debug-only; default is derived from redeem script.
  - Remove `group.threshold_m/n/member_pubkeys` from user-facing templates; derive them from redeem script.
  - Move `iroh.group_id` to a top-level `group_id` (or `group.group_id`) and compute it if not provided.

### Option B (Bigger change, simpler mental model): split into two files

- `igra-group.toml` (shared across all signers):
  - `network`
  - `pskt.redeem_script_hex`
  - policy + operational constraints that must match across signers
  - integrations (hyperlane/layerzero) if shared
  - computed or configured `group_id`
- `igra-signer.toml` (one per signer):
  - `signer_id = "signer-XX"` (explicit)
  - `data_dir`, `rpc.addr`
  - transport identity inputs (iroh peer id / seed / bind port)
  - `secrets_file` path (one secrets file per signer; no shared secrets)

## Suggested Implementation Phases

### Phase 1 — Remove obvious duplication (low risk)

- Eliminate `service.pskt.node_rpc_url` (use `service.node_rpc_url` everywhere).
- Make `service.pskt.source_addresses` fully optional:
  - if provided, verify it equals the derived address;
  - internally normalize to the single derived address.
- Update templates/docs accordingly.

### Phase 2 — Consolidate group identity

- Treat redeem script as the only membership+threshold input.
- Compute `group_id` from a single “group descriptor” and stop placing it under `[iroh]`.
- Always verify invariants on startup (no “optional verification”).

### Phase 3 — Structural cleanup (optional)

- Migrate from “profiles overlay” to “group file + signer file”.
- Keep a temporary compatibility loader for a short transition (devnet only).

## Open Questions

- What must be included in `group_id` computation?
  - Today it includes policy and metadata; decide whether group_id should reflect only membership+threshold, or also policy/operational constraints.
- Should hyperlane/layerzero be shared (group-level) or per-signer?
- Should `service.hd.required_sigs` exist at all once redeem script is required for production-like usage?

