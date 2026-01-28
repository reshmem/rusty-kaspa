#!/usr/bin/env python3
"""
Generate per-signer testnet-v1 bundles (configs + secrets files).

This script intentionally generates **local artifacts only** under:
  orchestration/testnet/bundles/

Those bundles contain secrets and are gitignored.

Security model note:
- For testnet-v1, we allow the admin to generate bundles centrally for speed.
- Production-aligned operation requires each signer to generate their own secrets locally
  (admin must not have access to private key material).

Design reference:
  - docs/wip/testnet-v1.md
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time
from dataclasses import dataclass


REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
TEMPLATE_PATH = REPO_ROOT / "orchestration/testnet/templates/igra-signer-testnet-v1.toml"
ENV_EXAMPLE_PATH = REPO_ROOT / "orchestration/testnet/.env-example"
ADMIN_TOOLS_NODE_MODULES = REPO_ROOT / "orchestration/testnet/admin/.tools/hyperlane-cli/node_modules"


@dataclass(frozen=True)
class KeygenOutput:
    group_id: str
    redeem_script_hex: str
    member_pubkeys: list[str]
    signers: list[dict]
    hyperlane_keys: list[dict]


def run_keygen(
    *,
    num_signers: int,
    threshold_m: int,
    iroh_network_id: int,
    output_dir: pathlib.Path,
    passphrase: str | None,
) -> KeygenOutput:
    cmd = [
        "cargo",
        "run",
        "--locked",
        "-p",
        "igra-core",
        "--bin",
        "devnet-keygen",
        "--release",
        "--",
        "--format",
        "file-per-signer",
        "--output-dir",
        str(output_dir),
        "--num-signers",
        str(num_signers),
        "--threshold-m",
        str(threshold_m),
        "--kaspa-network",
        "testnet",
        "--network-id",
        str(iroh_network_id),
        "--hyperlane-validator-count",
        str(num_signers),
        "--hyperlane-validator-name-format",
        "two-digit",
    ]
    if passphrase:
        cmd += ["--passphrase", passphrase]

    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"devnet-keygen failed (exit {proc.returncode})")

    try:
        data = json.loads(proc.stdout)
    except Exception as exc:
        sys.stderr.write(proc.stderr)
        sys.stderr.write(proc.stdout)
        raise SystemExit(f"failed to parse devnet-keygen JSON: {exc}")

    return KeygenOutput(
        group_id=data["group_id"],
        redeem_script_hex=data["redeem_script_hex"],
        member_pubkeys=data["member_pubkeys"],
        signers=data["signers"],
        hyperlane_keys=data.get("hyperlane_keys", []),
    )


def evm_address_from_privkey_hex(priv_hex_no_0x: str) -> str:
    priv = priv_hex_no_0x.strip().lower().removeprefix("0x")
    if len(priv) != 64:
        raise SystemExit(f"invalid secp256k1 private key hex length: expected 64, got {len(priv)}")

    # Prefer Foundry `cast` if installed.
    if shutil_which("cast"):
        proc = subprocess.run(
            ["cast", "wallet", "address", "--private-key", "0x" + priv],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            sys.stderr.write(proc.stderr)
            raise SystemExit("failed to compute EVM address via cast")
        addr = proc.stdout.strip()
        if not addr.startswith("0x") or len(addr) != 42:
            raise SystemExit(f"unexpected cast output address: {addr}")
        return addr

    # Fallback: Node + ethers from admin tools install.
    if not ADMIN_TOOLS_NODE_MODULES.exists():
        raise SystemExit(
            "cannot compute EVM address (missing Foundry cast and admin node_modules).\n"
            "Fix:\n"
            "  - install Foundry (cast), OR\n"
            "  - run: orchestration/testnet/admin/scripts/install_hyperlane_cli.sh\n"
        )
    if not shutil_which("node"):
        raise SystemExit("cannot compute validator EVM address (missing node). Install node/npm first.")

    proc = subprocess.run(
        [
            "node",
            "-e",
            "const { Wallet } = require('ethers'); const w = new Wallet(process.env.K); console.log(w.address);",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "NODE_PATH": str(ADMIN_TOOLS_NODE_MODULES), "K": "0x" + priv},
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit("failed to compute EVM address via node/ethers")
    addr = proc.stdout.strip()
    if not addr.startswith("0x") or len(addr) != 42:
        raise SystemExit(f"unexpected node/ethers output address: {addr}")
    return addr


def shutil_which(cmd: str) -> str | None:
    from shutil import which

    return which(cmd)


def generate_evm_privkey_hex() -> str:
    # Generate a random secp256k1 private key candidate (32 bytes hex, no 0x).
    # We validate it by attempting to derive an address; if invalid (rare), retry.
    for _ in range(1000):
        candidate = os.urandom(32).hex()
        try:
            _ = evm_address_from_privkey_hex(candidate)
            return candidate
        except SystemExit:
            continue
    raise SystemExit("failed to generate a valid EVM private key after many retries")


def toml_string_array(values: list[str]) -> str:
    # Single-line arrays are easiest to template safely.
    escaped = [v.replace("\\", "\\\\").replace('"', '\\"') for v in values]
    return "[" + ", ".join(f'"{v}"' for v in escaped) + "]"


def render_igra_config(
    *,
    template_text: str,
    signer_profile: str,
    data_dir: pathlib.Path,
    rpc_addr: str,
    group_id_hex: str,
    redeem_script_hex: str,
    threshold_m: int,
    threshold_n: int,
    member_pubkeys: list[str],
    iroh_network_id: int,
    iroh_verifier_keys: list[str],
    hyperlane_origin_domain_id: int,
    hyperlane_validators: list[str],
    hyperlane_threshold: int,
) -> str:
    out = template_text
    out = out.replace("__SIGNER_PROFILE__", signer_profile)
    out = out.replace("__DATA_DIR__", str(data_dir))
    out = out.replace("__RPC_ADDR__", rpc_addr)
    out = out.replace("__GROUP_ID_HEX__", group_id_hex)
    out = out.replace("__REDEEM_SCRIPT_HEX__", redeem_script_hex)
    out = out.replace("__THRESHOLD_M__", str(threshold_m))
    out = out.replace("__THRESHOLD_N__", str(threshold_n))
    out = out.replace("__SIG_OP_COUNT__", str(threshold_n))
    out = out.replace("__MEMBER_PUBKEYS_ARRAY__", toml_string_array(member_pubkeys))
    out = out.replace("__IROH_NETWORK_ID__", str(iroh_network_id))
    out = out.replace("__IROH_VERIFIER_KEYS_ARRAY__", toml_string_array(iroh_verifier_keys))
    out = out.replace("__HYPERLANE_ORIGIN_DOMAIN_ID__", str(hyperlane_origin_domain_id))
    out = out.replace("__HYPERLANE_VALIDATORS_ARRAY__", toml_string_array(hyperlane_validators))
    out = out.replace("__HYPERLANE_THRESHOLD__", str(hyperlane_threshold))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate testnet-v1 signer bundles")
    parser.add_argument("--out", default=None, help="Output bundles dir (default: orchestration/testnet/bundles/testnet-v1-<ts>)")
    parser.add_argument("--num-signers", type=int, default=5)
    parser.add_argument("--threshold-m", type=int, default=3)
    parser.add_argument("--iroh-network-id", type=int, default=4)
    parser.add_argument("--hyperlane-origin-domain-id", type=lambda s: int(s, 0), default=int("0x97B4", 16))
    parser.add_argument("--passphrase", default=None, help="Secrets file passphrase (or set IGRA_SECRETS_PASSPHRASE)")
    args = parser.parse_args()

    if args.threshold_m <= 0 or args.threshold_m > args.num_signers:
        raise SystemExit(f"invalid threshold: m={args.threshold_m} n={args.num_signers}")

    out_dir = pathlib.Path(args.out) if args.out else (REPO_ROOT / "orchestration/testnet/bundles" / f"testnet-v1-{int(time.time())}")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_dir = out_dir.resolve()

    passphrase = args.passphrase or os.environ.get("IGRA_SECRETS_PASSPHRASE")
    if not passphrase or not passphrase.strip():
        raise SystemExit("missing secrets passphrase: pass --passphrase or set IGRA_SECRETS_PASSPHRASE")

    # Generate secrets files + key material.
    keys_root = out_dir / "generated"
    keys_root.mkdir(parents=True, exist_ok=True)
    keygen_out = run_keygen(
        num_signers=args.num_signers,
        threshold_m=args.threshold_m,
        iroh_network_id=args.iroh_network_id,
        output_dir=keys_root,
        passphrase=passphrase,
    )

    template_text = TEMPLATE_PATH.read_text(encoding="utf-8")
    env_example_template = ENV_EXAMPLE_PATH.read_text(encoding="utf-8")

    # Best-effort binary path suggestions (filled into .env-example).
    suggested_igra_bin = str((REPO_ROOT / "target/release/kaspa-threshold-service").resolve())
    suggested_kaspad_bin = str((REPO_ROOT / "../.." / "target-igra-testnet/release/kaspad").resolve())
    suggested_hyp_repo = pathlib.Path(os.path.expanduser("~/Source/personal/hyperlane-monorepo"))
    suggested_hyp_validator = str((suggested_hyp_repo / "target-igra-testnet/release/validator").resolve())
    suggested_hyp_relayer = str((suggested_hyp_repo / "target-igra-testnet/release/relayer").resolve())

    # Verifier keys are a shared allowlist of signer identities.
    iroh_verifier_keys = [f"{s['iroh_peer_id']}:{s['iroh_pubkey_hex']}" for s in keygen_out.signers]

    # Hyperlane validator pubkeys for Igra config (hex, compressed secp256k1 pubkey).
    hyperlane_validators = [k["public_key_hex"] for k in keygen_out.hyperlane_keys]

    # Write one bundle per signer.
    for idx, signer in enumerate(keygen_out.signers):
        profile = signer["profile"]
        bundle_dir = out_dir / profile
        data_dir = bundle_dir / "data"
        config_dir = bundle_dir / "config"
        hyperlane_dir = bundle_dir / "hyperlane"
        bundle_dir.mkdir(parents=True, exist_ok=True)
        data_dir.mkdir(parents=True, exist_ok=True)
        config_dir.mkdir(parents=True, exist_ok=True)
        hyperlane_dir.mkdir(parents=True, exist_ok=True)
        bundle_dir = bundle_dir.resolve()
        data_dir = data_dir.resolve()
        config_dir = config_dir.resolve()
        hyperlane_dir = hyperlane_dir.resolve()

        # Place the signer secrets file at `${data_dir}/secrets.bin` (production-aligned).
        generated_secrets = keys_root / profile / "secrets.bin"
        if not generated_secrets.exists():
            raise SystemExit(f"missing generated secrets file for {profile}: {generated_secrets}")
        target_secrets = data_dir / "secrets.bin"
        if target_secrets.exists():
            raise SystemExit(f"refusing to overwrite existing secrets file: {target_secrets}")
        target_secrets.write_bytes(generated_secrets.read_bytes())
        os.chmod(target_secrets, 0o600)

        (bundle_dir / "group_id.hex").write_text(keygen_out.group_id + "\n", encoding="utf-8")

        # Store the matching Hyperlane validator private key alongside the bundle (not in igra secrets).
        if idx >= len(keygen_out.hyperlane_keys):
            raise SystemExit(
                f"hyperlane validator count mismatch: need {args.num_signers}, got {len(keygen_out.hyperlane_keys)}"
            )
        validator_key_path = hyperlane_dir / "validator-private-key.hex"
        validator_key_path.write_text(keygen_out.hyperlane_keys[idx]["private_key_hex"] + "\n", encoding="utf-8")
        os.chmod(validator_key_path, 0o600)

        validator_evm_address = evm_address_from_privkey_hex(keygen_out.hyperlane_keys[idx]["private_key_hex"])

        # Testnet-v1 shortcut: include a relayer EVM key in the bundle to reduce admin<->operator back-and-forth.
        relayer_priv_hex = generate_evm_privkey_hex()
        relayer_key_path = hyperlane_dir / "relayer-private-key.hex"
        relayer_key_path.write_text(relayer_priv_hex + "\n", encoding="utf-8")
        os.chmod(relayer_key_path, 0o600)
        relayer_evm_address = evm_address_from_privkey_hex(relayer_priv_hex)

        to_admin = {
            "signer_profile": profile,
            "group_id": "0x" + keygen_out.group_id,
            "iroh": {
                "peer_id": signer["iroh_peer_id"],
                "verifier_pubkey_hex": signer["iroh_pubkey_hex"],
            },
            "aws": {
                "validator_checkpoints_prefix": f"checkpoints/97b4/{keygen_out.hyperlane_keys[idx]['name']}/",
                "suggested_validator_iam_user": f"hyperlane-{keygen_out.hyperlane_keys[idx]['name']}-writer",
                "note": "Admin should provision one IAM writer per validator, scoped to this prefix.",
            },
            "hyperlane": {
                "origin_chain_name": "igratestnet4",
                "origin_domain_id": f"0x{args.hyperlane_origin_domain_id:08x}",
                "validator": {
                    "name": keygen_out.hyperlane_keys[idx]["name"],
                    "public_key_hex": keygen_out.hyperlane_keys[idx]["public_key_hex"],
                    "evm_address": validator_evm_address,
                    "checkpoints_s3_prefix": f"checkpoints/97b4/{keygen_out.hyperlane_keys[idx]['name']}/",
                    "private_key_location": "bundle:hyperlane/validator-private-key.hex",
                },
                "relayer": {
                    "evm_address": relayer_evm_address,
                    "private_key_location": "bundle:hyperlane/relayer-private-key.hex",
                },
            },
            "funding": {
                "validator_min_eth": "0.01",
                "relayer_min_eth": "0.05",
                "note": "Rule-of-thumb values for v1 testnet. Prefer overfunding to avoid stalls.",
            },
        }
        (bundle_dir / "to-admin.json").write_text(json.dumps(to_admin, indent=2) + "\n", encoding="utf-8")

        rpc_addr = f"127.0.0.1:{8088 + idx}"
        config_text = render_igra_config(
            template_text=template_text,
            signer_profile=profile,
            data_dir=data_dir,
            rpc_addr=rpc_addr,
            group_id_hex=keygen_out.group_id,
            redeem_script_hex=keygen_out.redeem_script_hex,
            threshold_m=args.threshold_m,
            threshold_n=args.num_signers,
            member_pubkeys=keygen_out.member_pubkeys,
            iroh_network_id=args.iroh_network_id,
            iroh_verifier_keys=iroh_verifier_keys,
            hyperlane_origin_domain_id=args.hyperlane_origin_domain_id,
            hyperlane_validators=hyperlane_validators,
            hyperlane_threshold=args.threshold_m,
        )
        (config_dir / "igra-config.toml").write_text(config_text, encoding="utf-8")

        env_text = (
            env_example_template.replace("__IGRA_BIN__", suggested_igra_bin)
            .replace("__KASPAD_BIN__", suggested_kaspad_bin)
            .replace("__HYP_VALIDATOR_BIN__", suggested_hyp_validator if pathlib.Path(suggested_hyp_validator).exists() else "validator")
            .replace("__HYP_RELAYER_BIN__", suggested_hyp_relayer if pathlib.Path(suggested_hyp_relayer).exists() else "relayer")
        )
        env_text = env_text.replace("HYP_EVM_SIGNER_KEY_HEX=", f"HYP_EVM_SIGNER_KEY_HEX={relayer_priv_hex}")
        env_path = bundle_dir / ".env"
        if env_path.exists():
            raise SystemExit(f"refusing to overwrite existing env file: {env_path}")
        env_path.write_text(env_text, encoding="utf-8")
        os.chmod(env_path, 0o600)

        (bundle_dir / "README.txt").write_text(
            "\n".join(
                [
                    f"Bundle for {profile}",
                    "",
                    "Files:",
                    "  - config/igra-config.toml",
                    "  - data/secrets.bin",
                    "  - hyperlane/validator-private-key.hex",
                    "  - hyperlane/relayer-private-key.hex",
                    "  - group_id.hex",
                    "  - .env",
                    "  - to-admin.json",
                    "",
                    "Next:",
                    "  - sync Hyperlane registry locally (addresses.yaml + metadata.yaml)",
                    "  - send to-admin.json to admin (contains validator+relayer EVM addresses + metadata)",
                    "  - admin funds BOTH EVM addresses (validatorAnnounce + relayer gas)",
                    "  - after funding, operator starts services; validator should send a one-time validatorAnnounce tx",
                    "  - export required env vars (see .env)",
                    "  - run: orchestration/testnet/scripts/run_testnet_v1_signer.sh --bundle <this dir> start",
                    "",
                ]
            ),
            encoding="utf-8",
        )

    # Write a small shared summary (non-secret).
    (out_dir / "shared.json").write_text(
        json.dumps(
            {
                "group_id": keygen_out.group_id,
                "threshold_m": args.threshold_m,
                "threshold_n": args.num_signers,
                "member_pubkeys": keygen_out.member_pubkeys,
                "redeem_script_hex": keygen_out.redeem_script_hex,
                "iroh_network_id": args.iroh_network_id,
                "hyperlane_origin_domain_id": args.hyperlane_origin_domain_id,
                "hyperlane_validator_pubkeys": hyperlane_validators,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"Wrote bundles to: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
