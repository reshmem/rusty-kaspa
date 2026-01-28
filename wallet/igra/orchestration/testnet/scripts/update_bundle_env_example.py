#!/usr/bin/env python3
"""
Update `.env` inside generated bundles with detected binary paths.

This is a convenience tool to run after:
  - orchestration/testnet/scripts/build_kaspa_node.sh
  - orchestration/testnet/scripts/build_hyperlane_agents.sh
  - building Igra binaries (`kaspa-threshold-service`)
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys


def set_key(text: str, key: str, value: str) -> str:
    pat = re.compile(rf"^{re.escape(key)}=.*$", re.MULTILINE)
    if pat.search(text):
        return pat.sub(f"{key}={value}", text)
    return text + f"\n{key}={value}\n"


def detect_paths(repo_root: pathlib.Path) -> dict[str, str]:
    workspace_root = (repo_root / "../..").resolve()
    out: dict[str, str] = {}

    igra_bin = (repo_root / "target/release/kaspa-threshold-service").resolve()
    if igra_bin.exists():
        out["IGRA_BIN"] = str(igra_bin)

    kaspad_bin = (workspace_root / "target-igra-testnet/release/kaspad").resolve()
    if kaspad_bin.exists():
        out["KASPAD_BIN"] = str(kaspad_bin)

    hyp_repo = pathlib.Path(os.path.expanduser(os.environ.get("HYPERLANE_REPO_DIR", "~/Source/personal/hyperlane-monorepo"))).resolve()
    hyp_validator = (hyp_repo / "target-igra-testnet/release/validator").resolve()
    hyp_relayer = (hyp_repo / "target-igra-testnet/release/relayer").resolve()
    if hyp_validator.exists():
        out["HYP_VALIDATOR_BIN"] = str(hyp_validator)
    if hyp_relayer.exists():
        out["HYP_RELAYER_BIN"] = str(hyp_relayer)

    return out


def main() -> int:
    repo_root = pathlib.Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description="Update bundle .env files with detected binary paths")
    parser.add_argument(
        "--bundles-dir",
        default=str(repo_root / "orchestration/testnet/bundles"),
        help="Bundles directory (default: orchestration/testnet/bundles)",
    )
    args = parser.parse_args()

    bundles_dir = pathlib.Path(args.bundles_dir).resolve()
    if not bundles_dir.exists():
        print(f"bundles dir does not exist: {bundles_dir}", file=sys.stderr)
        return 1

    updates = detect_paths(repo_root)
    if not updates:
        print("no binaries detected; nothing to update")
        return 0

    env_files = list(bundles_dir.rglob(".env"))
    if not env_files:
        print(f"no .env files found under: {bundles_dir}")
        return 0

    for env_path in env_files:
        text = env_path.read_text(encoding="utf-8")
        for k, v in updates.items():
            text = set_key(text, k, v)
        env_path.write_text(text, encoding="utf-8")
        print(f"updated {env_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
