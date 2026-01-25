#!/usr/bin/env python3
"""
Update devnet configuration files with generated keys (TOML version).

Args:
  1) env file path
  2) TOML template path
  3) config dir
  4) TOML output path
  5) hyperlane output path
  6) keygen json path
  7) igra data dir
  8) run root
  9) keyset output path
"""

import datetime
import json
import os
import pathlib
import sys
from typing import Any


def read_json(path: pathlib.Path) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception as exc:  # pragma: no cover
        print(f"ERROR: failed to read {path}: {exc}", file=sys.stderr)
        sys.exit(1)


def write_env(env_path: pathlib.Path, config_dir: pathlib.Path, data: dict) -> None:
    env_vars = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if not line.strip() or line.strip().startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env_vars[k.strip()] = v.strip()

    env_vars["KASPA_DEVNET_WALLET_MNEMONIC"] = data["wallet"]["mnemonic"]
    env_vars["KASPA_DEVNET_WALLET_PASSWORD"] = data["wallet"]["password"]
    env_vars["KASPA_DEVNET_WALLET_NAME"] = data["wallet"]["name"]
    env_vars["KASPA_MINING_ADDRESS"] = data["wallet"]["mining_address"]

    output_env = config_dir / ".env"
    output_env.write_text("\n".join(f"{k}={v}" for k, v in env_vars.items()) + "\n")


def write_hyperlane_keys(hyperlane_out: pathlib.Path, data: dict) -> None:
    validators = [
        {
            "name": key["name"],
            "private_key_hex": key["private_key_hex"],
            "public_key_hex": key["public_key_hex"],
        }
        for key in data.get("hyperlane_keys", [])
    ]
    hyperlane_out.write_text(json.dumps({"validators": validators}, indent=2) + "\n")


def write_keyset(keyset_out: pathlib.Path, data: dict, generated_ts: str) -> None:
    payload = {
        "generated_at": generated_ts,
        "wallet": data.get("wallet", {}),
        "signers": data.get("signers", []),
        "signer_addresses": data.get("signer_addresses", []),
        "member_pubkeys": data.get("member_pubkeys", []),
        "redeem_script_hex": data.get("redeem_script_hex", ""),
        "source_addresses": data.get("source_addresses", []),
        "change_address": data.get("change_address", ""),
        "hyperlane_keys": data.get("hyperlane_keys", []),
        "evm": data.get("evm", {}),
        "group_id": data.get("group_id", ""),
        "multisig_address": data.get("multisig_address", ""),
    }
    keyset_out.write_text(json.dumps(payload, indent=2) + "\n")


def write_identities(igra_data: pathlib.Path, data: dict) -> None:
    for signer in data.get("signers", []):
        profile = signer.get("profile", "")
        if not profile:
            continue
        identity_dir = igra_data / profile / "iroh"
        identity_dir.mkdir(parents=True, exist_ok=True)
        identity_path = identity_dir / "identity.json"
        identity = {
            # Peer IDs in Igra are user-defined labels (not tied to the iroh endpoint id).
            # Keep them stable and human-readable for devnet.
            "peer_id": profile,
            "seed_hex": signer.get("iroh_seed_hex", ""),
        }
        identity_path.write_text(json.dumps(identity, indent=2) + "\n")


def strip_comment(line: str) -> str:
    in_string = False
    escaped = False
    out = []
    for ch in line:
        if escaped:
            out.append(ch)
            escaped = False
            continue
        if ch == "\\" and in_string:
            out.append(ch)
            escaped = True
            continue
        if ch == '"':
            out.append(ch)
            in_string = not in_string
            continue
        if ch == "#" and not in_string:
            break
        out.append(ch)
    return "".join(out).strip()


def split_comma_separated(raw: str) -> list[str]:
    items: list[str] = []
    in_string = False
    escaped = False
    buf: list[str] = []
    for ch in raw:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\" and in_string:
            buf.append(ch)
            escaped = True
            continue
        if ch == '"':
            buf.append(ch)
            in_string = not in_string
            continue
        if ch == "," and not in_string:
            items.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        items.append(tail)
    return items


def parse_toml_value(raw: str) -> Any:
    raw = strip_comment(raw).strip()
    if raw == "":
        return ""
    if raw in ("true", "false"):
        return raw == "true"
    if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
        inner = raw[1:-1]
        inner = inner.replace('\\"', '"').replace("\\\\", "\\")
        return inner
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        items = split_comma_separated(inner)
        return [parse_toml_value(item) for item in items]
    try:
        return int(raw)
    except ValueError:
        return raw


def ensure_table(root: dict, path: list[str]) -> dict:
    cur = root
    for part in path:
        cur = cur.setdefault(part, {})
    return cur


def parse_simple_toml(text: str) -> dict:
    root: dict = {}
    cur: dict = root
    for raw_line in text.splitlines():
        line = strip_comment(raw_line)
        if not line:
            continue
        if line.startswith("[[") and line.endswith("]]"):
            # Array-of-tables are not used by the devnet template.
            continue
        if line.startswith("[") and line.endswith("]"):
            table_path = line[1:-1].strip()
            cur = ensure_table(root, table_path.split(".")) if table_path else root
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        cur[key.strip()] = parse_toml_value(value.strip())
    return root


def default_template_dict() -> dict:
    # Mirrors `orchestration/devnet/igra-devnet-template.toml` so the generator
    # works even if template parsing fails.
    return {
        "service": {
            "node_rpc_url": "grpc://127.0.0.1:16110",
            "data_dir": "",
            "pskt": {
                "source_addresses": [],
                "redeem_script_hex": "",
                "sig_op_count": 2,
                "fee_payment_mode": "recipient_pays",
                "fee_sompi": 0,
                "change_address": "",
            },
            "hd": {
                "key_type": "hd_mnemonic",
                "required_sigs": 2,
                "xpubs": [],
            },
        },
        "runtime": {"test_mode": False, "session_timeout_seconds": 60},
        "signing": {"backend": "threshold"},
        "rpc": {"addr": "0.0.0.0:8088", "enabled": True},
        "policy": {
            "allowed_destinations": [],
            "min_amount_sompi": 1000000,
            "max_amount_sompi": 100000000000,
            "max_daily_volume_sompi": 500000000000,
            "require_reason": False,
        },
        "group": {
            "threshold_m": 2,
            "threshold_n": 3,
            "member_pubkeys": [],
            "fee_rate_sompi_per_gram": 0,
            "finality_blue_score_threshold": 0,
            "dust_threshold_sompi": 0,
            "min_recipient_amount_sompi": 0,
            "session_timeout_seconds": 60,
        },
        "hyperlane": {"validators": [], "threshold": 2, "poll_secs": 10},
        "layerzero": {"endpoint_pubkeys": []},
        "iroh": {"group_id": "", "verifier_keys": [], "bootstrap": [], "bootstrap_addrs": []},
        "profiles": {},
    }


def toml_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def toml_value(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return f'"{toml_escape(v)}"'
    if isinstance(v, list):
        if not v:
            return "[]"
        if all(isinstance(x, (str, int, bool)) for x in v):
            items = [toml_value(x) for x in v]
            if len(items) == 1:
                return f"[{items[0]}]"
            return "[\n    " + ",\n    ".join(items) + "\n]"
        raise ValueError("unsupported TOML list value")
    raise ValueError(f"unsupported TOML value: {type(v)}")


def dump_tables(out_lines: list[str], table_path: str, table: dict) -> None:
    out_lines.append(f"[{table_path}]")
    for k, v in table.items():
        if isinstance(v, dict):
            continue
        if isinstance(v, list) and v and all(isinstance(item, dict) for item in v):
            # Handled separately (array-of-tables)
            continue
        out_lines.append(f"{k} = {toml_value(v)}")
    out_lines.append("")

    for k, v in table.items():
        if isinstance(v, dict):
            dump_tables(out_lines, f"{table_path}.{k}", v)

def dump_array_of_tables(out_lines: list[str], table_path: str, items: list[dict]) -> None:
    for item in items:
        out_lines.append(f"[[{table_path}]]")
        for k, v in item.items():
            if isinstance(v, dict):
                raise ValueError(f"nested tables inside [[{table_path}]] are not supported")
            out_lines.append(f"{k} = {toml_value(v)}")
        out_lines.append("")


def write_toml_config(toml_out: pathlib.Path, config: dict) -> None:
    lines = [
        "# Devnet config (generated)",
        "# See CONFIG_REFACTORING.md for migration details",
        "",
    ]
    for section in ["service", "runtime", "signing", "rpc", "policy", "group", "hyperlane", "layerzero", "iroh"]:
        if section in config and isinstance(config[section], dict):
            dump_tables(lines, section, config[section])
            # Arrays-of-tables (currently only used for hyperlane.domains).
            if section == "hyperlane":
                domains = config[section].get("domains")
                if isinstance(domains, list) and domains and all(isinstance(item, dict) for item in domains):
                    dump_array_of_tables(lines, "hyperlane.domains", domains)

    profiles = config.get("profiles", {})
    if isinstance(profiles, dict) and profiles:
        lines.append("# =============================================================================")
        lines.append("# Signer Profiles")
        lines.append("# =============================================================================")
        lines.append("")
        for profile_name in sorted(profiles.keys()):
            lines.append(f"[profiles.{profile_name}]")
            lines.append("")
            profile = profiles[profile_name]
            for subsection_name in sorted(profile.keys()):
                subsection = profile[subsection_name]
                if isinstance(subsection, dict):
                    dump_tables(lines, f"profiles.{profile_name}.{subsection_name}", subsection)

    toml_out.write_text("\n".join(lines).rstrip() + "\n")


def rewrite_toml(
    toml_template: pathlib.Path,
    toml_out: pathlib.Path,
    data: dict,
    generated_ts: str,
    igra_data: pathlib.Path,
    run_root: pathlib.Path,
) -> None:
    _ = run_root
    _ = generated_ts

    # Load template (no external deps; Python 3.9 compatible).
    try:
        config = parse_simple_toml(toml_template.read_text())
    except Exception:
        config = default_template_dict()

    # Ensure nested sections exist
    config.setdefault("service", {})
    config["service"].setdefault("pskt", {})
    config["service"].setdefault("hd", {})
    config.setdefault("runtime", {})
    config.setdefault("signing", {})
    config.setdefault("rpc", {})
    config.setdefault("policy", {})
    config.setdefault("layerzero", {})
    config.setdefault("group", {})
    config.setdefault("hyperlane", {})
    config.setdefault("iroh", {})
    config.setdefault("profiles", {})

    # Update service section
    config["service"]["data_dir"] = str(igra_data)

    # Update pskt section
    multisig_address = data.get("multisig_address") or ""
    if multisig_address:
        config["service"]["pskt"]["source_addresses"] = [multisig_address]
    else:
        config["service"]["pskt"]["source_addresses"] = data.get("source_addresses", [])
    config["service"]["pskt"]["redeem_script_hex"] = data.get("redeem_script_hex", "")
    change_address = (data.get("change_address") or "").strip()
    if change_address:
        config["service"]["pskt"]["change_address"] = change_address
    else:
        # Default change address to the multisig/source address in the Rust config loader.
        config["service"]["pskt"].pop("change_address", None)

    # Update hd section
    config["service"]["hd"].setdefault("key_type", "hd_mnemonic")
    config["service"]["hd"].setdefault("xpubs", [])
    config["service"]["hd"]["required_sigs"] = 2

    # Update group section
    config["group"]["member_pubkeys"] = data.get("member_pubkeys", [])

    # `sig_op_count` must be an upper bound on signature operations for P2SH multisig scripts.
    # For `m-of-n` CHECKMULTISIG, the upper bound is `n`.
    threshold_n = int(config["group"].get("threshold_n") or 0)
    if threshold_n > 0:
        config["service"]["pskt"]["sig_op_count"] = threshold_n

    # Update hyperlane section
    config["hyperlane"]["validators"] = [k.get("public_key_hex", "") for k in data.get("hyperlane_keys", []) if k.get("public_key_hex")]
    config["hyperlane"]["threshold"] = 2

    # Enable ISM-style mailbox processing for devnet by generating `hyperlane.domains`.
    # NOTE: the mailbox_process handler selects the set by `message.origin`.
    origin_domain = int(os.environ.get("HYPERLANE_DOMAIN", "5") or "5")
    validators = list(config["hyperlane"]["validators"])
    threshold = 2 if len(validators) >= 2 else len(validators)
    if validators and threshold > 0:
        config["hyperlane"]["domains"] = [
            {
                "domain": origin_domain,
                "validators": validators,
                "threshold": threshold,
                "mode": "message_id_multisig",
            }
        ]
    else:
        config["hyperlane"]["domains"] = []

    # Iroh section
    group_id = data.get("group_id", "")
    config["iroh"]["group_id"] = group_id

    # Build verifier keys and bootstrap info
    signers = data.get("signers", [])
    missing = []
    for s in signers:
        profile = s.get("profile", "?")
        if not s.get("profile"):
            missing.append("signers[].profile")
        if not s.get("iroh_seed_hex"):
            missing.append(f"signers[{profile}].iroh_seed_hex")
        if not s.get("iroh_pubkey_hex"):
            missing.append(f"signers[{profile}].iroh_pubkey_hex")
        if not s.get("mnemonic"):
            missing.append(f"signers[{profile}].mnemonic")

    if missing:
        missing_str = ", ".join(sorted(set(missing)))
        raise SystemExit(
            f"ERROR: keygen JSON missing required fields ({missing_str}); regenerate with the updated `devnet-keygen` binary."
        )

    endpoint_map = {s["profile"]: s["iroh_pubkey_hex"] for s in signers}
    seed_map = {s["profile"]: s["iroh_seed_hex"] for s in signers}

    verifier_keys = [f"{s['profile']}:{s['iroh_pubkey_hex']}" for s in signers]
    config["iroh"]["verifier_keys"] = verifier_keys

    port_map = {"signer-01": 9101, "signer-02": 9102, "signer-03": 9103}
    config["iroh"]["bootstrap"] = list(endpoint_map.values())
    config["iroh"]["bootstrap_addrs"] = [f"{endpoint_map[p]}@127.0.0.1:{port_map[p]}" for p in endpoint_map if p in port_map]

    # Profiles
    for signer in signers:
        profile = signer.get("profile", "")
        if not profile:
            continue
        profile_num = int(profile.split("-")[1]) if "-" in profile else 1

        other_bootstrap = [endpoint_map[p] for p in endpoint_map if p != profile]
        other_bootstrap_addrs = [
            f"{endpoint_map[p]}@127.0.0.1:{port_map[p]}" for p in endpoint_map if p != profile and p in port_map
        ]

        profile_service = {
            "data_dir": str(igra_data / profile),
        }

        config["profiles"][profile] = {
            "service": profile_service,
            "rpc": {
                "addr": f"0.0.0.0:{8087 + profile_num}",
            },
            "iroh": {
                "peer_id": profile,
                "signer_seed_hex": seed_map.get(profile, ""),
                "group_id": group_id,
                "network_id": config.get("iroh", {}).get("network_id", 0),
                "verifier_keys": verifier_keys,
                "bootstrap": other_bootstrap,
                "bootstrap_addrs": other_bootstrap_addrs,
                "bind_port": port_map.get(profile, 0),
            },
        }

    write_toml_config(toml_out, config)
    print(f"Written: {toml_out}")


def main(argv: list[str]) -> int:
    if len(argv) != 9:
        print(__doc__, file=sys.stderr)
        return 1

    env_path = pathlib.Path(argv[0])
    toml_template = pathlib.Path(argv[1])
    config_dir = pathlib.Path(argv[2])
    toml_out = pathlib.Path(argv[3])
    hyperlane_out = pathlib.Path(argv[4])
    keygen_path = pathlib.Path(argv[5])
    igra_data = pathlib.Path(argv[6])
    run_root = pathlib.Path(argv[7])
    keyset_out = pathlib.Path(argv[8])

    config_dir.mkdir(parents=True, exist_ok=True)
    data = read_json(keygen_path)
    generated_ts = datetime.datetime.utcnow().isoformat() + "Z"

    write_identities(igra_data, data)
    write_env(env_path, config_dir, data)
    rewrite_toml(toml_template, toml_out, data, generated_ts, igra_data, run_root)
    write_hyperlane_keys(hyperlane_out, data)
    write_keyset(keyset_out, data, generated_ts)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
