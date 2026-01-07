#!/usr/bin/env python3
"""
Update devnet configuration files with generated keys.

Args:
  1) env file path
  2) ini template path
  3) config dir
  4) ini output path
  5) hyperlane output path
  6) keygen json path
  7) igra data dir
  8) run root
  9) keyset output path
"""

import datetime
import hashlib
import json
import pathlib
import shutil
import sys


def read_keygen(path: pathlib.Path) -> dict:
  try:
    raw = path.read_text()
    return json.loads(raw)
  except Exception as exc:  # pragma: no cover - simple utility
    print(f"ERROR: failed to read or parse keygen output {path}: {exc}", file=sys.stderr)
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

  lines = [f"{k}={v}" for k, v in env_vars.items()]
  output_env = config_dir / ".env"
  output_env.write_text("\n".join(lines) + "\n")


def rewrite_ini(ini_template: pathlib.Path, ini_out: pathlib.Path, config_dir: pathlib.Path, data: dict,
                generated_ts: str, igra_data: pathlib.Path, run_root: pathlib.Path) -> None:
  text = ini_template.read_text()
  lines = text.splitlines()
  out_lines = []
  section = None
  signer_map = {s["profile"]: s for s in data["signers"]}

  group_preimage_str = "|".join(sorted(data["member_pubkeys"]))
  group_preimage_bytes = group_preimage_str.encode()
  group_id = hashlib.blake2b(group_preimage_bytes, digest_size=32).hexdigest()
  verifier_keys = [f"{s['profile']}:{s['pubkey_hex']}" for s in data["signers"]]

  comments = {
      "hd.mnemonics": f"generated {generated_ts}: signer mnemonics from devnet-keygen at {data['signers'][0]['derivation_path']} (comma-delimited)",
      "pskt.source_addresses": f"generated {generated_ts}: signer receive addresses at {data['signers'][0]['derivation_path']}",
      "pskt.redeem_script_hex": f"generated {generated_ts}: 2-of-3 redeem script over member_pubkeys (see group section)",
      "pskt.change_address": f"generated {generated_ts}: change address = signer-1 receive address",
      "group.member_pubkeys": f"generated {generated_ts}: pubkeys derived from signer mnemonics (ordered signer-1..3)",
      "hyperlane.validators": f"generated {generated_ts}: public keys for hyperlane validators from hyperlane-keys.json",
      "iroh.group_id": (
          f"generated {generated_ts}: blake2b-256 over sorted member_pubkeys joined with '|'. "
          f"inputs (sorted pubkeys)={group_preimage_str}; preimage_bytes={group_preimage_bytes.hex()}"
      ),
      "iroh.verifier_keys": f"generated {generated_ts}: signer verifier keys = signer pubkeys (profile:pubkey)",
  }

  for line in lines:
    if line.strip().startswith("; generated "):
      continue
    if line.strip().startswith("[") and line.strip().endswith("]"):
      section = line.strip()[1:-1]
    key = line.split("=", 1)[0].strip() if "=" in line else ""

    if section == "hd" and key == "mnemonics":
      joined = ", ".join(s["mnemonic"] for s in data["signers"])
      out_lines.append(f"; {comments['hd.mnemonics']}")
      out_lines.append(f"mnemonics = {joined}")
      continue
    if section == "pskt":
      if key == "source_addresses":
        out_lines.append(f"; {comments['pskt.source_addresses']}")
        out_lines.append(f"source_addresses = {','.join(data['source_addresses'])}")
        continue
      if key == "redeem_script_hex":
        out_lines.append(f"; {comments['pskt.redeem_script_hex']}")
        out_lines.append(f"redeem_script_hex = {data['redeem_script_hex']}")
        continue
      if key == "change_address":
        out_lines.append(f"; {comments['pskt.change_address']}")
        out_lines.append(f"change_address = {data['change_address']}")
        continue
    if section == "group" and key == "member_pubkeys":
      out_lines.append(f"; {comments['group.member_pubkeys']}")
      out_lines.append(f"member_pubkeys = {','.join(data['member_pubkeys'])}")
      continue
    if section == "hyperlane" and key == "validators":
      out_lines.append(f"; {comments['hyperlane.validators']}")
      out_lines.append(f"validators = {','.join(k['public_key_hex'] for k in data['hyperlane_keys'])}")
      continue
    if section == "iroh" and key == "group_id":
      out_lines.append(f"; {comments['iroh.group_id']}")
      out_lines.append(f"group_id = {group_id}")
      continue
    if section == "iroh" and key == "verifier_keys":
      out_lines.append(f"; {comments['iroh.verifier_keys']}")
      out_lines.append(f"verifier_keys = {','.join(verifier_keys)}")
      continue
    if section and section.startswith("signer-") and ".hd" in section and key == "mnemonics":
      profile = section.split(".")[0]
      out_lines.append(f"; generated {generated_ts}: mnemonic for {profile} (comma-delimited)")
      out_lines.append(f"mnemonics = {signer_map[profile]['mnemonic']}")
      continue
    if section and section.startswith("signer-") and ".iroh" in section and key == "signer_seed_hex":
      profile = section.split(".")[0]
      out_lines.append(f"; generated {generated_ts}: iroh seed for {profile}")
      out_lines.append(f"signer_seed_hex = {signer_map[profile]['iroh_seed_hex']}")
      continue
    if section and section.startswith("signer-") and ".iroh" in section and key == "group_id":
      out_lines.append(f"; {comments['iroh.group_id']}")
      out_lines.append(f"group_id = {group_id}")
      continue
    if section and section.startswith("signer-") and ".iroh" in section and key == "verifier_keys":
      out_lines.append(f"; {comments['iroh.verifier_keys']}")
      out_lines.append(f"verifier_keys = {','.join(verifier_keys)}")
      continue
    if section == "runtime" and key == "test_mode":
      out_lines.append(f"; generated {generated_ts}: test mode off for devnet realism")
      out_lines.append("test_mode = false")
      continue
    if section == "service" and key == "data_dir":
      out_lines.append(f"; generated {generated_ts}: data dir rooted at {run_root}")
      out_lines.append(f"data_dir = {igra_data}")
      continue
    if section and section.startswith("signer-") and ".service" in section and key == "data_dir":
      profile = section.split(".")[0]
      out_lines.append(f"; generated {generated_ts}: data dir for {profile} rooted at {run_root}")
      out_lines.append(f"data_dir = {igra_data / profile}")
      continue
    out_lines.append(line)

  new_text = "\n".join(out_lines) + "\n"
  ini_out.write_text(new_text)


def write_hyperlane_keys(hyperlane_out: pathlib.Path, config_dir: pathlib.Path, data: dict) -> None:
  validators = []
  for key in data["hyperlane_keys"]:
    validators.append({
        "name": key["name"],
        "private_key_hex": key["private_key_hex"],
        "public_key_hex": key["public_key_hex"],
  })
  content = json.dumps({"validators": validators}, indent=2) + "\n"
  hyperlane_out.write_text(content)


def write_keyset(keyset_out: pathlib.Path, config_dir: pathlib.Path, data: dict, generated_ts: str) -> None:
  payload = {
      "generated_at": generated_ts,
      "wallet": data["wallet"],
      "signers": data["signers"],
      "member_pubkeys": data["member_pubkeys"],
      "redeem_script_hex": data["redeem_script_hex"],
      "source_addresses": data["source_addresses"],
      "change_address": data["change_address"],
      "hyperlane_keys": data["hyperlane_keys"],
  }
  content = json.dumps(payload, indent=2) + "\n"
  keyset_out.write_text(content)


def main(argv: list[str]) -> int:
  if len(argv) != 9:
    print(__doc__, file=sys.stderr)
    return 1

  env_path = pathlib.Path(argv[0])
  ini_template = pathlib.Path(argv[1])
  config_dir = pathlib.Path(argv[2])
  ini_out = pathlib.Path(argv[3])
  hyperlane_out = pathlib.Path(argv[4])
  keygen_path = pathlib.Path(argv[5])
  igra_data = pathlib.Path(argv[6])
  run_root = pathlib.Path(argv[7])
  keyset_out = pathlib.Path(argv[8])

  config_dir.mkdir(parents=True, exist_ok=True)
  data = read_keygen(keygen_path)
  generated_ts = datetime.datetime.utcnow().isoformat() + "Z"

  write_env(env_path, config_dir, data)
  rewrite_ini(ini_template, ini_out, config_dir, data, generated_ts, igra_data, run_root)
  write_hyperlane_keys(hyperlane_out, config_dir, data)
  write_keyset(keyset_out, config_dir, data, generated_ts)
  return 0


if __name__ == "__main__":  # pragma: no cover - script entry
  sys.exit(main(sys.argv[1:]))
