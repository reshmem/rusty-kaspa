#!/usr/bin/env python3
"""
Monitor / summarize local devnet logs for Hyperlane -> Igra -> Kaspa flow.

This script reads:
  - Igra logs:     <root>/logs/igra-signer-XX.log
  - Hyperlane logs:<root>/hyperlane/logs/relayer-*.log, validator-*.log

It produces an end-to-end sanity summary:
  - Hyperlane relayer "submit" IDs vs Igra "indexed hyperlane delivery" IDs
  - Hyperlane relayer "message processed tx_id" vs Igra indexed tx_ids
  - Igra proof verification passed/failed counts (quorum/threshold)
  - Igra Kaspa submit_transaction success counts
  - Unfinalized Igra events tied to Hyperlane message ids

No external dependencies (stdlib only).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
HEX_32_RE = re.compile(r"0x[0-9a-f]{64}")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def now_iso() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def fmt_int(n: int) -> str:
    return f"{n:,}"


@dataclass
class SignerStats:
    verification_passed: int = 0
    proof_failed: int = 0
    indexed_delivery: int = 0
    submit_success: int = 0


@dataclass
class UnfinalizedEvent:
    event_id: str
    phase: str
    round: int
    age_seconds: int
    peer_log: str
    last_seen_ts: str


@dataclass
class State:
    root: Path
    signer_stats: dict[str, SignerStats] = field(default_factory=dict)

    # Igra
    indexed_msg_to_tx: dict[str, str] = field(default_factory=dict)  # message_id -> tx_id
    indexed_tx_ids: set[str] = field(default_factory=set)
    submitted_tx_ids: set[str] = field(default_factory=set)  # tx_id (0x-prefixed)
    unfinalized_by_external_id: dict[str, UnfinalizedEvent] = field(default_factory=dict)

    # Hyperlane relayer
    relayer_submit_ids: set[str] = field(default_factory=set)  # message_id (Hyperlane message id)
    relayer_processed_tx_ids: set[str] = field(default_factory=set)  # tx_id
    relayer_quorum_fail_ids: set[str] = field(default_factory=set)  # message_id

    # Hyperlane validators (lightweight sanity counter)
    validator_checkpoint_submits: int = 0


class LogFollower:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.pos = 0

    def poll_new_lines(self) -> list[str]:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return []

        # Handle truncation / rotation
        if st.st_size < self.pos:
            self.pos = 0

        try:
            with self.path.open("r", encoding="utf-8", errors="ignore") as f:
                f.seek(self.pos)
                data = f.read()
                self.pos = f.tell()
        except OSError:
            return []

        if not data:
            return []
        return data.splitlines()


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Monitor / summarize local Igra + Hyperlane devnet logs.")
    p.add_argument("--root", default="/tmp/igra_devnet", help="Devnet root dir (default: /tmp/igra_devnet)")
    p.add_argument("--once", action="store_true", help="Run one snapshot and exit (default)")
    p.add_argument("--watch", action="store_true", help="Continuously monitor logs")
    p.add_argument("--interval-secs", type=float, default=2.0, help="Watch polling interval (default: 2.0)")
    p.add_argument("--json", action="store_true", help="Emit JSON summary (snapshot) to stdout")
    p.add_argument("--max-stuck", type=int, default=20, help="Max stuck items to print (default: 20)")
    return p.parse_args(argv)


def signer_name_from_path(path: Path) -> str:
    # igra-signer-01.log -> signer-01
    m = re.search(r"igra-signer-(\d{2})\.log$", path.name)
    if not m:
        return path.stem
    return f"signer-{m.group(1)}"


def ensure_signer_stats(state: State, signer: str) -> SignerStats:
    stats = state.signer_stats.get(signer)
    if stats is None:
        stats = SignerStats()
        state.signer_stats[signer] = stats
    return stats


def parse_igra_line(state: State, signer: str, line: str) -> None:
    stats = ensure_signer_stats(state, signer)

    if "message verification passed" in line and "valid_signatures=" in line and "threshold=" in line:
        stats.verification_passed += 1
        return

    if "hyperlane proof verification failed" in line:
        stats.proof_failed += 1
        return

    if "indexed hyperlane delivery" in line:
        stats.indexed_delivery += 1
        mid_m = re.search(r"message_id=(0x[0-9a-f]{64})", line)
        tx_m = re.search(r"tx_id=(0x[0-9a-f]{64})", line)
        if mid_m and tx_m:
            mid = mid_m.group(1)
            tx = tx_m.group(1)
            state.indexed_msg_to_tx[mid] = tx
            state.indexed_tx_ids.add(tx)
        return

    if "submit_transaction ok" in line:
        stats.submit_success += 1
        tx_m = re.search(r"\btx_id=([0-9a-f]{64})\b", line)
        if tx_m:
            state.submitted_tx_ids.add("0x" + tx_m.group(1))
        return

    if "submit_transaction already accepted; treating as success" in line:
        stats.submit_success += 1
        tx_m = re.search(r"\btx_id=([0-9a-f]{64})\b", line)
        if tx_m:
            state.submitted_tx_ids.add("0x" + tx_m.group(1))
        return

    if "unfinalized event" in line and "external_id=" in line:
        external_m = re.search(r"external_id=(0x[0-9a-f]{64})", line)
        event_m = re.search(r"event_id=(0x[0-9a-f]{64})", line)
        phase_m = re.search(r"phase=([a-zA-Z_]+)", line)
        round_m = re.search(r"\bround=(\d+)\b", line)
        age_m = re.search(r"\bage_seconds=(\d+)\b", line)
        ts = line.split(" [", 1)[0].strip() if " [" in line else ""
        if external_m and event_m and phase_m and round_m and age_m:
            ext = external_m.group(1)
            state.unfinalized_by_external_id[ext] = UnfinalizedEvent(
                event_id=event_m.group(1),
                phase=phase_m.group(1),
                round=int(round_m.group(1)),
                age_seconds=int(age_m.group(1)),
                peer_log=signer,
                last_seen_ts=ts,
            )
        return


def parse_relayer_line(state: State, line: str) -> None:
    line = strip_ansi(line)

    if "pending_message::submit" in line and "id:" in line:
        m = re.search(r"\bid\s*:\s*(0x[0-9a-f]{64})", line)
        if m:
            state.relayer_submit_ids.add(m.group(1))
        return

    if "message processed: tx_id=" in line:
        m = re.search(r"tx_id=(0x[0-9a-f]{64})", line)
        if m:
            state.relayer_processed_tx_ids.add(m.group(1))
        return

    if "Unable to reach quorum" in line:
        m = re.search(r"\bid:\s*(0x[0-9a-f]{64})", line)
        if m:
            state.relayer_quorum_fail_ids.add(m.group(1))
        return


def parse_validator_line(state: State, line: str) -> None:
    line = strip_ansi(line)
    if "Signed and submitted checkpoint" in line:
        state.validator_checkpoint_submits += 1


def build_followers(root: Path) -> tuple[list[tuple[str, LogFollower]], list[LogFollower], list[LogFollower]]:
    igra_dir = root / "logs"
    hyperlane_dir = root / "hyperlane" / "logs"

    signer_followers: list[tuple[str, LogFollower]] = []
    for p in sorted(igra_dir.glob("igra-signer-*.log")):
        signer_followers.append((signer_name_from_path(p), LogFollower(p)))

    relayer_followers = [LogFollower(p) for p in sorted(hyperlane_dir.glob("relayer-*.log"))]
    validator_followers = [LogFollower(p) for p in sorted(hyperlane_dir.glob("validator-*.log"))]
    return signer_followers, relayer_followers, validator_followers


def snapshot_from_files(state: State) -> None:
    signer_followers, relayer_followers, validator_followers = build_followers(state.root)

    # One-shot: read entire files.
    for signer, follower in signer_followers:
        follower.pos = 0
        for line in follower.poll_new_lines():
            parse_igra_line(state, signer, line)

    for follower in relayer_followers:
        follower.pos = 0
        for line in follower.poll_new_lines():
            parse_relayer_line(state, line)

    for follower in validator_followers:
        follower.pos = 0
        for line in follower.poll_new_lines():
            parse_validator_line(state, line)


def compute_summary(state: State) -> dict[str, Any]:
    indexed_msg_ids = set(state.indexed_msg_to_tx.keys())

    missing_from_igra = sorted(state.relayer_submit_ids - indexed_msg_ids)
    processed_tx_not_indexed = sorted(state.relayer_processed_tx_ids - state.indexed_tx_ids)
    indexed_tx_not_processed = sorted(state.indexed_tx_ids - state.relayer_processed_tx_ids)
    indexed_tx_not_submitted = sorted(state.indexed_tx_ids - state.submitted_tx_ids)
    submitted_tx_not_indexed = sorted(state.submitted_tx_ids - state.indexed_tx_ids)

    signer = {}
    for name, stats in sorted(state.signer_stats.items()):
        signer[name] = {
            "verification_passed": stats.verification_passed,
            "proof_failed": stats.proof_failed,
            "indexed_delivery": stats.indexed_delivery,
            "submit_success": stats.submit_success,
        }

    unfinalized = {}
    for ext_id, ev in state.unfinalized_by_external_id.items():
        unfinalized[ext_id] = {
            "event_id": ev.event_id,
            "phase": ev.phase,
            "round": ev.round,
            "age_seconds": ev.age_seconds,
            "peer_log": ev.peer_log,
            "last_seen_ts": ev.last_seen_ts,
        }

    return {
        "root": str(state.root),
        "timestamp": now_iso(),
        "counts": {
            "indexed_message_ids": len(indexed_msg_ids),
            "indexed_tx_ids": len(state.indexed_tx_ids),
            "submitted_tx_ids": len(state.submitted_tx_ids),
            "relayer_submit_ids": len(state.relayer_submit_ids),
            "relayer_processed_tx_ids": len(state.relayer_processed_tx_ids),
            "relayer_quorum_fail_ids": len(state.relayer_quorum_fail_ids),
            "validator_checkpoint_submits": state.validator_checkpoint_submits,
            "unfinalized_events": len(state.unfinalized_by_external_id),
        },
        "signers": signer,
        "mismatches": {
            "relayer_submit_ids_not_indexed": missing_from_igra,
            "relayer_processed_tx_not_indexed": processed_tx_not_indexed,
            "indexed_tx_not_relayer_processed": indexed_tx_not_processed,
            "indexed_tx_not_submitted_in_igra_logs": indexed_tx_not_submitted,
            "submitted_tx_not_indexed": submitted_tx_not_indexed,
        },
        "unfinalized_by_external_id": unfinalized,
    }


def print_human(summary: dict[str, Any], max_stuck: int) -> None:
    counts = summary["counts"]
    print(f"[{summary['timestamp']}] root={summary['root']}")
    print(
        "messages: "
        f"relayer_submit={fmt_int(counts['relayer_submit_ids'])} "
        f"indexed={fmt_int(counts['indexed_message_ids'])} "
        f"missing={fmt_int(len(summary['mismatches']['relayer_submit_ids_not_indexed']))}"
    )
    print(
        "tx_ids: "
        f"relayer_processed={fmt_int(counts['relayer_processed_tx_ids'])} "
        f"indexed={fmt_int(counts['indexed_tx_ids'])} "
        f"submitted={fmt_int(counts['submitted_tx_ids'])}"
    )
    print(
        "proof: "
        f"relayer_quorum_fail={fmt_int(counts['relayer_quorum_fail_ids'])} "
        f"unfinalized_events={fmt_int(counts['unfinalized_events'])} "
        f"validator_checkpoint_submits={fmt_int(counts['validator_checkpoint_submits'])}"
    )

    print("per-signer:")
    for name, s in summary["signers"].items():
        print(
            f"  {name}: verification_passed={fmt_int(s['verification_passed'])} "
            f"proof_failed={fmt_int(s['proof_failed'])} "
            f"indexed={fmt_int(s['indexed_delivery'])} "
            f"submit_success={fmt_int(s['submit_success'])}"
        )

    missing = summary["mismatches"]["relayer_submit_ids_not_indexed"]
    if missing:
        print("missing message_ids (relayer submit seen, but not indexed by Igra):")
        for mid in missing[: max_stuck if max_stuck > 0 else len(missing)]:
            suffix = ""
            unfinal = summary["unfinalized_by_external_id"].get(mid)
            if unfinal:
                suffix = (
                    f" unfinalized(event_id={unfinal['event_id']} phase={unfinal['phase']} "
                    f"round={unfinal['round']} age_seconds={unfinal['age_seconds']} "
                    f"last={unfinal['last_seen_ts']} peer={unfinal['peer_log']})"
                )
            print(f"  - {mid}{suffix}")

    # Print a short warning if any hard mismatches exist
    hard = []
    if summary["mismatches"]["relayer_processed_tx_not_indexed"]:
        hard.append("relayer_processed_tx_not_indexed")
    if summary["mismatches"]["indexed_tx_not_relayer_processed"]:
        hard.append("indexed_tx_not_relayer_processed")
    if summary["mismatches"]["indexed_tx_not_submitted_in_igra_logs"]:
        hard.append("indexed_tx_not_submitted_in_igra_logs")
    if summary["mismatches"]["submitted_tx_not_indexed"]:
        hard.append("submitted_tx_not_indexed")
    if hard:
        print(f"WARNING: mismatches present: {', '.join(hard)}")


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = Path(args.root).expanduser()
    state = State(root=root)

    # Default behavior: snapshot once (unless --watch explicitly set)
    if args.watch and args.once:
        print("ERROR: choose only one of --watch or --once", file=sys.stderr)
        return 2

    if not args.watch:
        snapshot_from_files(state)
        summary = compute_summary(state)
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print_human(summary, args.max_stuck)
        return 0

    signer_followers, relayer_followers, validator_followers = build_followers(root)

    # Prime followers (start at end so we show *new* activity by default)
    for _, follower in signer_followers:
        try:
            follower.pos = follower.path.stat().st_size
        except FileNotFoundError:
            follower.pos = 0
    for follower in relayer_followers + validator_followers:
        try:
            follower.pos = follower.path.stat().st_size
        except FileNotFoundError:
            follower.pos = 0

    # First summary (from full snapshot), then tail mode.
    snapshot_from_files(state)

    while True:
        for signer, follower in signer_followers:
            for line in follower.poll_new_lines():
                parse_igra_line(state, signer, line)

        for follower in relayer_followers:
            for line in follower.poll_new_lines():
                parse_relayer_line(state, line)

        for follower in validator_followers:
            for line in follower.poll_new_lines():
                parse_validator_line(state, line)

        summary = compute_summary(state)
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            os.system("clear" if sys.stdout.isatty() else "true")
            print_human(summary, args.max_stuck)

        time.sleep(max(0.1, float(args.interval_secs)))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))

