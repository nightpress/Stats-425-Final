"""Turn an episode directory into tidy rows - one row per (episode, defender cfg).

An episode directory is whatever an Incalmo run wrote: ``action_log.jsonl``
(required), ``results.json`` (attacker/environment metadata + ground-truth
exfil), and ``token_usage.json`` (API cost; absent for replayed examples).

CLI:
    PYTHONPATH=. python3 -m research.extract_metrics <library_dir> --out rows.csv
Scores every episode sub-directory under ``library_dir`` against every
``DefenseConfig`` from :mod:`research.grid` and writes a long-format CSV ready
for :mod:`research.analyze`.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from typing import Iterable, Optional

from incalmo.defense import (
    DefenseConfig,
    STAGE_NAME,
    evaluate_episode,
    furthest_stage,
    parse_action_log,
)
from research.cost import summarize_token_usage

# The live runtime writes "actions.json"; the shipped example is "action_log.jsonl".
_ACTION_LOG_NAMES = ("actions.json", "action_log.jsonl")


def _action_log_path(episode_dir: str) -> str:
    """The action-log file in an episode dir, whichever name this build used."""
    for name in _ACTION_LOG_NAMES:
        candidate = os.path.join(episode_dir, name)
        if os.path.exists(candidate):
            return candidate
    return os.path.join(episode_dir, _ACTION_LOG_NAMES[0])  # default for the error msg


def _read_metadata(episode_dir: str) -> dict:
    """Attacker/environment metadata + ground-truth outcome from results.json."""
    path = os.path.join(episode_dir, "results.json")
    meta = {
        "attacker_model": "", "attacker_name": "", "environment": "",
        "abstraction": "", "gt_n_exfil": None, "gt_flags": None,
        "execution_time_s": None,
    }
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError):
        return meta
    scenario = data.get("scenario", {})
    attacker = scenario.get("attacker", {}) if isinstance(scenario, dict) else {}
    meta["attacker_name"] = attacker.get("name", "")
    meta["attacker_model"] = attacker.get("llm") or attacker.get("strategy", "")
    meta["abstraction"] = attacker.get("abstraction", "")
    meta["environment"] = scenario.get("environment", "") if isinstance(scenario, dict) else ""
    meta["gt_n_exfil"] = len(data.get("data_exfiltrated", []) or [])
    meta["gt_flags"] = len(data.get("flags_captured", []) or [])
    meta["execution_time_s"] = data.get("execution_time")
    return meta


def episode_rows(
    episode_dir: str,
    defender_configs: Iterable[DefenseConfig],
    *,
    is_benign: Optional[bool] = None,
    episode_id: Optional[str] = None,
    attacker_model_override: Optional[str] = None,
) -> list[dict]:
    """One row per defender config for a single episode directory."""
    events = parse_action_log(_action_log_path(episode_dir))
    stage_rank = furthest_stage(events)  # E2: how far along the kill chain it got
    stage_name = STAGE_NAME.get(stage_rank, "none")
    meta = _read_metadata(episode_dir)
    usage = summarize_token_usage(os.path.join(episode_dir, "token_usage.json")).to_row()
    eid = episode_id or os.path.basename(os.path.normpath(episode_dir))
    benign = bool(is_benign) if is_benign is not None else eid.startswith("benign")

    # The live runtime doesn't write results.json on an early stop; recover the
    # attacker model and environment from the episode id (<key>__<env>__repNN).
    if not meta["attacker_model"] or not meta["environment"]:
        parts = eid.split("__")
        if len(parts) >= 2:
            meta["attacker_model"] = meta["attacker_model"] or parts[0]
            meta["environment"] = meta["environment"] or parts[1]

    # Autonomy class — the E1 axis. scripted-* = deterministic full-chain; benign
    # = the FPR control; everything else = an LLM-driven attacker.
    if benign:
        autonomy = "benign"
    elif eid.startswith("scripted-") or (meta["attacker_model"] or "").startswith("scripted-"):
        autonomy = "scripted"
    else:
        autonomy = "llm"

    rows: list[dict] = []
    for cfg in defender_configs:
        metrics = evaluate_episode(events, cfg, is_benign=benign)
        row = {
            "episode_id": eid,
            "attacker_model": attacker_model_override or meta["attacker_model"],
            "autonomy": autonomy,
            "furthest_stage_rank": stage_rank,
            "furthest_stage": stage_name,
            "attacker_name": meta["attacker_name"],
            "environment": meta["environment"],
            "abstraction": meta["abstraction"],
            "window_seconds": cfg.window_seconds,
            "threshold": cfg.threshold,
            "scope": cfg.scope,
            "defender_label": cfg.label(),
            "gt_n_exfil": meta["gt_n_exfil"],
            "gt_flags": meta["gt_flags"],
            "execution_time_s": meta["execution_time_s"],
        }
        row.update(metrics.to_row())
        row.update(usage)
        rows.append(row)
    return rows


def _episode_dirs(library_dir: str) -> list[str]:
    """Sub-directories that look like episodes (contain an action_log.jsonl)."""
    def _has_log(d: str) -> bool:
        return any(os.path.exists(os.path.join(d, n)) for n in _ACTION_LOG_NAMES)

    found = [
        os.path.join(library_dir, name)
        for name in sorted(os.listdir(library_dir))
        if os.path.isdir(os.path.join(library_dir, name)) and _has_log(os.path.join(library_dir, name))
    ]
    # Allow pointing directly at a single episode directory.
    if not found and _has_log(library_dir):
        found = [library_dir]
    return found


def build_dataset(library_dir: str, out_csv: str) -> int:
    from research.grid import defender_configs

    configs = defender_configs()
    dirs = _episode_dirs(library_dir)
    if not dirs:
        raise SystemExit(f"no episode directories (with action_log.jsonl) under {library_dir}")

    all_rows: list[dict] = []
    for episode_dir in dirs:
        all_rows.extend(episode_rows(episode_dir, configs))

    os.makedirs(os.path.dirname(os.path.abspath(out_csv)), exist_ok=True)
    with open(out_csv, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(all_rows[0].keys()))
        writer.writeheader()
        writer.writerows(all_rows)
    print(f"wrote {len(all_rows)} rows ({len(dirs)} episodes x {len(configs)} configs) -> {out_csv}")
    return len(all_rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library_dir", help="directory of episode sub-directories (or one episode)")
    parser.add_argument("--out", default="research/out/rows.csv", help="output CSV path")
    args = parser.parse_args()
    build_dataset(args.library_dir, args.out)


if __name__ == "__main__":
    main()
