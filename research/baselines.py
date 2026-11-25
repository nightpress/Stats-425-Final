"""Baseline detectors, scored through the SAME orchestrator/evaluate_episode
machinery as our host-EDR defender, for a fair head-to-head comparison.

Three detectors, each its own (event parser, threshold grid) pair - the grid
is calibrated to that detector's own score scale (see calibrate_baselines in
research/dev notes; peak-windowed-score ranges differ by orders of magnitude
between detectors, so one shared THRESHOLDS list would silently favor one):

* ``naive_volume``   - every sensor event counted at its raw (un-reweighted)
  weight, i.e. the defender's scoring BEFORE the host-EDR fix
  (incalmo/defense/sensors.py weights, no SENSOR_WEIGHTS override). This is
  the "just sum everything Suricata+Falco report" baseline.
* ``suricata_sig_all``     - count of Suricata's OWN signature/alert engine
  output (event_type == "alert"), any signature.
* ``suricata_sig_exploit`` - same, filtered to alerts whose signature contains
  an exploit/scan/threat-intel keyword (ET EXPLOIT/SCAN/DROP/CINS/...), i.e.
  the subset a SOC would actually triage as attack-relevant.

On the captured library (research/out/caplib), calibration showed Suricata's
signature engine does NOT discriminate here: peak sig_all counts overlap
completely between benign (172-181) and scripted attacks (90-241), and
sig_exploit actually scores benign (70) HIGHER than scripted (35) - the ET
Open rules that fire are generic protocol-decode/threat-intel matches
unrelated to the actual Struts exploit, not a signature for it. This
motivates the host-EDR approach as the paper's result, not an assumption.

CLI:
    PYTHONPATH=. python3 -m research.baselines <library_dir> --out research/out/baseline_rows.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from datetime import datetime
from itertools import product
from typing import Iterable, Optional

from incalmo.defense import (
    DefenseConfig, SecurityEvent, evaluate_episode, furthest_stage, parse_action_log,
)
from incalmo.defense.sensors import parse_sensors, _iso  # reuse the ISO-timestamp parser

# --- calibrated threshold grids (see module docstring) ----------------------
WINDOW_SECONDS: list[float] = [30, 60, 120, 240, 480]
SCOPES: list[str] = ["host", "global"]
NAIVE_VOLUME_THRESHOLDS: list[float] = [2000, 5000, 8000, 10000, 12000, 15000, 18000]
SURICATA_SIG_ALL_THRESHOLDS: list[float] = [10, 30, 60, 90, 120, 150, 200, 250]
SURICATA_SIG_EXPLOIT_THRESHOLDS: list[float] = [5, 15, 25, 35, 45, 56, 65, 75]

_EXPLOIT_KEYWORDS = ("EXPLOIT", "SCAN", "DROP", "CINS", "TROJAN", "MALWARE", "WEBSHELL", "SHELLCODE")


def _config_grid(thresholds: list[float], **extra) -> list[DefenseConfig]:
    return [DefenseConfig(window_seconds=w, threshold=t, scope=s, **extra)
            for w, t, s in product(WINDOW_SECONDS, thresholds, SCOPES)]


def parse_naive_volume_events(episode_dir: str) -> list[SecurityEvent]:
    """The same sensor stream as our detector, but with NO weight override -
    every event counts at its own (un-reweighted) sensors.py default weight.
    This reproduces the pre-fix defender exactly (see research/grid.py
    SENSOR_WEIGHTS and git history for the host-EDR reweighting commit)."""
    return parse_sensors(episode_dir)


def _raw_suricata_alerts(path: str) -> Iterable[tuple[datetime, str, Optional[str]]]:
    try:
        handle = open(path, "r", encoding="utf-8")
    except FileNotFoundError:
        return
    with handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("event_type") != "alert":
                continue
            ts = _iso(rec.get("timestamp"))
            if ts is None:
                continue
            signature = (rec.get("alert") or {}).get("signature", "?")
            host = rec.get("dest_ip") or rec.get("src_ip")
            yield ts, signature, host


def _parse_suricata_signal(episode_dir: str, *, exploit_only: bool) -> list[SecurityEvent]:
    path = os.path.join(episode_dir, "sensors", "suricata_eve.json")
    raw = [(ts, sig, host) for ts, sig, host in _raw_suricata_alerts(path)
           if not exploit_only or any(k in sig for k in _EXPLOIT_KEYWORDS)]
    raw.sort(key=lambda r: r[0])
    if not raw:
        return []
    start = raw[0][0]
    return [
        SecurityEvent(index=i, timestamp=ts, t=(ts - start).total_seconds(),
                       signal=f"sig:{sig[:48]}", category="signature-alert", weight=1.0,
                       host=host, detail={"signature": sig})
        for i, (ts, sig, host) in enumerate(raw)
    ]


def parse_suricata_sig_all_events(episode_dir: str) -> list[SecurityEvent]:
    return _parse_suricata_signal(episode_dir, exploit_only=False)


def parse_suricata_sig_exploit_events(episode_dir: str) -> list[SecurityEvent]:
    return _parse_suricata_signal(episode_dir, exploit_only=True)


# name -> (event parser, threshold grid)
DETECTORS: dict[str, tuple] = {
    "naive_volume": (parse_naive_volume_events, NAIVE_VOLUME_THRESHOLDS),
    "suricata_sig_all": (parse_suricata_sig_all_events, SURICATA_SIG_ALL_THRESHOLDS),
    "suricata_sig_exploit": (parse_suricata_sig_exploit_events, SURICATA_SIG_EXPLOIT_THRESHOLDS),
}

# Reuses extract_metrics' episode-dir discovery and ground-truth/metadata logic
# so baseline rows carry the same episode_id/attacker_model/autonomy columns
# as our detector's rows.csv - required for analyze.compare_detectors to align
# the two on episode identity.
from research.extract_metrics import _action_log_path, _episode_dirs, _read_metadata  # noqa: E402


def baseline_rows_for_episode(episode_dir: str, detector_name: str) -> list[dict]:
    parser, thresholds = DETECTORS[detector_name]
    attacker_events = parse_action_log(_action_log_path(episode_dir))
    detector_events = parser(episode_dir)
    meta = _read_metadata(episode_dir)
    eid = os.path.basename(os.path.normpath(episode_dir))
    benign = eid.startswith("benign")
    if not meta["attacker_model"] or not meta["environment"]:
        parts = eid.split("__")
        if len(parts) >= 2:
            meta["attacker_model"] = meta["attacker_model"] or parts[0]
            meta["environment"] = meta["environment"] or parts[1]
    autonomy = "benign" if benign else ("scripted" if eid.startswith("scripted-") else "llm")
    # So analyze.load()'s refused/engaged split (furthest_stage_rank==0 -> an API
    # safety refusal, never a defender miss) applies identically to baseline rows -
    # the comparison must be on the SAME engaged-attack subset as our detector.
    stage_rank = furthest_stage(attacker_events)

    rows = []
    for cfg in _config_grid(thresholds):
        metrics = evaluate_episode(detector_events, cfg, is_benign=benign,
                                    ground_truth_events=attacker_events)
        row = {
            "detector": detector_name, "episode_id": eid,
            "attacker_model": meta["attacker_model"], "autonomy": autonomy,
            "furthest_stage_rank": stage_rank,
            "n_detector_events": len(detector_events),
            "window_seconds": cfg.window_seconds, "threshold": cfg.threshold, "scope": cfg.scope,
            "defender_label": f"{detector_name}_{cfg.label()}",
        }
        row.update(metrics.to_row())
        rows.append(row)
    return rows


def build_dataset(library_dir: str, out_csv: str, detectors: Optional[list[str]] = None) -> int:
    detectors = detectors or list(DETECTORS)
    dirs = _episode_dirs(library_dir)
    if not dirs:
        raise SystemExit(f"no episode directories under {library_dir}")
    all_rows: list[dict] = []
    for episode_dir in dirs:
        for name in detectors:
            all_rows.extend(baseline_rows_for_episode(episode_dir, name))
    os.makedirs(os.path.dirname(os.path.abspath(out_csv)), exist_ok=True)
    with open(out_csv, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(all_rows[0].keys()))
        writer.writeheader()
        writer.writerows(all_rows)
    print(f"wrote {len(all_rows)} rows ({len(dirs)} episodes x {len(detectors)} baseline detectors) -> {out_csv}")
    return len(all_rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library_dir")
    parser.add_argument("--out", default="research/out/baseline_rows.csv")
    parser.add_argument("--detectors", nargs="*", choices=list(DETECTORS),
                         help="subset of detectors to run (default: all)")
    args = parser.parse_args()
    build_dataset(args.library_dir, args.out, args.detectors)


if __name__ == "__main__":
    main()
