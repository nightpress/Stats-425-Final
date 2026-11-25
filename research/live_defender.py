"""Closed-loop defender ablation: a REAL, live intervention instead of the
main study's offline replay scoring.

The main result scores a defender against an already-finished episode's
telemetry: containment is a counterfactual ("would a later exfil event have
been prevented"), never an action that actually happened during the attack.
This module demonstrates the identical detection POLICY applied LIVE, with a
real intervention: it tails the already-running Falco host-EDR daemon's
systemd journal for the duration of a live episode, scores each event with
the same DefenseOrchestrator used throughout this study, and on a detection
actually terminates every registered implant via the C2's existing
agent-lifecycle endpoint (GET /agents, DELETE /agent/delete/<paw> - a
standard agent-management action already in agent_routes.py, not new
offensive or defensive code).

Scope (read before use):
* GLOBAL containment only. On detection we kill every registered agent
  (environment-wide containment, matching this study's scope="global" cells)
  rather than attributing to one host - matching a Falco container.name to a
  specific agent paw is unreliable without host-id plumbing this repo doesn't
  expose, so per-host live containment is NOT implemented here.
* Falco-only. Suricata's live daemon watches the VM's public eth0 interface,
  not the docker bridges (capture_episode.sh instead runs its own offline
  per-bridge tcpdump+Suricata pass after the episode ends) - there is no live
  network-IDS feed available without reconfiguring that daemon. Falco is
  host-wide eBPF (sees container syscalls regardless of network interface)
  and already carries the dominant discriminating signal in the main result
  (untrusted-shell exec, stdout->network redirection, drop-and-execute), so
  this ablation uses Falco alone. It is NOT a live replica of the full
  two-sensor detector - report it as that explicit, narrower scope.
* Episode-start timing: this process's own start time stands in for the
  episode's start (elapsed-seconds clock for the sliding window), so it must
  be launched at the same moment as the attacker's main.py - see
  scripts/live_defender_episode.sh, which does exactly that.

Usage (run ALONGSIDE a live episode):
    PYTHONPATH=. python3 -m research.live_defender <episode_dir> \\
        --c2 http://localhost:8888 --window 120 --threshold 65 \\
        [--max-seconds 900] [--dry-run]

Writes <episode_dir>/live_defense.json: one line per scored Falco event, plus
a line per detection/containment attempt - the real-time audit trail.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

from incalmo.defense import DefenseConfig, DefenseOrchestrator, SecurityEvent
from incalmo.defense.sensors import parse_falco_line

# The main study zeroes this Falco signal (container baseline noise, higher on
# benign than attack - see research/grid.py SENSOR_WEIGHTS); keep that choice
# for the Falco-only live weighting so the policy matches the replay result.
LIVE_FALCO_WEIGHTS = {"falco:Packet socket created in container": 0.0}


def _http(method: str, url: str, timeout: float = 10.0) -> dict | list | None:
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return json.loads(body) if body else None
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        print(f"[live_defender] HTTP {method} {url} failed: {exc!r}", file=sys.stderr)
        return None


def contain_everything(c2: str, audit: list, dry_run: bool) -> int:
    """GET /agents, DELETE /agent/delete/<paw> for every registered agent -
    this ablation's global-scope containment. Returns the number killed."""
    agents = _http("GET", f"{c2}/agents")
    if not agents:
        audit.append({"event": "containment", "ok": False, "reason": "no agents listed"})
        return 0
    # Each agent entry is Agent.model_dump_json() (see incalmo/models/agent.py).
    paws = []
    for a in agents:
        rec = json.loads(a) if isinstance(a, str) else a
        paw = rec.get("paw")
        if paw:
            paws.append(paw)
    killed = 0
    for paw in paws:
        if dry_run:
            audit.append({"event": "containment_dry_run", "paw": paw})
            continue
        result = _http("DELETE", f"{c2}/agent/delete/{paw}")
        ok = result is not None
        audit.append({"event": "containment", "paw": paw, "ok": ok})
        killed += int(ok)
    return killed if not dry_run else len(paws)


def run(episode_dir: str, c2: str, window: float, threshold: float,
        max_seconds: float, dry_run: bool, falco_unit: str) -> None:
    os.makedirs(episode_dir, exist_ok=True)
    audit_path = os.path.join(episode_dir, "live_defense.json")
    audit: list[dict] = [{
        "event": "start", "window": window, "threshold": threshold,
        "scope": "global", "sensor": "falco_only", "dry_run": dry_run,
        "ts": datetime.utcnow().isoformat(),
    }]

    cfg = DefenseConfig(window_seconds=window, threshold=threshold, scope="global",
                        weights=dict(LIVE_FALCO_WEIGHTS))
    orch = DefenseOrchestrator(cfg)

    proc = subprocess.Popen(
        ["journalctl", "-u", falco_unit, "-f", "-o", "cat", "-n", "0"],
        stdout=subprocess.PIPE, text=True, bufsize=1,
    )
    start = time.monotonic()
    n_events = 0
    try:
        while True:
            if time.monotonic() - start > max_seconds:
                audit.append({"event": "timeout"})
                break
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    audit.append({"event": "journalctl_exited"})
                    break
                continue
            parsed = parse_falco_line(line)
            if parsed is None:
                continue
            ts, signal, category, weight, host, detail = parsed
            n_events += 1
            t = time.monotonic() - start
            ev = SecurityEvent(index=n_events, timestamp=ts, t=t, signal=signal,
                                category=category, weight=weight, host=host, detail=detail)
            detection = orch.process_event(ev)
            audit.append({"event": "scored", "t": round(t, 2), "signal": signal, "host": host})
            if detection is not None:
                audit.append({
                    "event": "detection", "t": round(t, 2), "score": detection.score,
                    "evidence": detection.evidence,
                })
                killed = contain_everything(c2, audit, dry_run)
                audit.append({"event": "contained", "n_agents_killed": killed})
                break  # global containment is terminal for this episode
    finally:
        proc.terminate()
        with open(audit_path, "w", encoding="utf-8") as fh:
            json.dump(audit, fh, indent=2, default=str)
        print(f"[live_defender] wrote {audit_path} ({len(audit)} entries, {n_events} Falco events scored)")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("episode_dir")
    p.add_argument("--c2", default="http://localhost:8888")
    p.add_argument("--window", type=float, default=120.0)
    p.add_argument("--threshold", type=float, default=65.0)
    p.add_argument("--max-seconds", type=float, default=900.0)
    p.add_argument("--falco-unit", default="falco-modern-bpf")
    p.add_argument("--dry-run", action="store_true",
                    help="score and log detections without calling DELETE /agent/delete")
    args = p.parse_args()
    run(args.episode_dir, args.c2, args.window, args.threshold,
        args.max_seconds, args.dry_run, args.falco_unit)


if __name__ == "__main__":
    main()
