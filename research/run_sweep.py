"""Generate the attacker-episode library (the only part that spends API money),
then build the analysis dataset over it with the free offline defender sweep.

Subcommands:
  plan      Print the episode plan and an estimated total cost. No spending.
  generate  Run attacker episodes (resumable) under a hard spend cap.
  benign    Add synthetic benign episodes for false-positive measurement.
  extract   Score the whole library against the defender grid -> rows.csv.

The spend cap is enforced BEFORE each episode: with a per-episode estimate and a
cap, a run can never cross the budget. Actual per-call cost is read back from
each episode's ``token_usage.json`` and accumulated, so the cap tracks reality.

Example (on a host with the Incalmo range up):
  PYTHONPATH=. python3 -m research.run_sweep plan --invariance-arm
  PYTHONPATH=. python3 -m research.run_sweep generate --library research/out/library \\
      --cap 45 --cost-per-episode 0.25 --pilot 5
  PYTHONPATH=. python3 -m research.run_sweep benign  --library research/out/library --n 10
  PYTHONPATH=. python3 -m research.run_sweep extract --library research/out/library \\
      --out research/out/rows.csv
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime

from research.cost import BudgetExceeded, SpendLedger, preflight, summarize_token_usage
from research.grid import episode_plan

CONFIG_PATH = "./config/config.json"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _episode_id(cell: dict) -> str:
    if cell["benign"]:
        return f"benign__{cell['environment']}__rep{cell['replicate']:03d}"
    return f"{cell['attacker_model']}__{cell['environment']}__rep{cell['replicate']:03d}"


def _is_done(episode_dir: str) -> bool:
    # The live runtime writes actions.json; the example used action_log.jsonl.
    return any(os.path.exists(os.path.join(episode_dir, n))
               for n in ("actions.json", "action_log.jsonl"))


def _write_config(cell: dict) -> None:
    """Point config/config.json at this episode's attacker model and environment."""
    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        base = json.load(fh)
    base["name"] = f"sweep_{cell['attacker_model']}_{cell['replicate']}"
    base["strategy"] = {
        "planning_llm": cell["attacker_model"],
        "execution_llm": cell["attacker_model"],
        "abstraction": "incalmo",
    }
    base["environment"] = cell["environment"]
    if os.environ.get("C2C_SERVER"):
        base["c2c_server"] = os.environ["C2C_SERVER"]
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(base, fh, indent=2)


def _write_benign_config(environment: str, name: str) -> None:
    """Point config/config.json at the BenignAdmin state-machine strategy (no LLM)."""
    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        base = json.load(fh)
    base["name"] = name
    base["strategy"] = {"name": "BenignAdmin"}
    base["environment"] = environment
    if os.environ.get("C2C_SERVER"):
        base["c2c_server"] = os.environ["C2C_SERVER"]
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(base, fh, indent=2)


def _run_one_episode(cell: dict, episode_dir: str, timeout_s: int) -> None:
    """Invoke one Incalmo attacker run, writing its logs into episode_dir.

    Requires the Incalmo range to be up (C2 server, workers, environment). The
    attacker writes action_log.jsonl / results.json / token_usage.json into
    INCALMO_OUTPUT_DIR.
    """
    os.makedirs(episode_dir, exist_ok=True)
    _write_config(cell)
    env = dict(os.environ, INCALMO_OUTPUT_DIR=episode_dir)
    subprocess.run([sys.executable, "main.py"], cwd=REPO_ROOT, env=env,
                   timeout=timeout_s, check=False)


def _manifest_append(library_dir: str, record: dict) -> None:
    with open(os.path.join(library_dir, "manifest.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def cmd_plan(args: argparse.Namespace) -> None:
    plan = [c for c in episode_plan(args.invariance_arm) if not c["benign"]]
    by_model: dict[str, int] = {}
    for c in plan:
        by_model[c["attacker_model"]] = by_model.get(c["attacker_model"], 0) + 1
    print(f"Attacker episodes to generate: {len(plan)}")
    for model, n in sorted(by_model.items()):
        print(f"  {n:4d}  {model}")
    est = preflight(len(plan), args.cost_per_episode)
    print(f"\nAt ${args.cost_per_episode:.3f}/episode -> estimated ${est['estimated_total_usd']:.2f} total")
    if est["estimated_total_usd"] > args.cap:
        print(f"WARNING: estimate exceeds cap ${args.cap:.2f}. Reduce REPLICATES in research/grid.py "
              f"or lower per-episode cost (Haiku + caching).")


def cmd_generate(args: argparse.Namespace) -> None:
    os.makedirs(args.library, exist_ok=True)
    plan = [c for c in episode_plan(args.invariance_arm) if not c["benign"]]
    ledger = SpendLedger(cap_usd=args.cap)
    config_backup = CONFIG_PATH + ".sweepbak"
    shutil.copyfile(CONFIG_PATH, config_backup)
    ran = 0
    costs: list[float] = []
    try:
        for i, cell in enumerate(plan):
            if args.max_episodes and ran >= args.max_episodes:
                break
            episode_dir = os.path.join(args.library, _episode_id(cell))
            if _is_done(episode_dir):
                print(f"[skip] {_episode_id(cell)} (already present)")
                continue
            try:
                ledger.check(args.cost_per_episode)
            except BudgetExceeded as exc:
                print(f"[stop] {exc}")
                break
            print(f"[run ] {_episode_id(cell)}  (spent ${ledger.spent_usd:.2f}/"
                  f"${ledger.cap_usd:.2f})")
            started = datetime.now().isoformat()
            try:
                _run_one_episode(cell, episode_dir, args.timeout)
            except subprocess.TimeoutExpired:
                print(f"[warn] {_episode_id(cell)} timed out after {args.timeout}s")
            actual = summarize_token_usage(os.path.join(episode_dir, "token_usage.json"))
            ledger.add(actual.cost_usd)
            costs.append(actual.cost_usd)
            ran += 1
            _manifest_append(args.library, {
                "episode_id": _episode_id(cell), "started": started,
                "attacker_model": cell["attacker_model"], "environment": cell["environment"],
                "cost_usd": round(actual.cost_usd, 6), "n_calls": actual.n_calls,
                "cost_source": "reported" if actual.reported_cost_available else "computed",
            })
            if args.pilot and ran == args.pilot:
                mean = sum(costs) / len(costs) if costs else 0.0
                ext = preflight(len(plan), mean)
                print(f"\n[pilot] {ran} episodes, mean ${mean:.3f}/episode -> "
                      f"full run ~${ext['estimated_total_usd']:.2f} for {len(plan)} episodes.")
                if ext["estimated_total_usd"] > args.cap:
                    print(f"[pilot] extrapolation exceeds cap ${args.cap:.2f}; stopping. "
                          f"Lower REPLICATES or per-episode cost, then resume.")
                    break
    finally:
        shutil.move(config_backup, CONFIG_PATH)  # restore original config
    print(f"\nDone. Ran {ran} episodes, spent ${ledger.spent_usd:.2f} "
          f"(cap ${ledger.cap_usd:.2f}, remaining ${ledger.remaining_usd:.2f}).")


def cmd_benign(args: argparse.Namespace) -> None:
    """Synthetic benign episodes for FPR. NOTE: this build's telemetry is
    attacker-only, so a genuine benign corpus needs a benign-workload driver in
    the range (future work); these synthetic episodes are an explicit stand-in."""
    from research.synthesize import _benign_episode, _write_episode
    import random

    os.makedirs(args.library, exist_ok=True)
    rng = random.Random(args.seed)
    for rep in range(args.n):
        eid = f"benign__{args.environment}__rep{rep:03d}"
        episode_dir = os.path.join(args.library, eid)
        if _is_done(episode_dir):
            continue
        _write_episode(episode_dir, _benign_episode(rng), "benign", args.environment, 0, benign=True)
    print(f"wrote {args.n} synthetic benign episodes to {args.library} "
          f"(stand-in for FPR until a benign-workload driver exists)")


def cmd_benign_real(args: argparse.Namespace) -> None:
    """Run N REAL benign episodes on the live range via the BenignAdmin strategy.

    Needs the range up with a foothold (same as attacker episodes). Uses no LLM,
    so it costs $0 in API spend — these episodes give the false-positive rate
    from genuinely benign operations (inventory scans + config reads) that
    overlap attack indicators.
    """
    os.makedirs(args.library, exist_ok=True)
    config_backup = CONFIG_PATH + ".sweepbak"
    shutil.copyfile(CONFIG_PATH, config_backup)
    ran = 0
    try:
        for rep in range(args.n):
            eid = f"benign__{args.environment}__rep{rep:03d}"
            episode_dir = os.path.join(args.library, eid)
            if _is_done(episode_dir):
                print(f"[skip] {eid} (already present)")
                continue
            print(f"[run ] {eid}  (benign, $0)")
            _write_benign_config(args.environment, f"benign_{rep}")
            env = dict(os.environ, INCALMO_OUTPUT_DIR=episode_dir,
                       INCALMO_BENIGN_ROUNDS=str(args.rounds))
            try:
                subprocess.run([sys.executable, "main.py"], cwd=REPO_ROOT, env=env,
                               timeout=args.timeout, check=False)
            except subprocess.TimeoutExpired:
                print(f"[warn] {eid} timed out after {args.timeout}s")
            ran += 1
    finally:
        shutil.move(config_backup, CONFIG_PATH)
    print(f"\nDone. Ran {ran} real benign episodes (no API cost).")


def cmd_extract(args: argparse.Namespace) -> None:
    from research.extract_metrics import build_dataset
    build_dataset(args.library, args.out)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("plan", help="print plan + cost estimate (no spending)")
    sp.add_argument("--invariance-arm", action="store_true")
    sp.add_argument("--cost-per-episode", type=float, default=0.25)
    sp.add_argument("--cap", type=float, default=50.0)
    sp.set_defaults(func=cmd_plan)

    sg = sub.add_parser("generate", help="run attacker episodes under a spend cap")
    sg.add_argument("--library", required=True)
    sg.add_argument("--cap", type=float, default=45.0)
    sg.add_argument("--cost-per-episode", type=float, default=0.25)
    sg.add_argument("--invariance-arm", action="store_true")
    sg.add_argument("--pilot", type=int, default=0, help="extrapolate cost after N episodes")
    sg.add_argument("--max-episodes", type=int, default=0, help="cap episode count (0 = all)")
    sg.add_argument("--timeout", type=int, default=75 * 60, help="per-episode timeout (s)")
    sg.set_defaults(func=cmd_generate)

    sb = sub.add_parser("benign", help="add SYNTHETIC benign episodes for FPR (offline, no range)")
    sb.add_argument("--library", required=True)
    sb.add_argument("--n", type=int, default=10)
    sb.add_argument("--environment", default="equifax_large")
    sb.add_argument("--seed", type=int, default=0)
    sb.set_defaults(func=cmd_benign)

    sbr = sub.add_parser("benign-real", help="run REAL benign episodes on the live range (BenignAdmin, $0)")
    sbr.add_argument("--library", required=True)
    sbr.add_argument("--n", type=int, default=10)
    sbr.add_argument("--rounds", type=int, default=4, help="benign activity rounds per episode")
    sbr.add_argument("--environment", default="equifax_large")
    sbr.add_argument("--timeout", type=int, default=600, help="per-episode timeout (s)")
    sbr.set_defaults(func=cmd_benign_real)

    se = sub.add_parser("extract", help="score library -> rows.csv")
    se.add_argument("--library", required=True)
    se.add_argument("--out", default="research/out/rows.csv")
    se.set_defaults(func=cmd_extract)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
