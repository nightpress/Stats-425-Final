"""Generate inert E3 log fixtures using a virtual clock.

No network, attacker runtime, VM, or LLM calls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random

from datetime import datetime, timedelta
from pathlib import Path

from config.attacker_config import StealthConfig
from incalmo.defense import parse_action_log
from research.grid import e3_fixture_plan
from research.synthesize import (
    _attack_episode,
    write_e3_fixture,
)


def synthetic_episode(
    seed: int,
    n_hosts: int,
    config: StealthConfig
):
    """
    Generate offline synthetic telemetry.

    Original intervals are preserved.
    Configured delays are added to the original intervals.
    No real-time waiting or network operations occur.
    """

    if n_hosts < 1:
        raise ValueError("n_hosts must be positive")

    count = n_hosts

    # Apply fictional host coverage limit.
    if config.enabled and config.scan_breadth is not None:
        count = min(count, config.scan_breadth)

    # Generate the original synthetic telemetry.
    lines, n_exfil = _attack_episode(
        random.Random(seed),
        n_hosts=count
    )

    # Preserve baseline behavior.
    if not config.enabled:
        return lines, n_exfil

    # Independent random generator for timing.
    rng = random.Random(f"E3-clock:{seed}")

    # Accumulated additional virtual delay.
    added_delay = timedelta(0)

    first = True
    output = []
    pending = []

    for line in lines:

        rec = json.loads(line)

        # Retain attribution-only records.
        if not rec.get("action_results"):
            pending.append(rec)
            continue

        # Add delay between observable events.
        if not first:

            extra = config.inter_action_delay

            if config.randomized_timing:
                extra += rng.uniform(0, 10)

            added_delay += timedelta(seconds=extra)

        first = False

        # Preserve original timestamps plus accumulated delay.
        for item in [*pending, rec]:

            original = datetime.fromisoformat(
                item["timestamp"]
            )

            item["timestamp"] = (
                original + added_delay
            ).isoformat()

            output.append(json.dumps(item))

        pending.clear()

    # Preserve remaining attribution records.
    for item in pending:

        original = datetime.fromisoformat(
            item["timestamp"]
        )

        item["timestamp"] = (
            original + added_delay
        ).isoformat()

        output.append(json.dumps(item))

    return output, n_exfil


def episode_seed(base_seed, cell):
    """
    Create a reproducible paired seed.

    The seed excludes the enabled/disabled condition,
    allowing both conditions to share underlying randomness.
    """

    key = (
        f"{base_seed}:"
        f"{cell['environment']}:"
        f"{cell['attacker']}:"
        f"{cell['replicate']}"
    )

    return int.from_bytes(
        hashlib.sha256(key.encode()).digest()[:8],
        "big"
    )


def make_e3_library(
    library_dir,
    config,
    replicates=12,
    seed=0
):
    """
    Generate the complete E3 synthetic episode library.
    """

    if not config.enabled:
        raise ValueError(
            "config must describe the enabled arm"
        )

    plan = e3_fixture_plan(replicates)

    root = Path(library_dir)

    # Avoid accidentally mixing new fixtures with old
    # telemetry, sensor files, or experiment results.
    if root.exists() and any(root.iterdir()):

        raise FileExistsError(
            f"Choose an empty/new fixture directory: {root}"
        )

    root.mkdir(
        parents=True,
        exist_ok=True
    )

    for cell in plan:

        # Select baseline or modified configuration.
        cfg = (
            config
            if cell["stealth"]
            else StealthConfig(enabled=False)
        )

        paired_seed = episode_seed(seed, cell)

        # Match the existing scripted synthetic workload's
        # baseline host-count range.
        n_hosts = random.Random(
            f"E3-hosts:{paired_seed}"
        ).randint(4, 7)

        lines, n_exfil = synthetic_episode(
            paired_seed,
            n_hosts,
            cfg
        )

        condition = "on" if cfg.enabled else "off"

        # Match the naming convention in e3_replay.py.
        eid = (
            f"scripted-{cell['attacker']}"
            f"__{cell['environment']}"
            f"__stealth-{condition}"
            f"__rep{cell['replicate']:03d}"
        )

        path = root / eid

        # Write the existing Incalmo-compatible fixture files.
        write_e3_fixture(
            path,
            lines,
            f"scripted-{cell['attacker']}",
            cell["environment"],
            n_exfil,
            cfg.model_dump()
        )

        # Calculate the actual synthetic episode duration.
        events = parse_action_log(
            str(path / "action_log.jsonl")
        )

        result_path = path / "results.json"

        results = json.loads(
            result_path.read_text(encoding="utf-8")
        )

        results["execution_time"] = (
            events[-1].t if events else 0.0
        )

        result_path.write_text(
            json.dumps(results, indent=2),
            encoding="utf-8"
        )

    return len(plan)


def main():

    parser = argparse.ArgumentParser(
        description=__doc__
    )

    parser.add_argument(
        "--library",
        required=True
    )

    parser.add_argument(
        "--replicates",
        type=int,
        default=12
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=0
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=5
    )

    parser.add_argument(
        "--randomized-timing",
        action="store_true"
    )

    parser.add_argument(
        "--scan-breadth",
        type=int
    )

    args = parser.parse_args()

    cfg = StealthConfig(
        enabled=True,
        inter_action_delay=args.delay,
        randomized_timing=args.randomized_timing,
        scan_breadth=args.scan_breadth
    )

    n = make_e3_library(
        args.library,
        cfg,
        args.replicates,
        args.seed
    )

    print(
        f"Generated {n} synthetic E3 episodes "
        f"in {args.library}"
    )


if __name__ == "__main__":
    main()