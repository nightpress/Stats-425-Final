import argparse
import csv
import json

from pathlib import Path
from statistics import mean

from config.attacker_config import StealthConfig

from incalmo.defense import parse_action_log

from research.grid import (
    e3_fixture_plan,
    defender_configs
)

from research.extract_metrics import episode_rows


def run_e3(
    library_dir,
    out_csv,
    replicates=12
):

    plan = e3_fixture_plan(replicates)

    configs = defender_configs()

    rows = []

    for cell in plan:

        condition = (
            "on" if cell["stealth"] else "off"
        )

        episode_id = (
            f"scripted-{cell['attacker']}"
            f"__{cell['environment']}"
            f"__stealth-{condition}"
            f"__rep{cell['replicate']:03d}"
        )

        episode_dir = (
            Path(library_dir) / episode_id
        )

        if not episode_dir.is_dir():

            raise FileNotFoundError(
                f"Missing telemetry fixture: {episode_dir}"
            )

        # Read the configuration actually used to
        # generate this episode.
        meta = json.loads(
            (episode_dir / "e3_config.json").read_text(
                encoding="utf-8"
            )
        )

        cfg = StealthConfig.model_validate(
            meta["stealth_config"]
        )

        # Ensure that the episode belongs to the
        # expected synthetic experimental condition.
        if (
            meta.get("synthetic") is not True
            or cfg.enabled != cell["stealth"]
        ):

            raise ValueError(
                f"Invalid E3 fixture: {episode_dir}"
            )

        # Parse actual observable telemetry.
        events = parse_action_log(
            str(episode_dir / "action_log.jsonl")
        )

        # Calculate observed intervals.
        gaps = [
            b.t - a.t
            for a, b in zip(events, events[1:])
        ]

        # Measure actual workload properties.
        workload = {

            "synthetic": True,

            "n_observed_hosts": len({
                e.host
                for e in events
                if e.host is not None
            }),

            "mean_event_gap_s": (
                mean(gaps) if gaps else None
            )
        }

        # Run the existing defender evaluation pipeline.
        results = episode_rows(
            str(episode_dir),
            configs,
            is_benign=False,
            episode_id=episode_id
        )

        for row in results:

            row.update(
                experiment="E3",
                stealth=cfg.enabled,
                replicate=cell["replicate"],
                strategy=cell["strategy"]
            )

            row.update(cfg.model_dump())

            row.update(workload)

            rows.append(row)

    output = Path(out_csv)

    output.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=list(rows[0])
        )

        writer.writeheader()

        writer.writerows(rows)

    print(
        f"Wrote {len(rows)} E3 evaluation rows"
    )

    return rows


if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--library",
        required=True
    )

    parser.add_argument(
        "--out",
        required=True
    )

    parser.add_argument(
        "--replicates",
        type=int,
        default=12
    )

    args = parser.parse_args()

    run_e3(
        args.library,
        args.out,
        args.replicates
    )