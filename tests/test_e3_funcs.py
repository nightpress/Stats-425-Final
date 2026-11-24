import random
import tempfile
import unittest

from pathlib import Path

from config.attacker_config import StealthConfig
from incalmo.defense import parse_action_log

from research.e3_replay import run_e3

from research.e3_workload import (
    synthetic_episode,
    make_e3_library
)

from research.grid import (
    e3_fixture_plan,
    defender_configs
)

from research.synthesize import _attack_episode


class TestE3Workload(unittest.TestCase):

    def events(self, cfg, seed=42, n_hosts=6):
        """
        Generate telemetry and parse it using
        the actual Incalmo telemetry parser.
        """

        lines, _ = synthetic_episode(
            seed,
            n_hosts,
            cfg
        )

        with tempfile.TemporaryDirectory() as tmp:

            p = Path(tmp) / "action_log.jsonl"

            p.write_text(
                "\n".join(lines) + "\n",
                encoding="utf-8"
            )

            return parse_action_log(str(p))

    @staticmethod
    def gaps(events):

        return [
            b.t - a.t
            for a, b in zip(events, events[1:])
        ]

    def test_disabled_preserves_original(self):
        """
        Disabled settings must preserve original telemetry.
        """

        cfg = StealthConfig(
            enabled=False,
            inter_action_delay=5,
            randomized_timing=True,
            scan_breadth=1
        )

        actual = synthetic_episode(
            42,
            6,
            cfg
        )

        expected = _attack_episode(
            random.Random(42),
            n_hosts=6
        )

        self.assertEqual(actual, expected)

    def test_fixed_virtual_intervals(self):
        """
        Each original interval must increase by
        exactly the configured fixed delay.
        """

        baseline = self.events(
            StealthConfig(enabled=False)
        )

        delayed = self.events(
            StealthConfig(
                enabled=True,
                inter_action_delay=5
            )
        )

        self.assertEqual(
            len(baseline),
            len(delayed)
        )

        self.assertGreater(len(baseline), 1)

        for original, modified in zip(
            self.gaps(baseline),
            self.gaps(delayed)
        ):

            self.assertAlmostEqual(
                modified - original,
                5,
                places=5
            )

    def test_jitter_bounds_and_additive_delay(self):
        """
        Random timing must add 0-10 seconds to the
        original interval.

        Fixed and randomized delays must be additive.
        """

        baseline = self.events(
            StealthConfig(enabled=False)
        )

        a = self.events(
            StealthConfig(
                enabled=True,
                randomized_timing=True
            )
        )

        b = self.events(
            StealthConfig(
                enabled=True,
                randomized_timing=True,
                inter_action_delay=5
            )
        )

        g0 = self.gaps(baseline)
        ga = self.gaps(a)
        gb = self.gaps(b)

        self.assertEqual(len(g0), len(ga))
        self.assertEqual(len(ga), len(gb))

        extras = [
            x - z
            for z, x in zip(g0, ga)
        ]

        # Confirm actual random variation.
        self.assertGreater(
            len(set(round(x, 5) for x in extras)),
            1
        )

        tolerance = 1e-5

        for z, x, y in zip(g0, ga, gb):

            # Random delay adds 0-10 seconds.
            self.assertTrue(
                -tolerance <= x - z <= 10 + tolerance
            )

            # Fixed + random delay adds 5-15 seconds.
            self.assertTrue(
                5 - tolerance <= y - z <= 15 + tolerance
            )

            # Fixed delay remains additive.
            self.assertAlmostEqual(
                y - x,
                5,
                places=5
            )

        # Timing changes must not change event content.
        self.assertEqual(
            [
                (e.signal, e.host, e.detail)
                for e in baseline
            ],
            [
                (e.signal, e.host, e.detail)
                for e in b
            ]
        )

    def test_breadth_changes_observable_hosts(self):
        """
        Verify the number of fictional hosts changes
        in the generated telemetry.
        """

        full = self.events(
            StealthConfig(
                enabled=True,
                inter_action_delay=5
            )
        )

        narrow = self.events(
            StealthConfig(
                enabled=True,
                inter_action_delay=5,
                scan_breadth=2
            )
        )

        hosts = lambda es: {
            e.host
            for e in es
            if e.host is not None
        }

        self.assertEqual(
            len(hosts(full)),
            6
        )

        self.assertEqual(
            len(hosts(narrow)),
            2
        )

        self.assertTrue(
            hosts(narrow).issubset(hosts(full))
        )

        self.assertLess(
            len(narrow),
            len(full)
        )

        # Verify fictional host-discovery payloads.
        for event in narrow:

            if event.signal == "HostsDiscovered":

                self.assertEqual(
                    len(event.detail["host_ips"]),
                    2
                )

    def test_seed_reproducibility(self):
        """
        Identical seeds and settings must produce
        identical telemetry.
        """

        cfg = StealthConfig(
            enabled=True,
            randomized_timing=True
        )

        self.assertEqual(
            synthetic_episode(42, 6, cfg),
            synthetic_episode(42, 6, cfg)
        )

        self.assertNotEqual(
            synthetic_episode(42, 6, cfg),
            synthetic_episode(43, 6, cfg)
        )

    def test_actual_defender_replay(self):
        """
        Generate a small synthetic E3 library and
        run the original defender evaluation pipeline.
        """

        with tempfile.TemporaryDirectory() as tmp:

            lib = Path(tmp) / "fixtures"
            out = Path(tmp) / "rows.csv"

            cfg = StealthConfig(
                enabled=True,
                inter_action_delay=5,
                randomized_timing=True,
                scan_breadth=2
            )

            n = make_e3_library(
                lib,
                cfg,
                replicates=1,
                seed=42
            )

            self.assertEqual(
                n,
                len(e3_fixture_plan(1))
            )

            rows = run_e3(
                lib,
                out,
                replicates=1
            )

            self.assertEqual(
                len(rows),
                n * len(defender_configs())
            )

            self.assertTrue(out.is_file())

            # Confirm offline telemetry is used.
            self.assertTrue(
                all(
                    r["defender_input"] == "action_log"
                    for r in rows
                )
            )

            # Confirm no LLM calls.
            self.assertTrue(
                all(
                    r["n_llm_calls"] == 0
                    for r in rows
                )
            )

            # Check ground-truth outcome consistency.
            self.assertTrue(
                all(
                    r["n_exfil_total"] == r["gt_n_exfil"]
                    for r in rows
                )
            )

            on = [
                r for r in rows
                if r["stealth"]
            ]

            self.assertGreater(len(on), 0)

            # Verify fictional host coverage.
            self.assertTrue(
                all(
                    r["n_observed_hosts"] == 2
                    for r in on
                )
            )

            # Total intervals retain the original timing.
            # Therefore, they are not capped at 15 seconds.
            self.assertTrue(
                all(
                    r["mean_event_gap_s"] >= 5 - 1e-5
                    for r in on
                )
            )

            # Match corresponding experimental conditions.
            pairs = {}

            for r in rows:

                key = (
                    r["strategy"],
                    r["environment"],
                    r["replicate"],
                    r["defender_label"]
                )

                pairs.setdefault(
                    key, {}
                )[r["stealth"]] = r

            # Verify that every pair has both conditions.
            self.assertTrue(
                all(
                    set(p.keys()) == {False, True}
                    for p in pairs.values()
                )
            )

            # Verify that workload size changes.
            self.assertTrue(
                all(
                    p[True]["n_events"]
                    < p[False]["n_events"]
                    for p in pairs.values()
                )
            )

            # Verify valid defender evaluation outputs,
            # without requiring a predetermined outcome.
            self.assertTrue(
                all(
                    isinstance(r["detected"], bool)
                    for r in rows
                )
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)