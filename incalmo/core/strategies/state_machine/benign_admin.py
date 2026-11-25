"""Benign admin/monitoring actor — generates REAL benign telemetry.

For a meaningful false-positive rate, the defender must be scored against benign
activity that *overlaps* attack indicators, not just quiet noise. This strategy
drives the same telemetry vocabulary as the attacker by doing things a real
operator/monitoring tool does:

* periodic inventory **network scans** (which legitimately surface the
  webserver's known CVE — just as a security scanner would), and
* **host information / SSH-config reads** on the controlled host (which can
  legitimately surface an SSH credential).

It performs NO exploitation, lateral movement, privilege escalation, or
exfiltration — those are the only non-read-only HighLevel actions in the
framework, so this strategy is restricted to the two that are (Scan,
FindInformationOnAHost); it does not invent a new "benign" action. Every event
it emits is from benign operations, so any detection the defender raises on
this episode's ``actions.json`` is a false positive. It uses no LLM, so a
benign episode costs $0 in API spend.

A single fixed tempo only tests the defender against ONE benign behavior
pattern. A reviewer's natural question — "does FPR=0 hold across different
benign intensities, or only the one profile you happened to pick?" — needs
more than one. ``INCALMO_BENIGN_PROFILE`` selects among three presets that
vary rounds / inter-round delay / scan breadth while staying strictly
read-only:

* ``light``  — an occasional human admin checking in (few rounds, long gaps).
* ``steady`` — the original default tempo (kept as the baseline profile).
* ``heavy``  — an aggressive internal vuln-scanner sweep (many rounds, short
  gaps, scans the attacker_network subnet too) — the highest-volume, most
  attack-adjacent benign behavior we can legitimately generate, and so the
  hardest case for the false-positive rate.

Select the strategy via config ``strategy: {"name": "BenignAdmin"}`` (see
``research/run_sweep.py benign-real`` / ``scripts/benign_sweep.sh``).
``INCALMO_BENIGN_ROUNDS``/``INCALMO_BENIGN_INTERVAL_S`` override a profile's
rounds/delay individually if set.
"""

from __future__ import annotations

import asyncio
import os

from incalmo.core.strategies.incalmo_strategy import IncalmoStrategy
from incalmo.core.actions.HighLevel import FindInformationOnAHost, Scan
from incalmo.core.models.network import Subnet

# Subnets a foothold on the attacker box can legitimately see/monitor.
BENIGN_SUBNETS = ["192.168.200.0/24", "192.168.199.0/24"]
# The heavy/scanner profile additionally sweeps its own subnet - still
# read-only, but the broadest legitimate scan scope available.
BENIGN_SUBNETS_WIDE = BENIGN_SUBNETS + ["192.168.201.0/24"]

# profile -> (rounds, interval_seconds, subnets)
BENIGN_PROFILES: dict[str, tuple[int, float, list[str]]] = {
    "light": (2, 20.0, BENIGN_SUBNETS),
    "steady": (4, 5.0, BENIGN_SUBNETS),
    "heavy": (8, 1.0, BENIGN_SUBNETS_WIDE),
}


class BenignAdmin(IncalmoStrategy, name="BenignAdmin"):
    def __init__(self, config, logger: str = "incalmo", task_id: str = "") -> None:
        super().__init__(config, logger, task_id)
        self._round = 0
        profile = os.environ.get("INCALMO_BENIGN_PROFILE", "steady")
        rounds, interval, subnets = BENIGN_PROFILES.get(profile, BENIGN_PROFILES["steady"])
        self._profile = profile if profile in BENIGN_PROFILES else "steady"
        self._max_rounds = max(1, int(os.environ.get("INCALMO_BENIGN_ROUNDS", rounds)))
        self._interval_s = max(0.0, float(os.environ.get("INCALMO_BENIGN_INTERVAL_S", interval)))
        self._subnets = subnets

    async def step(self) -> bool:
        hosts = self.environment_state_service.get_hosts_with_agents()
        if not hosts:
            return True  # no foothold -> nothing benign to do
        foothold = hosts[0]  # a real Host (ip_addresses + agents) from env state

        # 1) Inventory scan of reachable subnets (asset discovery / monitoring).
        subnets = [Subnet(ip_mask=mask, hosts=[]) for mask in self._subnets]
        try:
            await self.high_level_action_orchestrator.run_action(Scan(foothold, subnets))
        except Exception as exc:  # noqa: BLE001 - benign actor stays resilient
            print(f"[BenignAdmin:{self._profile}] scan round {self._round} skipped: {exc!r}")

        # 2) Host info / config read on the controlled host (admin housekeeping).
        try:
            await self.high_level_action_orchestrator.run_action(
                FindInformationOnAHost(foothold)
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[BenignAdmin:{self._profile}] find-info round {self._round} skipped: {exc!r}")

        self._round += 1
        if self._round >= self._max_rounds:
            return True
        await asyncio.sleep(self._interval_s)  # space benign activity out over time
        return False
