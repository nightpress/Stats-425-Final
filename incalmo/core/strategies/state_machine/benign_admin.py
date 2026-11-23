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
exfiltration. Every event it emits is from benign operations, so any detection
the defender raises on this episode's ``actions.json`` is a false positive. It
uses no LLM, so a benign episode costs $0 in API spend.

Select it via config ``strategy: {"name": "BenignAdmin"}`` (see
``research/run_sweep.py benign-real``). Rounds: env ``INCALMO_BENIGN_ROUNDS``
(default 4).
"""

from __future__ import annotations

import asyncio
import os

from incalmo.core.strategies.incalmo_strategy import IncalmoStrategy
from incalmo.core.actions.HighLevel import FindInformationOnAHost, Scan
from incalmo.core.models.network import Subnet

# Subnets a foothold on the attacker box can legitimately see/monitor.
BENIGN_SUBNETS = ["192.168.200.0/24", "192.168.199.0/24"]


class BenignAdmin(IncalmoStrategy, name="BenignAdmin"):
    def __init__(self, config, logger: str = "incalmo", task_id: str = "") -> None:
        super().__init__(config, logger, task_id)
        self._round = 0
        self._max_rounds = max(1, int(os.environ.get("INCALMO_BENIGN_ROUNDS", "4")))

    async def step(self) -> bool:
        hosts = self.environment_state_service.get_hosts_with_agents()
        if not hosts:
            return True  # no foothold -> nothing benign to do
        foothold = hosts[0]  # a real Host (ip_addresses + agents) from env state

        # 1) Inventory scan of reachable subnets (asset discovery / monitoring).
        subnets = [Subnet(ip_mask=mask, hosts=[]) for mask in BENIGN_SUBNETS]
        try:
            await self.high_level_action_orchestrator.run_action(Scan(foothold, subnets))
        except Exception as exc:  # noqa: BLE001 - benign actor stays resilient
            print(f"[BenignAdmin] scan round {self._round} skipped: {exc!r}")

        # 2) Host info / config read on the controlled host (admin housekeeping).
        try:
            await self.high_level_action_orchestrator.run_action(
                FindInformationOnAHost(foothold)
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[BenignAdmin] find-info round {self._round} skipped: {exc!r}")

        self._round += 1
        if self._round >= self._max_rounds:
            return True
        await asyncio.sleep(5)  # space benign activity out over time
        return False
