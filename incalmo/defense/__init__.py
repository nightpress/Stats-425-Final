"""Reactive defense evaluation for Incalmo attacker telemetry.

This package implements an offline *replay* defender: it consumes the telemetry
an Incalmo attacker episode emits (``action_log.jsonl`` + ``results.json``),
evaluates sliding-window threat heuristics, and triggers *simulated* remediation
(host isolation, credential rotation, process termination) against an in-memory
model of the environment. Nothing here touches a real host, network, or process.

The design is deliberately offline so that one (expensive) corpus of recorded
attacker episodes can be scored under many defender configurations for free -
the detection-latency / false-positive operating curve is produced entirely by
re-running :class:`~incalmo.defense.orchestrator.DefenseOrchestrator` over fixed
logs. See ``research/README.md`` for the experiment design.

Modeling assumption (stated so results are interpretable): containment of a host
at time *T* prevents any exfiltration attributed to that host after *T*. The
replay defender does not feed back into the attacker, so prevented-exfiltration
counts are counterfactual under that assumption. A live closed-loop defender is
future work.
"""

from incalmo.defense.config import DefenseConfig
from incalmo.defense.telemetry import (
    SecurityEvent,
    parse_action_log,
    SIGNAL_SPEC,
    STAGE_NAME,
    furthest_stage,
)
from incalmo.defense.orchestrator import (
    DefenseOrchestrator,
    AuditEntry,
    Detection,
)
from incalmo.defense.remediation import NetworkState, RemediationRecord
from incalmo.defense.evaluate import EpisodeDefenseMetrics, evaluate_episode

__all__ = [
    "DefenseConfig",
    "SecurityEvent",
    "parse_action_log",
    "SIGNAL_SPEC",
    "STAGE_NAME",
    "furthest_stage",
    "DefenseOrchestrator",
    "AuditEntry",
    "Detection",
    "NetworkState",
    "RemediationRecord",
    "EpisodeDefenseMetrics",
    "evaluate_episode",
]
