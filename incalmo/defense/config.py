"""Configuration for the replay defender.

The two knobs that trace the operating curve are ``window_seconds`` and
``threshold``: a wider window and lower threshold detect sooner but raise more
false positives on benign telemetry. Everything else has a sensible default so a
sweep can vary just those two.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from incalmo.defense.telemetry import SIGNAL_SPEC


def _default_weights() -> dict[str, float]:
    return {signal: spec[1] for signal, spec in SIGNAL_SPEC.items()}


@dataclass
class DefenseConfig:
    """Parameters for :class:`~incalmo.defense.orchestrator.DefenseOrchestrator`."""

    window_seconds: float = 120.0
    """Width of the sliding detection window."""
    threshold: float = 8.0
    """Windowed threat score at or above which the orchestrator acts."""
    scope: str = "host"
    """``"host"`` scores/contains per host; ``"global"`` scores the whole episode."""
    remediation_latency_seconds: float = 0.0
    """Delay between detection and effective containment."""
    weights: dict[str, float] = field(default_factory=_default_weights)
    """Per-signal severity weights (override to test alternate heuristics)."""
    enable_isolation: bool = True
    enable_credential_rotation: bool = True
    enable_process_termination: bool = True
    cooldown_seconds: float = 0.0
    """Per-host minimum spacing between repeated remediations (0 = re-arm at once)."""

    def weight_for(self, signal: str) -> float:
        return self.weights.get(signal, SIGNAL_SPEC.get(signal, ("other", 1.0))[1])

    def label(self) -> str:
        """Short stable identifier for this config (used as a sweep cell key)."""
        return f"w{self.window_seconds:g}_t{self.threshold:g}_{self.scope}"
