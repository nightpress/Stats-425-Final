"""Turn one episode's telemetry + a defender config into response variables.

These are the per-episode outcomes the statistical analysis consumes: attacker
ground truth (did data leave, and when), defender performance (did it detect,
how fast), the counterfactual prevention under the stated containment
assumption, and - for benign episodes - false positives.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

from incalmo.defense.config import DefenseConfig
from incalmo.defense.orchestrator import DefenseOrchestrator
from incalmo.defense.telemetry import SecurityEvent


@dataclass
class EpisodeDefenseMetrics:
    # attacker ground truth (independent of the defender)
    n_events: int
    n_exfil_total: int
    time_to_first_exfil: Optional[float]
    attack_reached_exfil: bool
    episode_duration_s: float
    # defender performance
    detected: bool
    time_to_detect: Optional[float]
    time_to_contain: Optional[float]
    n_detections: int
    n_remediations: int
    # counterfactual outcome under the containment assumption
    n_exfil_prevented: int
    n_exfil_realized: int
    prevented_fraction: Optional[float]
    detected_before_first_exfil: Optional[bool]
    # benign / false-positive accounting
    is_benign: bool
    false_positive: bool
    n_false_positive_detections: int

    def to_row(self) -> dict:
        return asdict(self)


def evaluate_episode(
    events: list[SecurityEvent],
    config: DefenseConfig,
    *,
    is_benign: bool = False,
) -> EpisodeDefenseMetrics:
    """Run the orchestrator over ``events`` and compute per-episode metrics."""
    orch = DefenseOrchestrator(config)
    orch.run(events)

    exfils = [e for e in events if e.is_exfil]
    n_exfil_total = len(exfils)
    time_to_first_exfil = exfils[0].t if exfils else None
    episode_duration_s = events[-1].t if events else 0.0

    detections = orch.detections
    detected = len(detections) > 0
    time_to_detect = min((d.time for d in detections), default=None)
    time_to_contain = min((d.containment_time for d in detections), default=None)
    n_remediations = len(orch.network.records)

    # Counterfactual: an exfil at time E on host H is prevented if H (or the
    # environment, under global scope) was contained strictly before E.
    prevented = 0
    for e in exfils:
        contained = orch.network.contained_time(e.host)
        if contained is not None and contained < e.t:
            prevented += 1
    realized = n_exfil_total - prevented
    prevented_fraction = (prevented / n_exfil_total) if n_exfil_total else None

    detected_before_first_exfil: Optional[bool]
    if time_to_first_exfil is None:
        detected_before_first_exfil = None
    else:
        detected_before_first_exfil = (
            time_to_contain is not None and time_to_contain < time_to_first_exfil
        )

    false_positive = is_benign and detected

    return EpisodeDefenseMetrics(
        n_events=len(events),
        n_exfil_total=n_exfil_total,
        time_to_first_exfil=time_to_first_exfil,
        attack_reached_exfil=n_exfil_total > 0,
        episode_duration_s=episode_duration_s,
        detected=detected,
        time_to_detect=time_to_detect,
        time_to_contain=time_to_contain,
        n_detections=len(detections),
        n_remediations=n_remediations,
        n_exfil_prevented=prevented,
        n_exfil_realized=realized,
        prevented_fraction=prevented_fraction,
        detected_before_first_exfil=detected_before_first_exfil,
        is_benign=is_benign,
        false_positive=false_positive,
        n_false_positive_detections=len(detections) if is_benign else 0,
    )
