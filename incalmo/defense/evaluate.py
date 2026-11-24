"""Turn one episode's telemetry + a defender config into response variables.

The defender is scored on the **sensor** stream (what a SOC sees); exfiltration
and kill-chain ground truth come from the attacker's own log. The two streams
have independent clocks, so everything is aligned to a common episode start
(the earliest timestamp across both) before comparing detection vs. exfil times.

These are the per-episode outcomes the statistical analysis consumes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import timedelta
from typing import Optional

from incalmo.defense.config import DefenseConfig
from incalmo.defense.orchestrator import DefenseOrchestrator
from incalmo.defense.telemetry import SecurityEvent


@dataclass
class EpisodeDefenseMetrics:
    n_events: int
    n_exfil_total: int
    time_to_first_exfil: Optional[float]
    attack_reached_exfil: bool
    episode_duration_s: float
    detected: bool
    time_to_detect: Optional[float]
    time_to_contain: Optional[float]
    n_detections: int
    n_remediations: int
    n_exfil_prevented: int
    n_exfil_realized: int
    prevented_fraction: Optional[float]
    detected_before_first_exfil: Optional[bool]
    is_benign: bool
    false_positive: bool
    n_false_positive_detections: int

    def to_row(self) -> dict:
        return asdict(self)


def _naive(ts):
    """Drop tzinfo so sensor (tz-aware) and attacker-log (naive) times compare.
    All range timestamps are UTC, so this is a safe normalization."""
    return ts.replace(tzinfo=None) if ts.tzinfo is not None else ts


def _empty(is_benign: bool) -> EpisodeDefenseMetrics:
    return EpisodeDefenseMetrics(
        0, 0, None, False, 0.0, False, None, None, 0, 0, 0, 0, None, None,
        is_benign, False, 0,
    )


def evaluate_episode(
    defender_events: list[SecurityEvent],
    config: DefenseConfig,
    *,
    is_benign: bool = False,
    ground_truth_events: Optional[list[SecurityEvent]] = None,
) -> EpisodeDefenseMetrics:
    """Score the defender on ``defender_events``; take exfil ground truth from
    ``ground_truth_events`` (defaults to ``defender_events`` for single-stream use)."""
    if ground_truth_events is None:
        ground_truth_events = defender_events

    firsts = [_naive(e[0].timestamp) for e in (defender_events, ground_truth_events) if e]
    if not firsts:
        return _empty(is_benign)
    episode_start = min(firsts)

    def rel(ts) -> float:
        return (_naive(ts) - episode_start).total_seconds()

    orch = DefenseOrchestrator(config)
    orch.run(defender_events)
    def_start = defender_events[0].timestamp if defender_events else episode_start

    # ground-truth exfiltration (from the attacker's own log), on the common clock
    exfil_times = sorted(rel(e.timestamp) for e in ground_truth_events if e.is_exfil)
    n_exfil_total = len(exfil_times)
    time_to_first_exfil = exfil_times[0] if exfil_times else None
    episode_duration_s = max(
        (rel(e.timestamp) for e in (defender_events + ground_truth_events)), default=0.0
    )

    # defender detections, mapped from defender-relative t to the common clock
    det_epi = [rel(def_start + timedelta(seconds=d.time)) for d in orch.detections]
    cont_epi = [rel(def_start + timedelta(seconds=d.containment_time)) for d in orch.detections]
    detected = bool(orch.detections)
    time_to_detect = min(det_epi) if det_epi else None
    time_to_contain = min(cont_epi) if cont_epi else None

    # Counterfactual: exfiltration strictly after the earliest containment is
    # prevented (global-containment assumption; host identifiers differ across
    # the sensor and attacker streams, so prevention is scored at episode level).
    prevented = sum(1 for t in exfil_times if time_to_contain is not None and t > time_to_contain)
    realized = n_exfil_total - prevented
    prevented_fraction = (prevented / n_exfil_total) if n_exfil_total else None
    detected_before_first_exfil = (
        (time_to_contain is not None and time_to_contain < time_to_first_exfil)
        if time_to_first_exfil is not None else None
    )

    return EpisodeDefenseMetrics(
        n_events=len(defender_events),
        n_exfil_total=n_exfil_total,
        time_to_first_exfil=time_to_first_exfil,
        attack_reached_exfil=n_exfil_total > 0,
        episode_duration_s=episode_duration_s,
        detected=detected,
        time_to_detect=time_to_detect,
        time_to_contain=time_to_contain,
        n_detections=len(orch.detections),
        n_remediations=len(orch.network.records),
        n_exfil_prevented=prevented,
        n_exfil_realized=realized,
        prevented_fraction=prevented_fraction,
        detected_before_first_exfil=detected_before_first_exfil,
        is_benign=is_benign,
        false_positive=is_benign and detected,
        n_false_positive_detections=len(orch.detections) if is_benign else 0,
    )
