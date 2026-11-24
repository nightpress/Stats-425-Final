"""The DefenseOrchestrator: sliding-window threat scoring + simulated remediation.

Streams :class:`~incalmo.defense.telemetry.SecurityEvent` objects, maintains a
sliding window of recent events, and when the windowed threat score for a scope
(a single host, or the whole episode) crosses the configured threshold it fires
one detection and dispatches simulated remediation, appending an audit entry.

Policy (scoring/thresholding) is kept separate from mechanism (remediation via
:class:`~incalmo.defense.remediation.NetworkState`) so either can be tested or
swapped on its own.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterable, Optional

from incalmo.defense.config import DefenseConfig
from incalmo.defense.remediation import NetworkState, RemediationRecord
from incalmo.defense.telemetry import CREDENTIAL_CATEGORIES, SecurityEvent


@dataclass
class Detection:
    """A threshold crossing that triggered remediation."""

    time: float
    scope_key: str  # a host, or NetworkState.GLOBAL
    score: float
    implicated_host: Optional[str]
    containment_time: float
    evidence: dict[str, int] = field(default_factory=dict)  # signal -> count in window


@dataclass
class AuditEntry:
    """One detection together with the remediation it caused - the audit trail."""

    detection: Detection
    remediations: list[RemediationRecord] = field(default_factory=list)

    def summary(self) -> str:
        ev = ", ".join(f"{k}x{v}" for k, v in sorted(self.detection.evidence.items()))
        acts = ", ".join(r.action for r in self.remediations) or "none"
        host = self.detection.implicated_host or "environment"
        return (
            f"t={self.detection.time:.1f}s score={self.detection.score:.1f} "
            f"target={host} evidence=[{ev}] -> {acts}"
        )


class DefenseOrchestrator:
    """Evaluate telemetry and trigger simulated remediation with an audit trail."""

    def __init__(self, config: Optional[DefenseConfig] = None) -> None:
        self.config = config or DefenseConfig()
        self.network = NetworkState()
        self.audit: list[AuditEntry] = []
        self.detections: list[Detection] = []
        self._window: deque[SecurityEvent] = deque()
        self._last_detection_time: dict[str, float] = {}

    # -- public API ---------------------------------------------------------

    def run(self, events: Iterable[SecurityEvent]) -> list[AuditEntry]:
        """Process an ordered stream of events; return the audit trail."""
        for event in events:
            self.process_event(event)
        return self.audit

    def process_event(self, event: SecurityEvent) -> Optional[Detection]:
        """Ingest one event, updating the window and possibly firing a detection."""
        self._window.append(event)
        self._evict(event.t)

        scope_key = self._scope_key_for(event)
        score, evidence, implicated = self._score(scope_key)

        if score < self.config.threshold:
            return None
        if not self._armed(scope_key, event.t):
            return None

        containment_time = event.t + self.config.remediation_latency_seconds
        detection = Detection(
            time=event.t,
            scope_key=scope_key,
            score=score,
            implicated_host=implicated,
            containment_time=containment_time,
            evidence=evidence,
        )
        self.detections.append(detection)
        self._last_detection_time[scope_key] = event.t
        self.audit.append(AuditEntry(detection=detection, remediations=self._remediate(detection)))
        return detection

    # -- internals ----------------------------------------------------------

    def _evict(self, now: float) -> None:
        cutoff = now - self.config.window_seconds
        while self._window and self._window[0].t < cutoff:
            self._window.popleft()

    def _scope_key_for(self, event: SecurityEvent) -> str:
        if self.config.scope == "global":
            return NetworkState.GLOBAL
        return event.host or NetworkState.GLOBAL

    def _score(self, scope_key: str) -> tuple[float, dict[str, int], Optional[str]]:
        """Windowed weighted score for a scope, plus evidence counts and the
        top-contributing host."""
        total = 0.0
        evidence: dict[str, int] = {}
        host_weight: dict[str, float] = {}
        for ev in self._window:
            in_scope = (
                scope_key == NetworkState.GLOBAL
                or ev.host == scope_key
                or (ev.host is None and scope_key == NetworkState.GLOBAL)
            )
            if not in_scope:
                continue
            # Explicit per-signal config weight wins; otherwise use the event's
            # own weight (set by whichever parser - attacker outcomes or sensors).
            w = self.config.weights.get(ev.signal, ev.weight)
            total += w
            evidence[ev.signal] = evidence.get(ev.signal, 0) + 1
            if ev.host is not None:
                host_weight[ev.host] = host_weight.get(ev.host, 0.0) + w
        implicated: Optional[str]
        if scope_key != NetworkState.GLOBAL:
            implicated = scope_key
        elif host_weight:
            implicated = max(host_weight, key=host_weight.get)
        else:
            implicated = None
        return total, evidence, implicated

    def _armed(self, scope_key: str, now: float) -> bool:
        """Whether a (fresh) detection may fire for this scope.

        With ``cooldown_seconds <= 0`` a scope fires at most once (the first
        crossing - what detection latency and containment are measured from).
        A positive cooldown re-arms the scope after that many seconds.
        """
        last = self._last_detection_time.get(scope_key)
        if last is None:
            return True
        if self.config.cooldown_seconds <= 0:
            return False
        return (now - last) >= self.config.cooldown_seconds

    def _remediate(self, detection: Detection) -> list[RemediationRecord]:
        # Containment breadth follows the configured scope: a per-host posture
        # quarantines the implicated host; a global posture quarantines the whole
        # environment (host=None -> NetworkState.GLOBAL). implicated_host is kept
        # on the detection for the audit either way.
        target = None if self.config.scope == "global" else detection.implicated_host
        t = detection.containment_time
        records: list[RemediationRecord] = []
        if self.config.enable_isolation:
            records.append(self.network.isolate_host(target, t))
        if self.config.enable_credential_rotation and self._window_has_credentials(detection):
            records.append(self.network.rotate_credentials(target, t))
        if self.config.enable_process_termination:
            records.append(self.network.terminate_processes(target, t))
        return records

    def _window_has_credentials(self, detection: Detection) -> bool:
        return any(
            ev.category in CREDENTIAL_CATEGORIES
            and (detection.scope_key == NetworkState.GLOBAL or ev.host == detection.scope_key)
            for ev in self._window
        )
