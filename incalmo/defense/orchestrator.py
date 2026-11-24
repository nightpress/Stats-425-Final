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
        self._wwin: deque[float] = deque()  # per-event weights, aligned with _window
        self._last_detection_time: dict[str, float] = {}
        # Running window aggregates, kept in lockstep with _window by _add/_sub so
        # scoring is O(1) per event. A full rescan per event (the earlier design)
        # is O(N*W) and turns quadratic on long streams (~20k events/benign episode).
        self._g_total: float = 0.0                   # weighted score over all window events
        self._g_evi: dict[str, int] = {}             # signal -> count over all window events
        self._h_total: dict[str, float] = {}         # host -> weighted score (host-scoped)
        self._h_evi: dict[str, dict[str, int]] = {}  # host -> signal -> count
        self._h_count: dict[str, int] = {}           # host -> # window events (drives eviction)

    # -- public API ---------------------------------------------------------

    def run(self, events: Iterable[SecurityEvent]) -> list[AuditEntry]:
        """Process an ordered stream of events; return the audit trail."""
        for event in events:
            self.process_event(event)
        return self.audit

    def process_event(self, event: SecurityEvent) -> Optional[Detection]:
        """Ingest one event, updating the window and possibly firing a detection."""
        w = self.config.weights.get(event.signal, event.weight)
        self._window.append(event)
        self._wwin.append(w)
        self._add(event, w)
        self._evict(event.t)

        scope_key = self._scope_key_for(event)
        score = self._scope_total(scope_key)

        if score < self.config.threshold:
            return None
        if not self._armed(scope_key, event.t):
            return None

        # Build the evidence snapshot + implicated host only now that we are firing.
        evidence, implicated = self._scope_detail(scope_key)
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
            ev = self._window.popleft()
            self._sub(ev, self._wwin.popleft())

    def _add(self, ev: SecurityEvent, w: float) -> None:
        """Fold one event INTO the running window aggregates."""
        self._g_total += w
        self._g_evi[ev.signal] = self._g_evi.get(ev.signal, 0) + 1
        if ev.host is not None:
            h = ev.host
            self._h_total[h] = self._h_total.get(h, 0.0) + w
            evi = self._h_evi.setdefault(h, {})
            evi[ev.signal] = evi.get(ev.signal, 0) + 1
            self._h_count[h] = self._h_count.get(h, 0) + 1

    def _sub(self, ev: SecurityEvent, w: float) -> None:
        """Remove one evicted event FROM the running window aggregates."""
        self._g_total -= w
        self._dec(self._g_evi, ev.signal)
        if ev.host is not None:
            h = ev.host
            self._h_total[h] -= w
            self._dec(self._h_evi[h], ev.signal)
            self._h_count[h] -= 1
            if self._h_count[h] <= 0:  # host has no events left in the window
                del self._h_count[h]
                del self._h_total[h]
                del self._h_evi[h]

    @staticmethod
    def _dec(counts: dict[str, int], key: str) -> None:
        """Decrement a count, dropping the key at zero so a snapshot lists only
        signals actually present in the window."""
        c = counts.get(key, 0) - 1
        if c <= 0:
            counts.pop(key, None)
        else:
            counts[key] = c

    def _scope_key_for(self, event: SecurityEvent) -> str:
        if self.config.scope == "global":
            return NetworkState.GLOBAL
        return event.host or NetworkState.GLOBAL

    def _scope_total(self, scope_key: str) -> float:
        """Windowed weighted score for a scope - O(1) from the running aggregates.

        A global scope sums every window event (hosted or not); a host scope sums
        only that host's events. Per-signal config weights win over the event's own
        weight; that choice is baked in at _add time.
        """
        if scope_key == NetworkState.GLOBAL:
            return self._g_total
        return self._h_total.get(scope_key, 0.0)

    def _scope_detail(self, scope_key: str) -> tuple[dict[str, int], Optional[str]]:
        """Evidence snapshot + implicated host for a scope that is about to fire.

        Returned dicts are copies, so a stored detection keeps the window state at
        firing time. For a global scope the implicated host is the top-weighted one
        (ties break by first appearance; immaterial to the metrics)."""
        if scope_key == NetworkState.GLOBAL:
            implicated = max(self._h_total, key=self._h_total.get) if self._h_total else None
            return dict(self._g_evi), implicated
        return dict(self._h_evi.get(scope_key, {})), scope_key

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
