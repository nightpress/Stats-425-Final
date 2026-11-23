"""Normalize Incalmo attacker logs into a stream of observable security events.

The defender consumes *observable telemetry* - the effects a host/network sensor
(EDR/IDS/SIEM) would actually record - which we take to be the attacker's
``action_results`` outcomes in ``action_log.jsonl`` (a new host beaconing, a
credential surfacing, data leaving). The attacker's internal high-level planning
lines are *not* treated as observable; they are used only to attribute a host to
outcome events that do not name one (e.g. ``ExfiltratedData``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

# signal name -> (MITRE-ish category, default severity weight)
# Keyed by the attacker's action_results outcome keys (see tools profiling of the
# shipped example episode). Unknown signals fall back to ("other", 1.0).
SIGNAL_SPEC: dict[str, tuple[str, float]] = {
    "HostsDiscovered": ("recon", 1.0),
    "ServicesDiscoveredOnHost": ("recon", 1.0),
    "VulnerableServiceFound": ("exploitation", 3.0),
    "InfectedNewHost": ("compromise", 5.0),
    "SSHCredentialFound": ("credential-access", 4.0),
    "SudoVersion": ("privilege-escalation", 2.0),
    "FilesFound": ("collection", 1.0),
    "FileContentsFound": ("collection", 1.5),
    "BashOutputEvent": ("execution", 0.5),
    "ExfiltratedData": ("exfiltration", 6.0),
}

# Categories that justify rotating credentials when seen in a detection window.
CREDENTIAL_CATEGORIES = frozenset({"credential-access"})
# The outcome signal that constitutes attacker success (data leaving the network).
EXFIL_SIGNAL = "ExfiltratedData"


@dataclass
class SecurityEvent:
    """One observable telemetry event, normalized from an action_log line."""

    index: int
    """0-based position in the parsed stream (stable tie-breaker for equal times)."""
    timestamp: datetime
    t: float
    """Seconds since the first event of the episode."""
    signal: str
    category: str
    weight: float
    host: Optional[str]
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def is_exfil(self) -> bool:
        return self.signal == EXFIL_SIGNAL


def _coerce_host(value: Any) -> Optional[str]:
    """Best-effort host string from a str or an agent/host dict. Never raises.

    For an agent dict, prefer its IP (``host_ip_addrs``) so hosts are identified
    consistently with the IP-keyed outcome events (ServicesDiscoveredOnHost,
    VulnerableServiceFound, ...) rather than by container hostname.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value or None
    if isinstance(value, dict):
        ips = value.get("host_ip_addrs")
        if isinstance(ips, list) and ips and isinstance(ips[0], str):
            return ips[0]
        for key in ("host_ip", "ip_address", "host", "hostname"):
            got = value.get(key)
            if isinstance(got, str) and got:
                return got
    return None


def _host_from_result(signal: str, payload: Any) -> Optional[str]:
    """Extract the host a result event pertains to, by the event's known shape."""
    if not isinstance(payload, dict):
        return None
    if signal == "ServicesDiscoveredOnHost":
        return _coerce_host(payload.get("host_ip"))
    if signal == "VulnerableServiceFound":
        return _coerce_host(payload.get("host"))
    if signal == "InfectedNewHost":
        # The newly infected host is the meaningful target; fall back to the
        # source agent's host if the new agent is not named in the payload.
        return (
            _coerce_host(payload.get("new_agent"))
            or _coerce_host(payload.get("agent"))
            or _coerce_host(payload.get("source_agent"))
        )
    if signal in ("SSHCredentialFound", "FilesFound", "FileContentsFound", "BashOutputEvent"):
        return _coerce_host(payload.get("agent"))
    # HostsDiscovered is subnet-level; ExfiltratedData names only a file.
    return None


def _target_host_from_highlevel(action_name: str, params: dict[str, Any]) -> Optional[str]:
    """The host a high-level action is aimed at (used only for host attribution)."""
    if not isinstance(params, dict):
        return None
    for key in ("host_to_attack", "target_host", "scan_host", "host"):
        if key in params:
            got = _coerce_host(params[key])
            if got:
                return got
    return None


def _record_timestamp(record: dict[str, Any]) -> Optional[datetime]:
    """Timestamp of a log line, across schemas (``timestamp`` or ``ts_finish``)."""
    for key in ("timestamp", "ts_finish", "ts_start"):
        raw = record.get(key)
        if raw:
            try:
                return datetime.fromisoformat(raw)
            except (TypeError, ValueError):
                continue
    return None


def _record_outcomes(record: dict[str, Any]):
    """Yield (signal, payload) from either schema on one line:

    * the example corpus:  ``action_results`` is a dict {Signal: payload}
    * the live runtime:     ``events`` is a list of {class_name, ...} objects
    """
    results = record.get("action_results")
    if isinstance(results, dict):
        for signal, payload in results.items():
            yield signal, payload
    events = record.get("events")
    if isinstance(events, list):
        for ev in events:
            if isinstance(ev, dict) and ev.get("class_name"):
                yield ev["class_name"], ev


def parse_action_log(path: str) -> list[SecurityEvent]:
    """Parse an Incalmo action log into a time-ordered list of SecurityEvents.

    Handles both on-disk shapes: the live runtime's ``actions.json`` (outcomes in
    an ``events`` list, ``ts_start``/``ts_finish`` times) and the shipped example
    ``action_log.jsonl`` (outcomes in an ``action_results`` dict, ``timestamp``).
    One event is emitted per outcome; an outcome that names no host inherits the
    acting agent's host, then the most recent action's host. Malformed lines are
    skipped rather than aborting the parse.
    """
    raw: list[tuple[datetime, str, str, float, Optional[str], dict[str, Any]]] = []
    current_target_host: Optional[str] = None

    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts = _record_timestamp(record)
            params = record.get("action_params") or {}
            # The host this line acts from: the acting agent, else a high-level
            # action's explicit target. Used to attribute host-less outcomes.
            line_host = _coerce_host(params.get("agent")) or _target_host_from_highlevel(
                record.get("action_name", ""), params
            )
            if line_host:
                current_target_host = line_host

            if ts is None:
                continue

            for signal, payload in _record_outcomes(record):
                category, weight = SIGNAL_SPEC.get(signal, ("other", 1.0))
                host = _host_from_result(signal, payload) or line_host or current_target_host
                detail = payload if isinstance(payload, dict) else {"value": payload}
                raw.append((ts, signal, category, weight, host, detail))

    raw.sort(key=lambda r: r[0])
    if not raw:
        return []
    start = raw[0][0]
    events: list[SecurityEvent] = []
    for index, (ts, signal, category, weight, host, detail) in enumerate(raw):
        events.append(
            SecurityEvent(
                index=index,
                timestamp=ts,
                t=(ts - start).total_seconds(),
                signal=signal,
                category=category,
                weight=weight,
                host=host,
                detail=detail,
            )
        )
    return events
