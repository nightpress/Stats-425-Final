"""Simulated remediation against an in-memory model of the environment.

None of this performs real I/O. Each action records what *would* have happened
(which host isolated, which credentials rotated, which processes terminated) and
mutates an in-memory :class:`NetworkState` so later counterfactual reasoning can
ask "was this host contained at time T?".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RemediationRecord:
    """One simulated remediation action in the audit trail."""

    time: float
    action: str  # "isolate_host" | "rotate_credentials" | "terminate_processes"
    host: Optional[str]
    detail: str = ""


class NetworkState:
    """Tracks which hosts are contained, and when, under simulated remediation."""

    # Sentinel used when the defender contains "the environment" rather than a
    # single named host (global scope, or a host-less detection).
    GLOBAL = "*"

    def __init__(self) -> None:
        self._contained_at: dict[str, float] = {}
        self.records: list[RemediationRecord] = []

    def is_contained(self, host: Optional[str], at_time: float) -> bool:
        """True if ``host`` was contained at or before ``at_time``.

        A global containment (``GLOBAL``) contains every host.
        """
        global_t = self._contained_at.get(self.GLOBAL)
        if global_t is not None and global_t <= at_time:
            return True
        if host is None:
            return False
        host_t = self._contained_at.get(host)
        return host_t is not None and host_t <= at_time

    def contained_time(self, host: Optional[str]) -> Optional[float]:
        candidates = [t for t in (self._contained_at.get(self.GLOBAL),
                                  self._contained_at.get(host) if host else None)
                      if t is not None]
        return min(candidates) if candidates else None

    def isolate_host(self, host: Optional[str], time: float, detail: str = "") -> RemediationRecord:
        key = host or self.GLOBAL
        # Record the earliest containment time for the host.
        if key not in self._contained_at or time < self._contained_at[key]:
            self._contained_at[key] = time
        record = RemediationRecord(time=time, action="isolate_host", host=host,
                                   detail=detail or f"drop inter-subnet traffic for {key}")
        self.records.append(record)
        return record

    def rotate_credentials(self, host: Optional[str], time: float, detail: str = "") -> RemediationRecord:
        record = RemediationRecord(time=time, action="rotate_credentials", host=host,
                                   detail=detail or "invalidate harvested credentials")
        self.records.append(record)
        return record

    def terminate_processes(self, host: Optional[str], time: float, detail: str = "") -> RemediationRecord:
        record = RemediationRecord(time=time, action="terminate_processes", host=host,
                                   detail=detail or "terminate unauthorized implant processes")
        self.records.append(record)
        return record
