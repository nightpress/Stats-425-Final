"""Normalize INDEPENDENT sensor telemetry into the defender's event stream.

This is the external-validity path: the defender scores what a real SOC would
have - host-EDR (Falco) + network (Suricata) - NOT the attacker's own
``actions.json`` (which research/extract_metrics uses only as ground-truth
labels). Both are mapped into the same :class:`SecurityEvent` taxonomy so the
sliding-window orchestrator scores host and network signals uniformly.

Falco emits one JSON object per rule hit (rule, priority, MITRE ``tags``,
``output_fields`` incl. ``container.name`` and ``proc.name``). Suricata emits
``event_type`` records (flow/http/ssh/fileinfo/alert); we use the clean
protocol/flow metadata (SSH sessions = lateral movement, HTTP to the web app =
exploit/recon, large flows = exfiltration) rather than its signature alerts,
which don't reassemble reliably on offloaded container-bridge captures.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from incalmo.defense.telemetry import SecurityEvent

# --- Falco host-EDR rule -> (category, weight) -------------------------------
# Categories align with the attacker-side taxonomy (telemetry.SIGNAL_SPEC).
_FALCO_RULES: dict[str, tuple[str, float]] = {
    "Read sensitive file untrusted": ("credential-access", 4.0),
    "Run shell untrusted": ("execution", 2.0),
    "Redirect STDOUT/STDIN to Network Connection in Container": ("c2", 3.0),
    "Launch Remote File Copy Tools in Container": ("lateral-movement", 4.0),
    "Netcat Remote Code Execution in Container": ("exploitation", 4.0),
    "Create files below dev": ("execution", 1.0),
    "Clear Log Activities": ("defense-evasion", 3.0),
    "Packet socket created in container": ("recon", 2.0),
}
_FALCO_PRIORITY_WEIGHT = {  # fallback weight by Falco priority when rule unmapped
    "Emergency": 5.0, "Alert": 5.0, "Critical": 4.0, "Error": 3.0,
    "Warning": 2.5, "Notice": 1.5, "Informational": 0.8, "Debug": 0.5,
}


def _iso(value: Any) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _raw_falco(path: str):
    try:
        handle = open(path, "r", encoding="utf-8")
    except FileNotFoundError:
        return
    with handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = _iso(rec.get("time"))
            if ts is None:
                continue
            rule = rec.get("rule", "")
            fields = rec.get("output_fields", {}) or {}
            host = fields.get("container.name") or rec.get("hostname")
            category, weight = _FALCO_RULES.get(
                rule, ("execution", _FALCO_PRIORITY_WEIGHT.get(rec.get("priority", ""), 1.5))
            )
            yield ts, f"falco:{rule}", category, weight, host, {
                "proc": fields.get("proc.name"), "tags": rec.get("tags"),
            }


def _raw_suricata(path: str):
    try:
        handle = open(path, "r", encoding="utf-8")
    except FileNotFoundError:
        return
    with handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            etype = rec.get("event_type")
            ts = _iso(rec.get("timestamp"))
            if ts is None:
                continue
            dst = rec.get("dest_ip")
            dport = rec.get("dest_port")
            if etype == "ssh":
                # SSH session = lateral movement; attribute to the target host.
                yield ts, "net:ssh_session", "lateral-movement", 4.0, dst, {
                    "src": rec.get("src_ip"), "dport": dport,
                }
            elif etype == "http":
                http = rec.get("http", {}) or {}
                # POST / app-server port => likely exploit; GET scans => recon.
                exploit = (http.get("http_method") == "POST") or dport in (8080, 8009)
                cat, w, sig = (("exploitation", 3.0, "net:http_exploit") if exploit
                               else ("recon", 1.0, "net:http_request"))
                yield ts, sig, cat, w, dst, {"src": rec.get("src_ip"),
                                             "url": http.get("url"), "method": http.get("http_method")}
            elif etype == "flow":
                fl = rec.get("flow", {}) or {}
                bts = int(fl.get("bytes_toserver", 0) or 0)
                btc = int(fl.get("bytes_toclient", 0) or 0)
                # Bulk transfer = possible exfiltration; attribute to the source.
                if max(bts, btc) >= 50_000:
                    yield ts, "net:bulk_transfer", "exfiltration", 5.0, rec.get("src_ip"), {
                        "dst": dst, "bytes_toserver": bts, "bytes_toclient": btc,
                    }
            # fileinfo/alert/anomaly/stats are not scored (kept in pcaps/eve for audit).


def parse_sensors(episode_dir: str) -> list[SecurityEvent]:
    """Combined, time-ordered SecurityEvent stream from an episode's sensors/."""
    import os

    sdir = os.path.join(episode_dir, "sensors")
    raw = list(_raw_falco(os.path.join(sdir, "falco.json")))
    raw += list(_raw_suricata(os.path.join(sdir, "suricata_eve.json")))
    raw.sort(key=lambda r: r[0])
    if not raw:
        return []
    start = raw[0][0]
    events: list[SecurityEvent] = []
    for index, (ts, signal, category, weight, host, detail) in enumerate(raw):
        events.append(SecurityEvent(
            index=index, timestamp=ts, t=(ts - start).total_seconds(),
            signal=signal, category=category, weight=weight,
            host=host, detail=detail,
        ))
    return events
