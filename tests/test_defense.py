"""Tests for the replay defender, verified against the shipped example episode.

Pure-stdlib and runnable two ways:  ``pytest tests/test_defense.py``  or
``python3 tests/test_defense.py`` (prints a summary, exits non-zero on failure).
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta

from incalmo.defense import (
    DefenseConfig,
    DefenseOrchestrator,
    NetworkState,
    SecurityEvent,
    evaluate_episode,
    parse_action_log,
)

EXAMPLE_LOG = os.path.join(
    os.path.dirname(__file__), "..", "output", "example_output", "action_log.jsonl"
)


def _event(t: float, signal: str, host: str | None, weight: float, category: str = "x") -> SecurityEvent:
    base = datetime(2025, 1, 1)
    return SecurityEvent(
        index=int(t), timestamp=base + timedelta(seconds=t), t=t,
        signal=signal, category=category, weight=weight, host=host,
    )


def test_parse_example_log():
    events = parse_action_log(EXAMPLE_LOG)
    assert len(events) > 100, "expected a rich event stream from the example"
    assert all(a.t <= b.t for a, b in zip(events, events[1:])), "events must be time-ordered"
    assert events[0].t == 0.0
    assert any(e.is_exfil for e in events), "example is a successful exfiltration attack"
    assert any(e.host for e in events), "at least some events carry a host"


def test_orchestrator_detects_on_first_crossing():
    # Weight-5 events in a 60s window: score reaches threshold 10 at the SECOND
    # event (t=10). Detection must fire then, exactly once (cooldown=0).
    cfg = DefenseConfig(window_seconds=60, threshold=10, scope="global",
                        enable_credential_rotation=False)
    orch = DefenseOrchestrator(cfg)
    orch.run([
        _event(0, "InfectedNewHost", "h1", 5),
        _event(10, "InfectedNewHost", "h1", 5),
        _event(20, "InfectedNewHost", "h1", 5),
    ])
    assert len(orch.detections) == 1, "fires once on first crossing"
    assert orch.detections[0].time == 10, "first crossing is at the second event"
    assert orch.network.is_contained("h1", 10)


def test_window_expiry_prevents_detection():
    # Same three events spread beyond the 15s window never co-occur -> no crossing.
    cfg = DefenseConfig(window_seconds=15, threshold=10, scope="global")
    orch = DefenseOrchestrator(cfg)
    orch.run([
        _event(0, "InfectedNewHost", "h1", 5),
        _event(30, "InfectedNewHost", "h1", 5),
        _event(60, "InfectedNewHost", "h1", 5),
    ])
    assert orch.detections == []


def test_per_host_scope_isolates_only_implicated_host():
    cfg = DefenseConfig(window_seconds=120, threshold=10, scope="host")
    orch = DefenseOrchestrator(cfg)
    orch.run([
        _event(0, "InfectedNewHost", "h1", 5),
        _event(5, "InfectedNewHost", "h1", 5),  # h1 crosses
        _event(6, "InfectedNewHost", "h2", 5),  # h2 alone does not
    ])
    assert orch.network.is_contained("h1", 10)
    assert not orch.network.is_contained("h2", 10)


def test_evaluate_example_aggressive_vs_lax():
    events = parse_action_log(EXAMPLE_LOG)
    aggressive = evaluate_episode(events, DefenseConfig(window_seconds=120, threshold=5, scope="global"))
    assert aggressive.detected
    assert aggressive.attack_reached_exfil
    # An unreachable threshold must never detect.
    lax = evaluate_episode(events, DefenseConfig(window_seconds=120, threshold=1e9, scope="global"))
    assert not lax.detected
    assert lax.n_exfil_prevented == 0
    assert lax.n_exfil_realized == lax.n_exfil_total


def test_prevention_counts_only_strictly_later_exfil():
    # Exfil at t=0 triggers detection; a second exfil at t=100 is prevented.
    cfg = DefenseConfig(window_seconds=200, threshold=6, scope="global",
                        remediation_latency_seconds=0)
    events = [_event(0, "ExfiltratedData", "h1", 6, "exfiltration"),
              _event(100, "ExfiltratedData", "h1", 6, "exfiltration")]
    m = evaluate_episode(events, cfg)
    assert m.n_exfil_total == 2
    assert m.n_exfil_realized == 1 and m.n_exfil_prevented == 1


def test_benign_detection_is_false_positive():
    cfg = DefenseConfig(window_seconds=120, threshold=5, scope="global")
    events = [_event(0, "InfectedNewHost", "h1", 5), _event(1, "InfectedNewHost", "h1", 5)]
    m = evaluate_episode(events, cfg, is_benign=True)
    assert m.detected and m.false_positive and m.n_false_positive_detections == m.n_detections


def test_networkstate_global_contains_all():
    ns = NetworkState()
    ns.isolate_host(None, 50.0)  # global containment
    assert ns.is_contained("anything", 50.0)
    assert not ns.is_contained("anything", 49.0)


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except Exception as exc:  # noqa: BLE001 - test harness surface
            failed += 1
            print(f"FAIL {t.__name__}: {exc!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return failed


if __name__ == "__main__":
    import sys
    sys.exit(1 if _run_all() else 0)
