# Threat model

Precise statement of attacker/defender capabilities, visibility, and trust
boundaries, as the study actually implements them. Every claim below is a
property of the committed code (`incalmo/`, `research/`, `scripts/`), not an
assumption layered on top of it — file references are given so each line is
checkable against the implementation.

## Environment

- A single, self-contained, air-gapped Docker range (`docker/docker-compose.yml`):
  an attacker/C2 container, a Tomcat webserver vulnerable to the Struts
  CVE-2017-5638 RCE, and a database host reachable only via a lateral hop
  from the webserver. Three isolated bridge networks
  (`192.168.{199,200,201}.0/24`); no connectivity beyond the host VM.
- "Critical data" is a synthetic placeholder file (`data.json`) on the DB
  host. No real system, real credentials, or real person's data exists in
  the range at any point (see `README.md` security note).

## Attacker

**Goal.** Obtain a foothold, escalate to the webserver via the known CVE,
pivot to the DB host, and exfiltrate the placeholder data — the standard
Equifax-breach kill chain the range models.

**Capabilities.** Two attacker classes, both scoped to the SDK of
`incalmo/core/actions/HighLevel/` (scan, find-information, lateral-move,
privilege-escalation, exfiltrate-data — no attacker action outside this
fixed action set exists):

1. **Scripted** (`EquifaxStrategy`, deterministic, $0): a fixed state machine
   that always completes the full chain. No safety guardrail applies (no
   model in the loop), so this class supplies ground-truth completed-attack
   telemetry the LLM attackers often can't.
2. **LLM-driven** (`incalmo/core/strategies/llm/`): a Claude model, prompted
   as an authorized white-hat pentester (or a goal-framing variant — see
   `incalmo/.../preprompts/incalmo/framings.json`), planning and issuing
   actions through the same fixed SDK, one query/action per turn
   (`langchain_interface.py`). It may refuse outright (an API
   `finish_reason=refusal`, logged and treated as a safety-axis outcome, not
   a defender miss — see `research/analyze.py::refused`/`attacker_engaged`).

**What the attacker does NOT have.** No access to the defender's
configuration, scoring weights, or detection state (one-way information flow:
attacker events -> sensors -> defender, never the reverse). No ability to
disable sensors, tamper with telemetry, or address the defender process
directly. No action outside the fixed HighLevel SDK (e.g. no arbitrary raw
shell against the sensors/C2 themselves). The attacker in this study is
**sensor-oblivious**: it is not told what the defender scores or weighs, and
no experiment in this repo gives it that information or optimizes against it
(see Limitations).

## Defender

**Visibility.** Two INDEPENDENT sensors, never the attacker's own log:

- **Falco** (host-wide eBPF): process/syscall events on every container,
  regardless of which network interface traffic uses.
- **Suricata** (network): per-episode offline pass over tcpdump captures of
  each docker bridge (`scripts/capture_episode.sh`) — flow/HTTP/SSH metadata,
  not signature alerts (Suricata's live daemon watches the VM's public
  interface, not the bridges, and offline per-pcap signature matching proved
  non-discriminating here — see `research/baselines.py`).

The attacker's own `actions.json` is used ONLY as ground truth for scoring
(exfil timing, kill-chain stage reached) — never fed to the defender
(`research/extract_metrics.py::defender_events = sensor_events if ... else
attacker_events`, with `defender_input` recorded per episode for audit).

**Mechanism.** A sliding-window weighted-score orchestrator
(`incalmo/defense/orchestrator.py`): each sensor event adds its configured
weight to a window-scoped running total; crossing the threshold fires one
detection and a simulated remediation (isolate / rotate credentials /
terminate). Weights are fixed FOR THE DURATION OF AN EPISODE — the main
study's defender is a **static offline policy**, not one that adapts within
an episode (the live ablation, `research/live_defender.py`, intervenes for
real but still runs the same static per-episode weights).

**What the defender does NOT have.** No knowledge of which attacker class or
model is running. No ability to query the attacker's internal state or
intent. No access to the ground-truth action log during scoring (replay
mode) or at all (live mode).

## Trust boundary

```
 ATTACKER (fixed action SDK)            DEFENDER (fixed-weight scorer)
        |                                        ^
        v  (acts on the range)                   |  (reads sensors only)
   [ Docker range: webserver, db, network ] ---> [ Falco + Suricata ]
        |
        v  (own log, ground truth ONLY - never scored)
   [ actions.json ]  ---------- used for labels, not detection -----
```

The one-way arrow into the defender is the paper's central validity claim:
detection numbers come from telemetry an attacker does not control the
defender's view of, not from privileged access to the attacker's log.

## Explicit non-goals / scope limits

- **Not evaluated here: an attacker that targets the defender.** No
  experiment denies, floods, or spoofs the sensors; no attacker strategy in
  this repo is given the defender's weights to evade. (See
  `PAPER_PLAN.md`/the adaptive-adversary section for exactly what IS varied —
  existing attacker strategies/parameters, not new evasion engineering — and
  why a sensor-aware evasive attacker is out of scope for this study.)
- **Not evaluated here: multiple simultaneous attackers**, or an attacker
  that persists across episodes (`StateStore.initialize()` resets range state
  at the start of every episode).
- **Single vulnerability class.** Every episode is the same Struts RCE on
  the same topology (`equifax_large`); no second CVE or environment ships in
  this repo (see `PAPER_PLAN.md` environments note).
- **The live ablation is Falco-only, global-scope** (see
  `research/live_defender.py` module docstring for why) — it demonstrates a
  real intervention exists and works, not a live replica of the full
  two-sensor, per-host replay result.
