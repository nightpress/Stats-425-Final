# Paper plan: autonomous-attacker detectability & the guardrail boundary

## Thesis (what the whole paper argues)
> The **autonomy** of an LLM attacker changes its **detectability** in a
> characteristic, measurable way, and frontier-model **safety guardrails act as a
> de facto defensive control** that bounds autonomous intrusions at predictable
> kill-chain stages.

This complements Incalmo (arXiv 2501.16466, CMU — *attacker* feasibility) on the
open **defense / detectability** axis rather than competing on their turf.

## Target venues (honest)
- **This semester:** a workshop / short paper / poster (autonomous cyber defense,
  security+ML). Real and submittable from Phases 1–2.
- **Top-tier full paper (USENIX/S&P/CCS/NDSS):** a *shot*, not a lock, and only
  with all four non-negotiables below + statistical rigor + a released benchmark,
  over ~2–3 quarters, **ideally with a security-faculty advisor** (matters for
  threat-model credibility and getting past reviewers). Building the infrastructure
  earns the shot; the *finding* has to emerge from the data and survive review.

## The four non-negotiables (build order)

### 1. Independent sensor telemetry  — FOUNDATION (in progress)
Defender must consume what a real SOC sees, not the attacker's self-report.
- `scripts/sensor_setup.sh`: Suricata (network IDS) + Falco (host EDR, eBPF).
- `scripts/capture_episode.sh`: pcap the range subnets per episode → Suricata
  offline (`eve.json`) + Falco host events sliced to the episode window.
- Keep `actions.json` ONLY as ground-truth labels (attack vs benign, stage times).
- **Next:** capture one real episode → write parsers against ACTUAL Suricata/Falco
  output (not assumed schemas) → re-wire `incalmo/defense` to ingest sensor events.

### 2. Attacker spectrum (autonomy axis)
Scripted/optimal (`MulvalOptimal`, `OptimalReplay`, `BFS/DFS`, `Darkside`) →
low-abstraction LLM → high-abstraction LLM (Incalmo), across models (Claude
Haiku/Sonnet/Opus, + GPT/Gemini/DeepSeek via the registry). Scripted attackers
complete the full chain incl. exfiltration ($0, no LLM); LLM refusals are a
*measured* result (the guardrail boundary), not a bug to engineer around.
**We do not bypass model safety.** Grid expansion in `research/grid.py`.

### 3. Adaptive adversary
"Low-and-slow" stealth knobs on the scripted attackers (inter-action delay,
randomized timing, reduced scan breadth) → does an attacker that knows the
detection window evade it? Sandbox-only, for defender evaluation. We build
scripted stealth; we do **not** build real-world evasion tooling or prompt a model
to defeat its own safeguards.

### 4. Scale + rigor + released benchmark
- Scale: {7 topologies} × {attacker spectrum} × {stealth on/off} × {reps}.
  Scripted = $0; defender sweep is free offline → tens of thousands of rows.
- Rigor: mixed-effects models (topology/attacker as random effects), effect sizes,
  bootstrap CIs, multiple-comparison control (`research/analyze.py` + statsmodels).
- Artifact: environments + captured sensor telemetry + attacker suite + defender,
  packaged reproducibly. A benchmark others adopt is the high-citation contribution.

## Experiments that produce the finding
- **E1 Detectability vs. autonomy:** detection rate / latency on *sensor* telemetry
  as a function of attacker autonomy, across topologies. (Is autonomy louder or
  stealthier?)
- **E2 Guardrail boundary:** per model, the kill-chain stage at which the LLM
  attacker refuses, across topologies. (Novel; safety-relevant.)
- **E3 Operating curve + adaptive adversary:** detection vs. false-positive on real
  benign telemetry, and how stealth shifts it.
- **E4 Closed-loop prevention:** a live defender that quarantines a flagged agent
  via the C2 mid-episode → *actual* (not counterfactual) attack disruption.

## Status
- ✅ Offline defender, harness, cost accounting, real benign driver, dry run on DO.
- ✅ Phase-1 capture scripts written (sensor_setup, capture_episode).
- ⏳ Preliminary LLM-attacker + benign sweep running on the DO range.
- ▢ Deploy sensors → capture real telemetry → parsers → re-wire defender (next).
- ▢ Attacker spectrum, stealth, scale, closed-loop, benchmark, stats.

## Honest limitations to state in any submission
Emulated range (not a production network); `actions.json`-as-labels assumes the
attacker's self-report is correct ground truth; LLM attacks are safety-bounded
(a finding, but it means LLM-driven full-chain data comes from scripted attackers,
not the models); closed-loop prevention depends on the C2 control point.
