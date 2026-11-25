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

## Environments / external validity (resolved scope, 2026-11-25)

The repo's `Environment` enum (`config/attacker_config.py`) names seven values,
but only ONE is actually runnable here:

- `equifax_small`/`equifax_medium`/`equifax_large` differ ONLY in the
  attacker's initial belief model (`environment_initializer.py` gives all
  three the identical subnet list) - there is no infrastructure difference.
  They are not distinct topologies.
- `ics`/`ring`/`enterprise_a`/`enterprise_b` require a MulVAL-based scripted
  attacker (`mulval_optimal.py`) that loads precomputed attack graphs and
  environment specs from `/home/cyberautonomy/v3_MHBench/...` - an external
  benchmark dataset that does not exist in this repository and was never
  shipped with it. No docker-compose topology for them exists either.

We will NOT fabricate the missing MHBench data, and will NOT extend the
scripted attacker's exploit/pivot logic to a second, authored topology (both
are out of scope for this project - see `THREAT_MODEL.md`). **Every result in
this study generalizes within ONE vulnerability class and ONE topology
(Equifax / Struts CVE-2017-5638 / `equifax_large`) only.** This is reported as
a hard external-validity limitation, not downplayed - see below.

## Status
- ✅ Offline (replay) defender, harness, cost accounting, real benign driver.
- ✅ Two independent sensors (Falco + Suricata) captured over a 95-episode
  library spanning scripted/LLM(haiku/sonnet/opus, 5.5 + 4.5-4.8 generations)/
  benign attackers; host-EDR reweighting fixes a volume-domination FPR=1.0
  failure mode (FPR→0.014, 0 for threshold≥10) - see git history.
- ✅ E1/E1b/E2: autonomy-graded detectability; refusal is a 5.5-generation
  safety-training shift (not capability) AND robust to goal reframing.
- ✅ Baseline comparison (`research/baselines.py`): naive-volume and two
  Suricata-signature baselines, all ~3x worse than our detector at matched FPR.
- ✅ Benign-realism ablation: FPR across three tempo/intensity profiles
  (light/steady/heavy), not just one fixed benign behavior.
- ✅ E4a tempo-robustness ablation (`scripts/tempo_sweep.sh`): detection vs.
  attack pacing, varying ONLY the existing step-delay knob
  (`incalmo/incalmo_runner.py` `STEP_DELAY_S`) - no new attacker technique.
- ✅ E4b closed-loop ablation (`research/live_defender.py`): a REAL (not
  counterfactual) intervention - tails the live Falco journal, scores with
  the identical orchestrator, and actually terminates agents via the C2's
  existing `/agent/delete/<paw>` on detection. Falco-only, global-scope (see
  module docstring for why); validated live (dry-run then real) against a
  scripted episode.
- ▢ NOT built (see Environments above): a second vulnerability class/topology.

## Honest limitations to state in any submission
Emulated range (not a production network); `actions.json`-as-labels assumes
the attacker's self-report is correct ground truth; **single vulnerability
class / single topology** (see Environments above - the main external-validity
gap); the closed-loop ablation is Falco-only and global-scope, not a live
replica of the full two-sensor per-host replay result; no sensor-aware
adaptive adversary (the attacker in every experiment is sensor-oblivious -
see THREAT_MODEL.md "Explicit non-goals"); Claude-only model coverage (no
cross-vendor arm - within-Claude generation/capability gradient only).
