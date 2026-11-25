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

### 1. Independent sensor telemetry  — ✅ DONE
Defender consumes Falco + Suricata, not the attacker's self-report.
- `scripts/sensor_setup.sh` / `scripts/capture_episode.sh`: real schemas, not
  assumed ones (`incalmo/defense/sensors.py` parses the ACTUAL eve.json/Falco
  JSON this range produces).
- `actions.json` is used ONLY as ground-truth labels, never fed to the
  defender (`research/extract_metrics.py`).
- Host-EDR reweighting (`research/grid.py::SENSOR_WEIGHTS`) was REQUIRED: raw
  volume scoring is dominated by benign traffic (benign out-generates every
  attack class) → FPR=1.0 pre-fix; the host-EDR behaviors that actually
  separate the classes (untrusted-shell exec, stdout→network, drop-and-
  execute) bring FPR to 0.014 (0 for threshold≥10). Quantified against
  baselines in `research/baselines.py` (ours ~3x the detection rate of the
  best baseline at matched zero FPR).

### 2. Attacker spectrum (autonomy axis)  — ✅ DONE (within Claude)
Scripted (`EquifaxStrategy`, deterministic, $0, always completes the chain)
vs. LLM across the Claude family: Haiku 4.5/5.5 comply (exfil 0-192, bimodal);
Sonnet/Opus **4.5-4.8** comply; Sonnet/Opus **5.5** refuse 100% at step 0
(API `finish_reason=refusal`), and that refusal is robust to goal reframing
(authorized-explicit / access-only / benign-admin — `framings.json`,
`research/refusal_probe.py`). This is a **5.5-generation safety-training
shift**, not a capability gradient (opus-4-8 is highly capable and still
complies). **We did not bypass model safety** to get full-chain LLM data —
scripted supplies it. NOT done: GPT/Gemini/DeepSeek (Claude-credits-only
constraint for this project; the registry supports them for future work).

### 3. Adaptive adversary  — ✅ DONE, scoped to existing parameters
Per an explicit project constraint, we vary only parameters/strategies
already in the repo rather than author new evasion technique/content:
**attack-tempo** (`incalmo/incalmo_runner.py` `STEP_DELAY_S`, the existing
inter-step delay, now overridable - `scripts/tempo_sweep.sh`) tests whether
detection holds as the identical attack is spread across more wall-clock
time relative to the sliding window. NOT built: a sensor-aware attacker that
is given the defender's weights and optimized to evade them specifically
(see `THREAT_MODEL.md` "Explicit non-goals") - that is a materially larger,
separately-scoped research question we did not take on here.

### 4. Scale + rigor + released benchmark
- Scale: single topology (see Environments below) × attacker spectrum
  (scripted, Haiku 4.5/5.5, Sonnet/Opus 4.5-5.5, 3 goal framings, 3 tempos)
  × 3 benign tempo/intensity profiles × reps → 95+ episodes, 70-config
  defender grid, 4340-6650+ scored rows depending on library size.
- Rigor: bootstrap CIs on every rate, Kaplan-Meier + log-rank for
  time-to-containment, logistic GLMs (detection/prevention ~ autonomy +
  window + threshold + scope), refused-vs-engaged split so refusal and
  detectability are never conflated (`research/analyze.py`).
- Artifact: captured sensor telemetry + attacker suite + defender + baselines
  + ablations, all driven by committed, resumable scripts (`README.md`
  section 3) - reproducible from a clean VM.

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
