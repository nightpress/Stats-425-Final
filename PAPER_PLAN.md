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
  execute) bring FPR to 0 for the `steady`/`light` benign tempo profiles.
  Quantified against baselines in `research/baselines.py`.
- **Benign-realism finding (do not overclaim FPR=0):** an AGGRESSIVE,
  scanner-heavy admin workload (the `heavy` profile — Nikto/Nmap-style deep
  service probing, `incalmo/.../benign_admin.py`) drives FPR to ~0.6 at the
  reported operating point, because its subprocess/socket-piping scan
  pattern trips the SAME two signals that discriminate real attacks
  (`Drop and execute new binary`, `Redirect STDOUT/STDIN to Network`) - a
  genuine behavioral overlap between deep vulnerability scanning and
  exploitation, not a bug. Report FPR as tempo-conditional: ~0 for
  steady/light administrative activity, ~0.6 for an aggressive internal
  scanner workload at this same threshold (`research/analyze.py
  benign_fpr_by_profile`, `research/out/caplib/benign_fpr_by_profile.csv`).

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
- ✅ Two independent sensors (Falco + Suricata) captured over a 107-episode
  library spanning scripted/LLM(haiku/sonnet/opus, 5.5 + 4.5-4.8 generations,
  2 MHBench-lite environments)/benign(3 tempo profiles) attackers; host-EDR
  reweighting fixes a volume-domination FPR=1.0 failure mode - see git history
  and the benign-realism finding below for the honest, tempo-conditional FPR.
- ✅ E1/E1b/E2: autonomy-graded detectability; refusal is a 5.5-generation
  safety-training shift (not capability) AND robust to goal reframing AND
  corroborated across two independent, externally-sourced environments
  (MHBench-lite, n=3 opus + n=3 sonnet per topology): 100% refusal in both,
  matching the main range exactly. Haiku refuses 12% there (n=8 each) vs. 0%
  on the main range - a directional signal only (CI overlaps 0, not yet
  powered). The boundary lands at data-exfiltration intent specifically, not
  at reconnaissance/lateral-movement (`docker/mhbench/README.md`).
- ✅ Cross-environment detection check: at the main study's representative
  cell, engaged-Haiku detection on MHBench-lite looks like a miss (0% vs 80%)
  - but the same discriminating signals are present and strong; detection
  recovers at threshold<=25 (any window) or window=480s (at threshold=50).
  A second, independent line of evidence for the window-vs-attack-tempo
  dynamic E4a was built to measure - a different-environment attack path
  (not an artificially slowed one) needing a wider window, not a coverage
  gap (`docker/mhbench/README.md` "Rep sweep results").
- ✅ Baseline comparison (`research/baselines.py`) at the overall best
  operating point (window=30s, threshold=10, scope=global, now including the
  `heavy` benign profile): host-EDR (ours) detect=0.867 FPR=0.150 (J=0.717)
  vs. suricata_sig_all detect=0.299 FPR=0.250 (J=0.049) vs. naive_volume /
  suricata_sig_exploit, whose grids find no cell worth reporting once `heavy`
  is included (J=0 - the honest "neither detects nor false-alarms" corner).
  Report both the single best-point number AND the full curve
  (`research/out/caplib/figures/detector_comparison.png`) - the single point
  alone understates how much better ours separates attack from benign.
- ✅ Benign-realism ablation (FPR across three tempo/intensity profiles) - a
  REAL finding, not a clean pass: `steady`/`light` admin activity holds
  FPR=0, but the `heavy` (aggressive internal vuln-scanner) profile drives
  FPR to ~0.6 at the same operating point - its Nikto/Nmap-style deep service
  probing trips the SAME two signals that discriminate real attacks
  (subprocess spawn + socket-piped I/O look identical whether the process is
  a scanner or a shell). Report FPR as tempo-conditional, not a single
  number (`research/analyze.py benign_fpr_by_profile`).
- ✅ E4a tempo-robustness ablation (`scripts/tempo_sweep.sh`): detection vs.
  attack pacing, varying ONLY the existing step-delay knob
  (`incalmo/incalmo_runner.py` `STEP_DELAY_S`) - no new attacker technique.
- ✅ E4b closed-loop ablation (`research/live_defender.py`): a REAL (not
  counterfactual) intervention - tails the live Falco journal, scores with
  the identical orchestrator, and actually terminates agents via the C2's
  existing `/agent/delete/<paw>` on detection. Falco-only, global-scope (see
  module docstring for why). Replicated N=5 (`scripts/live_defender_sweep.sh`):
  1 rep dropped (a known restart-race flakiness, "No attacker agent found" -
  see `docker/mhbench/README.md`), and of the 4 valid reps, **0/4 were
  detected/contained live** - the scripted attacker completed its full
  exfiltration chain uninterrupted every time. This is a REAL, sobering
  finding, not a bug: it contrasts with the one earlier ad hoc demonstration
  that did show a successful live containment, and shows the live
  Falco-only/global-scope policy's real-world reliability is lower than the
  main study's offline-replay prevention numbers suggest - replaying a
  detection policy against a pre-recorded trace cannot capture the live
  timing/race effects (journal lag, window-vs-tempo interaction) that a real
  intervention is actually exposed to. Report this as its own number, not
  folded into the main replay-based prevention rate.
- ▢ NOT built (see Environments above): a second vulnerability class/topology.

## Honest limitations to state in any submission
Emulated range (not a production network); `actions.json`-as-labels assumes
the attacker's self-report is correct ground truth; **mostly one vulnerability
class / topology** - the main study is Struts/`equifax_large` only, and the
two MHBench-lite environments (`docker/mhbench/`) are n=1 episode each so
far (a feasibility/corroboration result, not yet a powered one - see
Environments above); the closed-loop ablation is Falco-only and global-scope,
not a live replica of the full two-sensor per-host replay result, and its
measured live prevention rate (0/4 valid reps) is markedly lower than the
offline-replay numbers, underscoring that replay-based prevention estimates
are an upper bound on real-world live detection, not an estimate of it; no
sensor-aware adaptive adversary (the attacker in every experiment is
sensor-oblivious - see THREAT_MODEL.md "Explicit non-goals"); Claude-only
model coverage (no cross-vendor arm - within-Claude generation/capability
gradient only); **the host-EDR detector's FPR=0 is tempo-conditional, not
universal** - it holds for steady/light administrative benign activity but
rises to ~0.6 against an aggressive internal-scanner-style benign workload,
because deep service probing and real exploitation trip the same low-level
subprocess/socket-I/O signals (see the benign-realism finding above).
