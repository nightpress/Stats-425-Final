# Autonomous defense against an autonomous LLM attacker — a statistical study

This harness turns the Incalmo attacker framework into a **data generator** for a
statistics study. We add a reactive **defender** (`incalmo/defense/`) that
monitors the attacker's telemetry, scores sliding-window threat heuristics, and
triggers simulated remediation; then we characterize, with proper inference, the
tradeoff every automated defender faces: **detect sooner vs. fire on benign
activity.**

## Research question

> As a telemetry-driven defender's sensitivity increases, how does its ability to
> contain an autonomous LLM attack *before data is exfiltrated* trade off against
> its *false-positive rate* on benign activity — and does the Incalmo paper's
> finding that attack success is roughly model-invariant still hold under active
> defense?

## Design

Two independent axes (see `grid.py`):

- **Episode library** (costs Claude API money, generated once). Factors:
  attacker model (`claude-haiku-5-5` bulk; `claude-sonnet-5-5` invariance arm),
  environment, replicate. The attacker runs against the sandboxed Docker range
  only.
- **Defender sweep** (free — replayed offline over the library). Factors:
  sliding-window width, detection threshold, containment scope (`host` vs
  `global`). These trace the operating curve.

Because the defender is evaluated offline, **one expensive corpus of attacker
episodes is scored under all 50 defender configurations for $0** — the entire
operating curve is free. Only the library costs money.

### Response variables (one row per episode × defender config, `extract_metrics.py`)

- `detected`, `time_to_detect`, `time_to_contain`
- `attack_reached_exfil`, `time_to_first_exfil`, `n_exfil_total`
- `detected_before_first_exfil` (the containment "win"), `prevented_fraction`
- `false_positive` (benign episodes only)
- `api_cost_usd`, token counts (per-episode cost accounting)

### Planned analysis (`analyze.py`)

- **Operating curve**: contained-before-exfil rate vs. false-positive rate, per
  scope, with bootstrap 95% CIs.
- **Survival analysis**: Kaplan–Meier of time-to-containment by scope; log-rank
  test. (Time-to-first-exfil is right-censored when the attack never exfiltrates
  within the episode — survival analysis handles this correctly.)
- **GLM**: logistic regression of containment success on window, threshold, scope
  (needs `statsmodels`; KM/log-rank do not).
- **Invariance test**: compare Haiku vs. Sonnet attacker arms. To *claim*
  equivalence, use a TOST equivalence test, not a failed difference test.

## Modeling assumptions (state these in the writeup)

1. **Offline replay**: the defender scores recorded telemetry; it does not feed
   back into the attacker. `time_to_contain` and prevented-exfil counts are
   **counterfactual** under assumption (2). A live closed-loop defender is future
   work.
2. **Containment**: a host contained at time *T* prevents exfiltration attributed
   to it after *T* (global scope contains the whole environment).
3. **Observable telemetry** = the attacker's `action_results` outcomes (a host
   beaconing, a credential surfacing, data leaving) — not its internal planning.
4. **Benign telemetry is synthetic.** This build logs attacker actions only, so a
   genuine false-positive rate needs a benign-workload driver in the range (not
   yet built). `run_sweep.py benign` injects synthetic background-noise episodes
   as an explicit stand-in; treat FPR as provisional until a real benign source
   exists. **This is the most important limitation to disclose.**

## Budget model (target: under $50 of Claude credit)

- Cost driver is the agentic loop re-sending growing context each step; prompt
  caching (cache reads ≈ 0.1×) is the biggest lever.
- Main sweep = Haiku attacker × rule-based (0-token) offline defender → the
  defender sweep is free; only ~20–40 attacker episodes cost money.
- `run_sweep.py` enforces a hard `--cap`; `--pilot N` extrapolates real
  per-episode cost after N runs and aborts if the full run would exceed the cap.
- The Sonnet invariance arm costs ~20× per episode — keep it to a handful and
  pass a higher `--cost-per-episode` (the flat estimate in `plan` does not
  distinguish models; the pilot measures reality).

## How to run

**Offline, free, no API — validate the whole pipeline on synthetic data:**
```bash
PYTHONPATH=. python3 -m research.synthesize research/out/demo_library
PYTHONPATH=. python3 -m research.extract_metrics research/out/demo_library --out research/out/demo_rows.csv
pip install -r research/requirements-analysis.txt   # pandas/numpy/matplotlib/scipy (+ optional statsmodels)
PYTHONPATH=. python3 -m research.analyze research/out/demo_rows.csv --outdir research/out
```

**Real episodes** (needs the Docker range up): see `runpod/README.md`, or locally:
```bash
PYTHONPATH=. python3 -m research.run_sweep plan --cost-per-episode 0.25 --cap 45
PYTHONPATH=. python3 -m research.run_sweep generate --library research/out/library --cap 45 --pilot 5
PYTHONPATH=. python3 -m research.run_sweep benign  --library research/out/library --n 10
PYTHONPATH=. python3 -m research.run_sweep extract --library research/out/library --out research/out/rows.csv
PYTHONPATH=. python3 -m research.analyze research/out/rows.csv --outdir research/out
```

## Layout

```
incalmo/defense/      the defender (pure stdlib, unit-tested): telemetry,
                      config, orchestrator, remediation, evaluate
research/grid.py      the experimental design (edit to resize the study)
research/cost.py      Claude pricing, usage aggregation, hard spend cap
research/extract_metrics.py   episode logs -> tidy CSV
research/run_sweep.py         episode-library generation + offline sweep
research/synthesize.py        synthetic library for offline validation
research/analyze.py           survival / GLM / operating-curve + figures
tests/test_defense.py         verifies the defender against the shipped episode
```
