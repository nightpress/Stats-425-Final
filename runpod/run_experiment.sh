#!/usr/bin/env bash
# Run the full defense study pipeline INSIDE the attacker container, once the
# Incalmo range is up (see runpod/README.md). Generates the attacker-episode
# library under a hard spend cap, adds synthetic benign episodes, extracts the
# tidy dataset, and (if analysis deps are present) runs the statistical analysis.
#
# Env vars (all optional except ANTHROPIC_API_KEY):
#   ANTHROPIC_API_KEY   required - your Claude API key (the budget)
#   CAP_USD             hard spend cap in USD                 (default 45)
#   COST_PER_EPISODE    pre-run per-episode estimate in USD   (default 0.25)
#   PILOT               extrapolate cost after N episodes     (default 5)
#   LIBRARY             episode-library output dir            (default research/out/library)
#   N_BENIGN            synthetic benign episodes for FPR     (default 10)
#   INVARIANCE_ARM      "1" to add the Sonnet invariance arm  (default unset)
set -euo pipefail

cd "$(dirname "$0")/.."
export PYTHONPATH="${PYTHONPATH:-.}"

: "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY (your Claude API credit funds the run)}"
CAP_USD="${CAP_USD:-45}"
COST_PER_EPISODE="${COST_PER_EPISODE:-0.25}"
PILOT="${PILOT:-5}"
LIBRARY="${LIBRARY:-research/out/library}"
N_BENIGN="${N_BENIGN:-10}"

RUN=(python3 -m research.run_sweep)
ARM_FLAG=()
[ "${INVARIANCE_ARM:-}" = "1" ] && ARM_FLAG=(--invariance-arm)

echo "== Plan (no spend) =="
"${RUN[@]}" plan --cost-per-episode "$COST_PER_EPISODE" --cap "$CAP_USD" "${ARM_FLAG[@]}"

echo; echo "== Generate episode library (hard cap \$$CAP_USD) =="
"${RUN[@]}" generate --library "$LIBRARY" --cap "$CAP_USD" \
  --cost-per-episode "$COST_PER_EPISODE" --pilot "$PILOT" "${ARM_FLAG[@]}"

echo; echo "== Add synthetic benign episodes for FPR (stand-in; see README) =="
"${RUN[@]}" benign --library "$LIBRARY" --n "$N_BENIGN"

echo; echo "== Extract tidy dataset =="
"${RUN[@]}" extract --library "$LIBRARY" --out research/out/rows.csv

echo; echo "== Analyze (skipped if analysis deps missing) =="
if python3 -c "import pandas, numpy, matplotlib, scipy" 2>/dev/null; then
  python3 -m research.analyze research/out/rows.csv --outdir research/out
else
  echo "analysis deps not installed; copy research/out/rows.csv to a machine with"
  echo "  pip install -r research/requirements-analysis.txt   and run research.analyze there."
fi

echo; echo "Done. Dataset: research/out/rows.csv  Figures/summary: research/out/"
