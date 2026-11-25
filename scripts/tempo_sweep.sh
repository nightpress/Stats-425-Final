#!/usr/bin/env bash
# Attack-tempo robustness ablation (E4: "adaptive adversary" scoped to an
# existing, strategy-agnostic parameter - see incalmo/incalmo_runner.py
# STEP_DELAY_S). Runs the deterministic scripted attacker (EquifaxStrategy,
# $0, identical action sequence every time) at several step-delay values, to
# test whether the sliding-window detector's detection rate holds as the SAME
# attack is spread across more wall-clock time relative to the window - the
# complementary axis to the main study's own WINDOW_SECONDS grid. This
# changes ONLY the pacing of an already-decided action sequence; it adds no
# new attacker technique or evasion logic. Resumable.
#   nohup bash scripts/tempo_sweep.sh > research/out/tempo_sweep.log 2>&1 &
set -uo pipefail
cd "$(dirname "$0")/.."

# step_delay_s  key     reps
# (0.5s = the default tempo, already covered by the 8 existing
# scripted-equifax episodes - no need to recapture it here.)
ARMS=(
  "10     medium  3"
  "30     slow    3"
)

rm -f research/out/caplib/TEMPO_DONE
for arm in "${ARMS[@]}"; do
  # shellcheck disable=SC2086
  set -- $arm
  echo "===== TEMPO step_delay=${1}s key=$2 reps=$3 ====="
  STEP_DELAY_S="$1" TEMPO_KEY="$2" SCRIPTED="$3" LLM=0 BENIGN=0 \
    bash scripts/capture_sweep.sh </dev/null
done
touch research/out/caplib/TEMPO_DONE
echo "===== TEMPO SWEEP COMPLETE ====="
