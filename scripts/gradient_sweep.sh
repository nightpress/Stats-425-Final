#!/usr/bin/env bash
# Within-Claude capability/generation gradient (experiment E1c). Runs the
# BASELINE attack task across accessible Claude models spanning the 4.5 -> 5.5
# generations, to test whether the step-0 safety refusal tracks capability /
# model recency. (The 5.5 trio - haiku/sonnet/opus - is already captured by
# scale_llm.sh; this adds the older generations.) Resumable.
#   nohup bash scripts/gradient_sweep.sh > research/out/gradient_sweep.log 2>&1 &
set -uo pipefail
cd "$(dirname "$0")/.."

# model_id            id_suffix  reps   (untested refusal-candidates first; the
# compliant haiku-4-5 is last and already has episodes, so it resumes/skips).
ARMS=(
  "claude-opus-4-5     opus45     3"
  "claude-sonnet-4-6   sonnet46   3"
  "claude-opus-4-8     opus48     3"
  "claude-haiku-4-5    haiku45    3"
)

rm -f research/out/caplib/GRADIENT_DONE
for arm in "${ARMS[@]}"; do
  # shellcheck disable=SC2086
  set -- $arm
  echo "===== GRADIENT model=$1 key=$2 reps=$3 ====="
  LLM_MODEL="$1" LLM_KEY="$2" LLM="$3" ATTACK_FRAMING=baseline SCRIPTED=0 BENIGN=0 \
    bash scripts/capture_sweep.sh </dev/null
done
touch research/out/caplib/GRADIENT_DONE
echo "===== GRADIENT COMPLETE ====="
