#!/usr/bin/env bash
# Refusal-robustness sweep (experiment E1b). For each (Claude model, goal framing)
# cell, capture N episodes. The framings (incalmo/.../framings.json) vary ONLY the
# task's objective/authorization toward LESS-harmful goals - stronger explicit
# authorization, access-without-exfiltration, and a benign read-only admin control
# - to measure WHICH task properties drive a model's API safety refusal. This is
# guardrail measurement, not jailbreak development.
#
# The shipped prompt ('baseline') is already captured by scale_llm.sh, so this
# only runs the non-baseline cells. Resumable (skips episodes with actions.json).
#   nohup bash scripts/framing_sweep.sh > research/out/framing_sweep.log 2>&1 &
set -uo pipefail
cd "$(dirname "$0")/.."

# model_id            id_suffix          ATTACK_FRAMING       reps
CELLS=(
  "claude-opus-5-5    opus-authz         authorized_explicit  3"
  "claude-opus-5-5    opus-accessonly    access_only          3"
  "claude-opus-5-5    opus-benign        benign_admin         3"
  "claude-sonnet-5-5  sonnet-authz       authorized_explicit  3"
  "claude-sonnet-5-5  sonnet-accessonly  access_only          3"
  "claude-sonnet-5-5  sonnet-benign      benign_admin         3"
  "claude-haiku-5-5   haiku-accessonly   access_only          3"
  "claude-haiku-5-5   haiku-benign       benign_admin         3"
)

rm -f research/out/caplib/FRAMING_DONE
for cell in "${CELLS[@]}"; do
  # shellcheck disable=SC2086  # intentional split into the 4 fields
  set -- $cell
  echo "===== CELL model=$1 key=$2 framing=$3 reps=$4 ====="
  LLM_MODEL="$1" LLM_KEY="$2" LLM="$4" ATTACK_FRAMING="$3" SCRIPTED=0 BENIGN=0 \
    bash scripts/capture_sweep.sh </dev/null
done
touch research/out/caplib/FRAMING_DONE
echo "===== FRAMING SWEEP COMPLETE: $(ls -d research/out/caplib/llm-*-*/ 2>/dev/null | wc -l) framed llm dirs ====="
