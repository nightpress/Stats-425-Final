#!/usr/bin/env bash
# Scale the LLM attacker arm of the captured library across models (resumable).
# Each arm reuses capture_sweep.sh with SCRIPTED=0/BENIGN=0 and an LLM model;
# capture_sweep.sh skips any episode that already has actions.json, so a dropped
# SSH connection (or a re-run) is safe. Run on the VM:
#   nohup bash scripts/scale_llm.sh > research/out/scale_llm.log 2>&1 &
#
# Arms are a bash array iterated with a for-loop - NOT piped into `while read`:
# a piped loop has its stdin drained by docker/python inside capture_sweep.sh,
# which silently skipped every arm after the first. `</dev/null` on the inner
# call is a second guard so nothing can steal the arm list.
set -uo pipefail
cd "$(dirname "$0")/.."

ARMS=(
  "claude-haiku-5-5 haiku 20"
  "claude-sonnet-5-5 sonnet 12"
  "claude-opus-5-5 opus 12"
)

rm -f research/out/caplib/SCALE_DONE
for arm in "${ARMS[@]}"; do
  # shellcheck disable=SC2086  # intentional split into model/key/count
  set -- $arm
  echo "===== ARM: model=$1 key=$2 target=$3 ====="
  LLM_MODEL="$1" LLM_KEY="$2" LLM="$3" SCRIPTED=0 BENIGN=0 \
    bash scripts/capture_sweep.sh </dev/null
done
touch research/out/caplib/SCALE_DONE
echo "===== SCALE COMPLETE: $(ls -d research/out/caplib/llm-*/ 2>/dev/null | wc -l) llm episode dirs ====="
