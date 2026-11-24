#!/usr/bin/env bash
# Scale the LLM attacker arm of the captured library across models (resumable).
# Each arm reuses capture_sweep.sh with SCRIPTED=0/BENIGN=0 and an LLM model;
# capture_sweep.sh skips any episode that already has actions.json, so a dropped
# SSH connection is safe to resume from. Run on the VM:
#   nohup bash scripts/scale_llm.sh > research/out/scale_llm.log 2>&1 &
# Override arms with ARMS="model key count; model key count".
set -uo pipefail
cd "$(dirname "$0")/.."
DEFAULT_ARMS="claude-haiku-5-5 haiku 20
claude-sonnet-5-5 sonnet 12
claude-opus-5-5 opus 12"
rm -f research/out/caplib/SCALE_DONE
printf '%s\n' "${ARMS:-$DEFAULT_ARMS}" | while read -r model key count; do
  [ -n "${model:-}" ] || continue
  echo "===== ARM: model=$model key=$key target=$count ====="
  LLM_MODEL="$model" LLM_KEY="$key" LLM="$count" SCRIPTED=0 BENIGN=0 \
    bash scripts/capture_sweep.sh
done
touch research/out/caplib/SCALE_DONE
echo "===== SCALE COMPLETE: $(ls -d research/out/caplib/llm-*/ 2>/dev/null | wc -l) llm episode dirs ====="
