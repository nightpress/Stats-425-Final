#!/usr/bin/env bash
# Benign-realism sweep: capture episodes under the light/heavy tempo profiles
# (the default "steady" profile already has 10 episodes from the main sweep).
# Answers "does FPR=0 hold across different benign intensities, not just the
# one profile most of the library used?" Resumable (benign-<key> episode ids
# don't collide with the plain "benign__..." steady episodes).
#   nohup bash scripts/benign_profile_sweep.sh > research/out/benign_profile_sweep.log 2>&1 &
set -uo pipefail
cd "$(dirname "$0")/.."

# profile  key    reps
ARMS=(
  "light    light  5"
  "heavy    heavy  5"
)

rm -f research/out/caplib/BENIGN_PROFILE_DONE
for arm in "${ARMS[@]}"; do
  # shellcheck disable=SC2086
  set -- $arm
  echo "===== BENIGN PROFILE profile=$1 key=$2 reps=$3 ====="
  BENIGN_PROFILE="$1" BENIGN_KEY="$2" BENIGN="$3" SCRIPTED=0 LLM=0 \
    bash scripts/capture_sweep.sh </dev/null
done
touch research/out/caplib/BENIGN_PROFILE_DONE
echo "===== BENIGN PROFILE SWEEP COMPLETE: $(ls -d research/out/caplib/benign-*/ 2>/dev/null | wc -l) profiled benign dirs ====="
