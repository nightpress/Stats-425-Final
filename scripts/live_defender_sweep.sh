#!/usr/bin/env bash
# Replicate the closed-loop (live) defender ablation N times (experiment item
# #4). The first validation (dry-run then real, see docker/mhbench/README.md
# "Validated") proved the mechanism works and measured ONE real prevention;
# this turns "we demonstrated it once" into "we measured a real prevention
# rate" by running N independent trials of the deterministic scripted
# attacker (EquifaxStrategy, $0, always completes the full chain absent
# intervention) under the SAME live defender.
#
# Restarts webserver/db between reps as a safety margin (a prior rep's
# containment already kills its own implant on success - see
# research/live_defender.py's DELETE /agent/delete/<paw> - but this guards
# against a failed/interrupted rep leaving a stale process, the same class
# of bug the MHBench-lite integration hit - docker/mhbench/README.md
# "Validated" gotcha #2).
#
#   nohup bash scripts/live_defender_sweep.sh > research/out/live_defender_sweep.log 2>&1 &
# Env: REPS (default 5), WINDOW/THRESHOLD (default 120/65, the Falco-only
#      calibration), PER_EP_TIMEOUT (default 900).
set -uo pipefail
cd "$(dirname "$0")/.."

REPS=${REPS:-5}
WINDOW=${WINDOW:-120}; THRESHOLD=${THRESHOLD:-65}; PER_EP_TIMEOUT=${PER_EP_TIMEOUT:-900}
COMPOSE="docker compose -f docker/docker-compose.yml -f docker/docker-compose.run.yml -f docker/docker-compose.dbpivot.yml"
LIB=research/out/caplib

rm -f "$LIB/LIVE_DEFENDER_SWEEP_DONE"
for i in $(seq 0 $((REPS - 1))); do
  # "scripted-equifax-livedefended" matches the established scripted-equifax-<key>
  # convention (tempo_sweep.sh's SCRIPTED_LABEL) so extract_metrics.py's
  # eid.startswith("scripted-") autonomy check classifies it correctly with
  # no new special-casing needed.
  EP="$LIB/scripted-equifax-livedefended__equifax_large__rep$(printf %03d "$i")"
  if [ -f "$EP/actions.json" ]; then
    echo "[skip] $EP"
    continue
  fi
  echo "===== live-defender rep $i: $EP ====="
  echo "--- restarting webserver/db (safety margin) ---"
  $COMPOSE restart webserver db >/dev/null 2>&1 || true
  sleep 5

  STRATEGY=scripted EP="$EP" WINDOW="$WINDOW" THRESHOLD="$THRESHOLD" PER_EP_TIMEOUT="$PER_EP_TIMEOUT" \
    bash scripts/live_defender_episode.sh
done

touch "$LIB/LIVE_DEFENDER_SWEEP_DONE"
echo "===== LIVE DEFENDER SWEEP COMPLETE: $(ls -d $LIB/scripted-equifax-livedefended__*/ 2>/dev/null | wc -l) reps ====="
