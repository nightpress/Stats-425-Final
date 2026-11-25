#!/usr/bin/env bash
# Rep sweep across both MHBench-lite topologies (docker/mhbench/README.md),
# driving scripts/mhbench_episode.sh with the ATTACKER_IP/CAPTURE_NETWORKS
# fix for each topology, and a clean compose down+up before EVERY episode
# (the "Validated" section's gotcha #2 - a stale implant from any prior
# attempt silently blocks the next scp). Resumable: skips any episode whose
# dir already has actions.json.
#
#   nohup bash scripts/mhbench_sweep.sh > research/out/mhbench_sweep.log 2>&1 &
#
# Models: haiku n=8 (statistical power on its bimodal engage/refuse
# behavior, matching the main study's scripted-equifax replicate count);
# sonnet/opus n=3 each (cheap - refusals are fast - to test whether the
# 5.5-generation refusal finding replicates across these two NEW
# environments, not just equifax_large).
set -uo pipefail
cd "$(dirname "$0")/.."

LIB=research/out/caplib
PER_EP_TIMEOUT=${PER_EP_TIMEOUT:-900}

# topology       compose_file                                            env_name                  capture_net                     attacker_ip
TOPOLOGIES=(
  "sudobaron-test docker/mhbench/sudobaron_test/docker-compose.yml mhbench_sudobaron_test sudobaron_test_target_subnet 192.168.210.100"
  "chain2hosts    docker/mhbench/chain_2hosts/docker-compose.yml   mhbench_chain_2hosts   chain_2hosts_ring_subnet     192.168.211.100"
)
# model               key     reps
MODELS=(
  "claude-haiku-5-5  haiku  8"
  "claude-sonnet-5-5 sonnet 3"
  "claude-opus-5-5   opus   3"
)

rm -f "$LIB/MHBENCH_SWEEP_DONE"
for topo in "${TOPOLOGIES[@]}"; do
  # shellcheck disable=SC2086
  set -- $topo
  TKEY="$1"; COMPOSE="$2"; ENV_NAME="$3"; CAPNET="$4"; AIP="$5"

  for model in "${MODELS[@]}"; do
    # shellcheck disable=SC2086
    set -- $model
    LLM_MODEL="$1"; MKEY="$2"; REPS="$3"

    for i in $(seq 0 $((REPS - 1))); do
      EP="$LIB/mhbench-${TKEY}-${MKEY}__rep$(printf %03d "$i")"
      if [ -f "$EP/actions.json" ]; then
        echo "[skip] $EP"
        continue
      fi
      rm -rf "$EP" "$EP.caplog"
      echo "===== $EP (topo=$TKEY model=$LLM_MODEL) ====="
      echo "--- clean restart of $TKEY ---"
      docker compose -f "$COMPOSE" down >/dev/null 2>&1 || true
      docker compose -f "$COMPOSE" up -d >/dev/null 2>&1
      sleep 5

      STRATEGY=llm EP="$EP" ENV_NAME="$ENV_NAME" COMPOSE_FILE="$COMPOSE" \
        CAPTURE_NETWORKS="$CAPNET" ATTACKER_IP="$AIP" LLM_MODEL="$LLM_MODEL" \
        PER_EP_TIMEOUT="$PER_EP_TIMEOUT" \
        bash scripts/mhbench_episode.sh
    done
  done
done

touch "$LIB/MHBENCH_SWEEP_DONE"
echo "===== MHBENCH SWEEP COMPLETE: $(ls -d $LIB/mhbench-*/ 2>/dev/null | wc -l) mhbench episode dirs ====="
