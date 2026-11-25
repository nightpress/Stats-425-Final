#!/usr/bin/env bash
# Run ONE episode against an MHBench-lite topology (docker/mhbench/README.md),
# wrapped in capture_episode.sh for Falco/Suricata telemetry exactly like the
# main range. The topology's own docker-compose.yml must already be up
# (`docker compose -f $COMPOSE_FILE up -d --build`).
#
# Usage:
#   STRATEGY=llm EP=research/out/caplib/<id> ENV_NAME=mhbench_sudobaron_test \
#     COMPOSE_FILE=docker/mhbench/sudobaron_test/docker-compose.yml \
#     CAPTURE_NETWORKS=sudobaron_test_target_subnet \
#     ATTACKER_IP=192.168.210.100 \
#     bash scripts/mhbench_episode.sh
# Env: LLM_MODEL (if STRATEGY=llm, default claude-haiku-5-5), PER_EP_TIMEOUT
#      (default 900). ATTACKER_IP is REQUIRED: a planted implant on a
#      pivoted host beacons back to agent_c2c_server (C2C_SERVER_AGENTS env -
#      see incalmo/core/services/config_service.py), which otherwise falls
#      back to config.json's c2c_server (http://localhost:8888 - wrong from a
#      target host's own perspective, so the implant never registers and
#      SSHLateralMove/NCLateralMove silently produce zero events, exactly as
#      a one-shared-bridge topology's main compose file's attacker IP is).
set -uo pipefail
cd "$(dirname "$0")/.."

STRATEGY=${STRATEGY:-llm}
EP=${EP:?set EP=research/out/caplib/<episode_id>}
ENV_NAME=${ENV_NAME:?set ENV_NAME=mhbench_<topology> (an Environment enum value)}
COMPOSE_FILE=${COMPOSE_FILE:?set COMPOSE_FILE=docker/mhbench/<topology>/docker-compose.yml}
CAPTURE_NETWORKS=${CAPTURE_NETWORKS:?set CAPTURE_NETWORKS="<bridge-network-names>"}
ATTACKER_IP=${ATTACKER_IP:?set ATTACKER_IP=<attacker's IP on this topology's bridge>}
PER_EP_TIMEOUT=${PER_EP_TIMEOUT:-900}
LLM_MODEL=${LLM_MODEL:-claude-haiku-5-5}
export CAPTURE_NETWORKS

rm -rf "$EP"; mkdir -p "$EP"

python3 - "$STRATEGY" "$ENV_NAME" "$LLM_MODEL" <<'PY'
import json, sys
strategy, env_name, model = sys.argv[1], sys.argv[2], sys.argv[3]
base = json.load(open("config/config.json"))
base["environment"] = env_name
if strategy == "llm":
    base["strategy"] = {"planning_llm": model, "execution_llm": model, "abstraction": "incalmo"}
    base["name"] = "mhbench_llm"
else:
    base["strategy"] = {"name": strategy}
    base["name"] = "mhbench_scripted"
json.dump(base, open("config/config.json", "w"), indent=2)
PY

cp config/config.json config/config.json.mhbbak 2>/dev/null || true
trap 'mv config/config.json.mhbbak config/config.json 2>/dev/null || true' EXIT

echo "=== running $ENV_NAME ($STRATEGY) against $COMPOSE_FILE ==="
bash scripts/capture_episode.sh "$EP" timeout "$PER_EP_TIMEOUT" \
  docker compose -f "$COMPOSE_FILE" exec -T -e "INCALMO_OUTPUT_DIR=/incalmo/$EP" \
  -e "C2C_SERVER_AGENTS=http://${ATTACKER_IP}:8888" \
  attacker bash -lc "cd /incalmo && uv run python main.py" \
  > "$EP.caplog" 2>&1 || echo "[warn] capture returned non-zero"

echo "=== RESULT ==="
echo "actions.json bytes: $(wc -c < "$EP/actions.json" 2>/dev/null || echo 0)"
echo "exfil: $(grep -o ExfiltratedData "$EP/actions.json" 2>/dev/null | wc -l)"
echo "suricata events: $(wc -l < "$EP/sensors/suricata_eve.json" 2>/dev/null || echo 0)"
echo "falco events: $(wc -l < "$EP/sensors/falco.json" 2>/dev/null || echo 0)"
