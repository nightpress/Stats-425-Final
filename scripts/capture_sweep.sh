#!/usr/bin/env bash
# Generate the captured episode library on the live range: scripted full-chain
# (EquifaxStrategy), LLM (claude-haiku-5-5), and benign (BenignAdmin) episodes,
# each wrapped in capture_episode.sh so every episode has its own Suricata +
# Falco telemetry alongside the attacker's ground-truth actions.json.
# Resumable (skips episodes that already have actions.json). Run on the VM:
#   SCRIPTED=8 LLM=8 BENIGN=10 nohup bash scripts/capture_sweep.sh >sweep.log 2>&1 &
set -uo pipefail
cd "$(dirname "$0")/.."
LIB=research/out/caplib   # fresh, uniformly sensor-captured library
ENV=equifax_large
C2=http://192.168.201.10:8888
COMPOSE="docker compose -f docker/docker-compose.yml -f docker/docker-compose.run.yml -f docker/docker-compose.dbpivot.yml"
SCRIPTED=${SCRIPTED:-8}; LLM=${LLM:-8}; BENIGN=${BENIGN:-10}; PER_EP_TIMEOUT=${PER_EP_TIMEOUT:-900}

# Ensure the DB-pivot implant payload is staged (gitignored; a setup step).
[ -s incalmo/c2server/payloads/sandcat.go-linux ] || \
  cp incalmo/c2server/agents/sandcat.go incalmo/c2server/payloads/sandcat.go-linux 2>/dev/null || true

write_cfg() {  # $1 = scripted|llm|benign
  python3 - "$1" <<'PY'
import json, sys
t = sys.argv[1]
base = json.load(open("config/config.json"))
base["environment"] = "equifax_large"
if t == "scripted":
    base["strategy"] = {"name": "EquifaxStrategy"}; base["name"] = "sweep_scripted"
elif t == "benign":
    base["strategy"] = {"name": "BenignAdmin"}; base["name"] = "sweep_benign"
else:
    base["strategy"] = {"planning_llm": "claude-haiku-5-5",
                        "execution_llm": "claude-haiku-5-5", "abstraction": "incalmo"}
    base["name"] = "sweep_llm"
json.dump(base, open("config/config.json", "w"), indent=2)
PY
}

run_one() {  # $1=label $2=type $3=rep
  local eid="$1__${ENV}__rep$(printf %03d "$3")" EP
  EP="$LIB/$eid"
  if [ -f "$EP/actions.json" ]; then echo "[skip] $eid"; return; fi
  rm -rf "$EP"
  write_cfg "$2"
  echo "[run ] $eid ($2)"
  bash scripts/capture_episode.sh "$EP" timeout "$PER_EP_TIMEOUT" \
    $COMPOSE exec -T -e C2C_SERVER_AGENTS="$C2" -e "INCALMO_OUTPUT_DIR=/incalmo/$EP" \
    attacker bash -lc "cd /incalmo && uv run python main.py" \
    > "$EP.caplog" 2>&1 || echo "[warn] $eid capture returned non-zero"
  echo "       exfil=$(grep -o ExfiltratedData "$EP/actions.json" 2>/dev/null | wc -l) \
sensors: suri=$(wc -l < "$EP/sensors/suricata_eve.json" 2>/dev/null || echo 0) \
falco=$(wc -l < "$EP/sensors/falco.json" 2>/dev/null || echo 0)"
}

cp config/config.json config/config.json.sweepbak 2>/dev/null || true
trap 'mv config/config.json.sweepbak config/config.json 2>/dev/null || true' EXIT

echo "=== capture sweep: scripted=$SCRIPTED llm=$LLM benign=$BENIGN ==="
for i in $(seq 0 $((SCRIPTED - 1))); do run_one scripted-equifax scripted "$i"; done
for i in $(seq 0 $((LLM - 1)));      do run_one llm-haiku      llm      "$i"; done
for i in $(seq 0 $((BENIGN - 1)));   do run_one benign         benign   "$i"; done

touch "$LIB/SWEEP_DONE"
echo "=== SWEEP COMPLETE: $(ls -d $LIB/*/ 2>/dev/null | wc -l) episodes ==="
