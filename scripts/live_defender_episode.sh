#!/usr/bin/env bash
# Run ONE episode under the closed-loop (live) defender ablation instead of
# offline replay: research.live_defender runs on the VM HOST (it needs
# `journalctl -u falco-modern-bpf`, a host systemd unit not visible inside the
# attacker container, and only imports incalmo.defense, which is pure stdlib
# and already proven to run directly on the host throughout this study), while
# the attacker runs in its container as usual - both launched together so the
# live defender's own start time stands in for the episode's start.
#
# Usage: STRATEGY=scripted|llm EP=research/out/caplib/<episode_id> \
#          bash scripts/live_defender_episode.sh
# Env: LLM_MODEL (if STRATEGY=llm), WINDOW/THRESHOLD (live defender config,
#      default 120/65 - the Falco-only calibration), DRY_RUN=1 to score
#      without containing, PER_EP_TIMEOUT (default 900).
set -uo pipefail
cd "$(dirname "$0")/.."

STRATEGY=${STRATEGY:-scripted}
EP=${EP:?set EP=research/out/caplib/<episode_id>}
WINDOW=${WINDOW:-120}; THRESHOLD=${THRESHOLD:-65}; PER_EP_TIMEOUT=${PER_EP_TIMEOUT:-900}
DRY_FLAG=(); [ "${DRY_RUN:-0}" = "1" ] && DRY_FLAG=(--dry-run)
C2=http://192.168.201.10:8888
COMPOSE="docker compose -f docker/docker-compose.yml -f docker/docker-compose.run.yml -f docker/docker-compose.dbpivot.yml"

rm -rf "$EP"; mkdir -p "$EP"

python3 - "$STRATEGY" <<'PY'
import json, os, sys
t = sys.argv[1]
base = json.load(open("config/config.json"))
base["environment"] = "equifax_large"
if t == "scripted":
    base["strategy"] = {"name": "EquifaxStrategy"}; base["name"] = "live_scripted"
else:
    m = os.environ.get("LLM_MODEL", "claude-haiku-5-5")
    base["strategy"] = {"planning_llm": m, "execution_llm": m, "abstraction": "incalmo"}
    base["name"] = "live_llm"
json.dump(base, open("config/config.json", "w"), indent=2)
PY

cp config/config.json config/config.json.livebak 2>/dev/null || true
trap 'mv config/config.json.livebak config/config.json 2>/dev/null || true' EXIT

echo "=== launching live defender (window=$WINDOW threshold=$THRESHOLD ${DRY_FLAG[*]:-}) on host ==="
PYTHONPATH=. nohup python3 -m research.live_defender "$EP" --c2 http://localhost:8888 \
  --window "$WINDOW" --threshold "$THRESHOLD" --max-seconds "$PER_EP_TIMEOUT" "${DRY_FLAG[@]}" \
  > "$EP.live_defender.log" 2>&1 &
DEFENDER_PID=$!

echo "=== launching attacker ($STRATEGY) ==="
timeout "$PER_EP_TIMEOUT" $COMPOSE exec -T -e C2C_SERVER_AGENTS="$C2" -e "INCALMO_OUTPUT_DIR=/incalmo/$EP" \
  attacker bash -lc "cd /incalmo && uv run python main.py" > "$EP.caplog" 2>&1
ATTACKER_RC=$?

# Give the live defender a moment to finish writing its audit, then stop it.
sleep 2
kill "$DEFENDER_PID" 2>/dev/null || true
wait "$DEFENDER_PID" 2>/dev/null || true

echo "=== RESULT ==="
echo "attacker exit: $ATTACKER_RC"
echo "actions.json exfil: $(grep -o ExfiltratedData "$EP/actions.json" 2>/dev/null | wc -l)"
echo "live_defense.json: $(wc -c < "$EP/live_defense.json" 2>/dev/null || echo 0) bytes"
python3 -c "
import json
try:
    audit = json.load(open('$EP/live_defense.json'))
    for e in audit:
        if e.get('event') in ('detection','contained'):
            print(' ', e)
except FileNotFoundError:
    print('  (no live_defense.json)')
"
