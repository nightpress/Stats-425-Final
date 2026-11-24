#!/usr/bin/env bash
# One-shot: on a fresh amd64 Ubuntu VM, install Docker, build + start the Incalmo
# range, and run ONE capped dry-run episode. Run from the repo root after you have
# rsync'd the working tree (including .env with a valid ANTHROPIC_API_KEY and
# incalmo/c2server/agents/sandcat.go) onto the VM.
#
#   cd ~/incalmo && bash scripts/vm_setup.sh
#
# Env overrides: CAP_USD (default 45), COST_PER_EPISODE (0.25), TIMEOUT (1800s).
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$(pwd)"
CAP_USD="${CAP_USD:-45}"; COST_PER_EPISODE="${COST_PER_EPISODE:-0.25}"; TIMEOUT="${TIMEOUT:-1800}"
COMPOSE="docker compose -f docker/docker-compose.yml -f docker/docker-compose.run.yml"

echo "== 0. preflight =="
[ -f .env ] && grep -q '^[[:space:]]*ANTHROPIC_API_KEY=sk-' .env || { echo "ERROR: .env missing a real ANTHROPIC_API_KEY line"; exit 1; }
[ -s incalmo/c2server/agents/sandcat.go ] || { echo "ERROR: incalmo/c2server/agents/sandcat.go missing"; exit 1; }
file incalmo/c2server/agents/sandcat.go | grep -q "x86-64" || echo "WARN: sandcat.go is not x86-64; this host is amd64 so it should be."

echo "== 1. Docker =="
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
docker --version && docker compose version | head -1

echo "== 2. build + start range (MODE=docker plants the initial foothold) =="
$COMPOSE up -d --build
echo "waiting ~45s for C2 + Metasploit + celery to come up ..."
sleep 45
$COMPOSE ps

echo "== 3. confirm the initial foothold agent registered with the C2 =="
for i in $(seq 1 20); do
  n=$($COMPOSE exec -T attacker bash -lc "curl -s http://localhost:8888/agents | grep -o '\"paw\"' | wc -l" 2>/dev/null || echo 0)
  echo "  trusted agents seen: $n"
  [ "${n:-0}" -ge 1 ] && break
  sleep 6
done

echo "== 4. run ONE capped dry-run episode (Haiku attacker, \$$CAP_USD cap, ${TIMEOUT}s) =="
$COMPOSE exec -T attacker bash -lc \
  "cd /incalmo && uv run python -m research.run_sweep generate --library research/out/library --max-episodes 1 --timeout $TIMEOUT --cap $CAP_USD --cost-per-episode $COST_PER_EPISODE" || true

echo "== 5. results =="
echo "-- episode dirs --"; ls -la research/out/library/ 2>/dev/null || echo "(none created)"
for d in research/out/library/*/; do
  [ -d "$d" ] || continue
  echo "-- $d --"
  echo "   action_log.jsonl lines: $(wc -l < "$d/action_log.jsonl" 2>/dev/null || echo 0)"
  echo "   token_usage.json lines: $(wc -l < "$d/token_usage.json" 2>/dev/null || echo 0)"
  [ -f "$d/results.json" ] && echo "   results.json: present"
done
echo "-- manifest (cost per episode) --"; cat research/out/library/manifest.jsonl 2>/dev/null || echo "(no manifest)"
echo
echo "Done. If step 3 showed 0 agents, the foothold didn't plant — paste steps 2-3 output back."
echo "Pull results to your Mac with:  rsync -avz <user>@<vm>:$REPO/research/out/library/ ./library/"
