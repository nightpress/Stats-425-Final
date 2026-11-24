#!/usr/bin/env bash
# Phase 1: capture INDEPENDENT sensor telemetry around a single episode, then
# run Suricata offline on the captured traffic. Produces, inside the episode dir:
#   sensors/traffic.pcap        raw network capture of the range subnets
#   sensors/suricata/eve.json   Suricata IDS alerts + flows (the network sensor)
#   sensors/falco.json          host EDR events for the episode window
# The episode's own actions.json stays as GROUND TRUTH (labels), never fed to the
# defender; the defender will consume the sensors/ outputs.
#
# Usage (run on the VM host, range already up):
#   scripts/capture_episode.sh <episode_dir> <run-cmd...>
# where <run-cmd...> launches ONE episode (e.g. a docker compose exec ... run_sweep).
set -euo pipefail

EPISODE_DIR="${1:?usage: capture_episode.sh <episode_dir> <run-cmd...>}"; shift
SENSORS="$EPISODE_DIR/sensors"
mkdir -p "$SENSORS"
NETS='net 192.168.199.0/24 or net 192.168.200.0/24 or net 192.168.201.0/24'
# Falco runs as a systemd service and emits JSON to the journal (not a file).
FALCO_UNIT=$(systemctl is-active --quiet falco-modern-bpf && echo falco-modern-bpf || echo falco)

start_epoch=$(date +%s)
echo "[capture] start $(date -u +%Y-%m-%dT%H:%M:%S) (falco unit: $FALCO_UNIT) -> $SENSORS"

# 1) start network capture across the range subnets (all docker bridges via -i any)
tcpdump -i any -n -s 0 -w "$SENSORS/traffic.pcap" "$NETS" >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1  # let tcpdump bind before the episode generates traffic

# 2) run the episode (whatever command was passed)
echo "[capture] running episode: $*"
"$@" || echo "[capture] episode command returned non-zero (continuing to collect sensors)"

# 3) stop capture
sleep 1
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
end_epoch=$(date +%s)
echo "[capture] end $(date -u +%Y-%m-%dT%H:%M:%S)"

# 4) Suricata offline over the pcap -> network sensor events
if command -v suricata >/dev/null 2>&1; then
  mkdir -p "$SENSORS/suricata"
  suricata -r "$SENSORS/traffic.pcap" -l "$SENSORS/suricata" >/dev/null 2>&1 \
    && echo "[capture] suricata eve.json: $(wc -l < "$SENSORS/suricata/eve.json" 2>/dev/null || echo 0) events" \
    || echo "[capture] suricata run failed"
fi

# 5) pull Falco host-EDR events for the episode window from the journal (JSON lines)
journalctl -u "$FALCO_UNIT" -o cat --since "@$start_epoch" --until "@$end_epoch" 2>/dev/null \
  | grep '^{' > "$SENSORS/falco.json" || true
echo "[capture] falco events in window: $(wc -l < "$SENSORS/falco.json" 2>/dev/null || echo 0)"

echo "[capture] sensor outputs in $SENSORS"
ls -la "$SENSORS" 2>/dev/null
