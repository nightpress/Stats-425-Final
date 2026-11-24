#!/usr/bin/env bash
# Phase 1: capture INDEPENDENT sensor telemetry around a single episode.
# Network: tcpdump on each docker bridge (real Ethernet frames; NOT `-i any`,
# whose Linux-cooked linktype Suricata decodes as 0 packets), then Suricata
# offline per-pcap with ET Open rules. Host: Falco events from the journal.
# Produces, inside the episode dir:
#   sensors/<network>.pcap        per-network packet capture
#   sensors/suricata_eve.json     concatenated Suricata events/alerts
#   sensors/falco.json            host-EDR events for the episode window
# The episode's actions.json stays GROUND TRUTH (labels), never fed to the defender.
#
# Usage (on the VM host, range up):  scripts/capture_episode.sh <episode_dir> <run-cmd...>
set -euo pipefail

EPISODE_DIR="${1:?usage: capture_episode.sh <episode_dir> <run-cmd...>}"; shift
SENSORS="$EPISODE_DIR/sensors"
mkdir -p "$SENSORS"
NETWORKS="${CAPTURE_NETWORKS:-docker_web_network docker_db_network docker_attacker_network}"
FALCO_UNIT=$(systemctl is-active --quiet falco-modern-bpf && echo falco-modern-bpf || echo falco)

start_epoch=$(date +%s)
echo "[capture] start $(date -u +%Y-%m-%dT%H:%M:%S) (falco: $FALCO_UNIT) -> $SENSORS"

# 1) one tcpdump per docker bridge (Ethernet linktype Suricata can decode)
declare -a TPIDS=()
for n in $NETWORKS; do
  id=$(docker network inspect "$n" -f '{{.Id}}' 2>/dev/null | cut -c1-12) || continue
  [ -n "$id" ] || continue
  br="br-$id"
  ip link show "$br" >/dev/null 2>&1 || { echo "[capture] bridge $br for $n missing, skip"; continue; }
  # Disable offload so the capture has real on-wire segments; GRO/GSO coalescing
  # breaks Suricata's stream reassembly (-> stream anomalies, no app-layer rules).
  ethtool -K "$br" gro off gso off tso off lro off 2>/dev/null || true
  tcpdump -i "$br" -n -s 0 -w "$SENSORS/${n}.pcap" >/dev/null 2>&1 &
  TPIDS+=($!)
  echo "[capture] tcpdump on $br ($n)"
done
sleep 1

# 2) run the episode
echo "[capture] running: $*"
"$@" || echo "[capture] episode command returned non-zero (continuing)"

# 3) stop captures
sleep 1
for pid in "${TPIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
wait 2>/dev/null || true
end_epoch=$(date +%s)
echo "[capture] end $(date -u +%Y-%m-%dT%H:%M:%S)"

# 4) Suricata offline per pcap -> concatenated eve.json (ET Open rules)
: > "$SENSORS/suricata_eve.json"
for pcap in "$SENSORS"/*.pcap; do
  [ -s "$pcap" ] || continue
  tmp=$(mktemp -d)
  # -k none: virtual-interface capture has offloaded (invalid) checksums; without
  # this Suricata floods invalid-checksum alerts and skips stream reassembly/ET rules.
  suricata -r "$pcap" -l "$tmp" -k none >/dev/null 2>&1 || true
  cat "$tmp/eve.json" >> "$SENSORS/suricata_eve.json" 2>/dev/null || true
  rm -rf "$tmp"
done
alerts=$(grep -c '"event_type":"alert"' "$SENSORS/suricata_eve.json" 2>/dev/null || echo 0)
echo "[capture] suricata events: $(wc -l < "$SENSORS/suricata_eve.json" 2>/dev/null || echo 0) (alerts: $alerts)"

# 5) Falco host-EDR events for the episode window from the journal
journalctl -u "$FALCO_UNIT" -o cat --since "@$start_epoch" --until "@$end_epoch" 2>/dev/null \
  | grep '^{' > "$SENSORS/falco.json" || true
echo "[capture] falco events: $(wc -l < "$SENSORS/falco.json" 2>/dev/null || echo 0)"
ls -la "$SENSORS" 2>/dev/null
