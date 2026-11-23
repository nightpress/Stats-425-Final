#!/usr/bin/env bash
# Phase 1 (external validity): install INDEPENDENT sensors on the range host so
# the defender can be evaluated on telemetry a real SOC would have — network IDS
# (Suricata) + host EDR (Falco, eBPF) — instead of the attacker's own actions.json.
# The attacker's actions.json is kept ONLY as ground-truth labels for scoring.
#
# Run once on the Ubuntu VM (as root):  bash scripts/sensor_setup.sh
# First-run note: Falco's eBPF probe can be finicky on a given kernel; if `falco`
# fails to start, re-run after `apt-get install -y linux-headers-$(uname -r)` or
# switch FALCO_DRIVER to kmod. Suricata is the critical sensor; Falco is additive.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "== Suricata (network IDS) + tooling =="
apt-get update -y
apt-get install -y suricata tcpdump jq linux-headers-"$(uname -r)" || apt-get install -y suricata tcpdump jq
suricata --build-info | head -1 || true
# Pull current rulesets (ET Open) so alerts are meaningful.
suricata-update || echo "suricata-update failed (will still run with built-in rules)"

echo "== Falco (host EDR via modern eBPF) =="
if ! command -v falco >/dev/null 2>&1; then
  curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
    | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" \
    > /etc/apt/sources.list.d/falcosecurity.list
  apt-get update -y
  # modern_ebpf needs no kernel module / dkms on recent kernels.
  echo "falco falco/driver_choice select modern_ebpf" | debconf-set-selections || true
  apt-get install -y falco || echo "WARN: falco install needs attention (see note above)"
fi

# Falco: emit JSON lines to a file the capture wrapper slices per episode.
FALCO_CFG=/etc/falco/falco.yaml
if [ -f "$FALCO_CFG" ]; then
  mkdir -p /var/log/falco
  sed -i 's/^json_output:.*/json_output: true/' "$FALCO_CFG" || true
  # Ensure a file output channel at /var/log/falco/falco.json
  if ! grep -q "/var/log/falco/falco.json" "$FALCO_CFG"; then
    cat >> "$FALCO_CFG" <<'YAML'

file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco/falco.json
YAML
  fi
  systemctl enable --now falco-modern-bpf 2>/dev/null || systemctl enable --now falco 2>/dev/null || \
    echo "WARN: start falco manually: falco -o json_output=true -o file_output.enabled=true -o file_output.filename=/var/log/falco/falco.json &"
fi

echo "== done =="
echo "Suricata: $(command -v suricata || echo MISSING)   Falco: $(command -v falco || echo MISSING)"
echo "Next: scripts/capture_episode.sh wraps an episode to collect pcap + suricata + falco."
