# Contributing guide — autonomous attack/defense study

This is a Stats-425 research project built on **Incalmo** (an autonomous
multi-host attack framework). We added a **reactive defender** and a research
harness, and we evaluate the defender on **independent sensor telemetry**
(Falco host-EDR + Suricata network) while the attacker's own log provides
ground-truth labels. The research plan, thesis, and remaining work are in
[`PAPER_PLAN.md`](PAPER_PLAN.md). Pick up open tasks from the repo **Issues**.

> ⚠️ **Security:** this repo runs a deliberately-vulnerable range (Struts CVE,
> a C2 server, an implant). Keep it on the sandboxed VM / local Docker only —
> never point it at anything you don't own. **Never commit** `.env` (API keys),
> the `sandcat` implant binaries, or the `caldera/` clone — they're gitignored.

---

## 1. Where things are

```
incalmo/defense/      the defender: telemetry, config, orchestrator (sliding-window
                      scoring + simulated remediation + audit), remediation,
                      evaluate, sensors (Falco/Suricata -> SecurityEvent)
research/             grid.py (experiment design), cost.py (Claude $ + spend cap),
                      extract_metrics.py (episodes -> tidy CSV), run_sweep.py,
                      synthesize.py (offline fixture), analyze.py (E1/E2/GLM/curves)
scripts/              sensor_setup.sh, capture_episode.sh, capture_sweep.sh, vm_setup.sh
docker/               docker-compose*.yml  (base + .run.yml foothold + .dbpivot.yml)
tests/test_defense.py pure-stdlib tests (also runnable: python3 tests/test_defense.py)
PAPER_PLAN.md         thesis, four non-negotiables, experiments E1-E4, venue plan
```

## 2. Local setup (no VM needed — do most dev here)

The defender + extractor are pure stdlib; only the analysis needs libs.

```bash
git clone https://github.com/nightpress/Stats-425-Final.git
cd Stats-425-Final
git switch feat/defense-orchestrator-experiment      # all the work is on this branch
pip install -r research/requirements-analysis.txt    # pandas/numpy/matplotlib/scipy (+statsmodels)

# run the tests
PYTHONPATH=. python3 tests/test_defense.py

# exercise the WHOLE pipeline offline on synthetic data (no range, no API cost):
PYTHONPATH=. python3 -m research.synthesize research/out/demo --scripted 15 --llm 15 --benign 12
PYTHONPATH=. python3 -m research.extract_metrics research/out/demo --out research/out/demo_rows.csv
PYTHONPATH=. python3 -m research.analyze research/out/demo_rows.csv --outdir research/out/demo
```

## 3. Accessing the live VM (the range + captured data)

The range (3 Docker containers) + sensors live on a DigitalOcean VM under
`/root/incalmo`. **The VM's IP and SSH access are shared privately by the repo
owner — do not commit them.**

1. Send the owner your **SSH public key** (`cat ~/.ssh/id_ed25519.pub`). They add it:
   ```bash
   # (owner runs, in the DO web console or over SSH)
   echo '<your-ssh-public-key>' >> /root/.ssh/authorized_keys
   ```
2. Get the VM's public IP from the owner, then:
   ```bash
   ssh root@<VM_IP>
   cd /root/incalmo
   ```
3. The captured episode library from the first run is at
   `research/out/caplib/` (one dir per episode: `actions.json` = attacker ground
   truth, `sensors/` = Suricata `suricata_eve.json` + Falco `falco.json`).
   Pull it to your machine to analyze:
   ```bash
   rsync -az --exclude '*.pcap' root@<VM_IP>:/root/incalmo/research/out/caplib/ ./research/out/caplib/
   ```

## 4. Reproducing / extending the range on the VM

Some setup is intentionally **not in git** (secrets + the implant). To rebuild:

```bash
# a) secrets: create .env with YOUR Claude key (one clean line, no trailing comment)
cp runpod/.env.example .env && $EDITOR .env      # ANTHROPIC_API_KEY=sk-ant-...

# b) implant: get the sandcat binary from the owner (or build per runpod/README.md),
#    place it, and stage the lateral-move payload the DB pivot needs:
#    incalmo/c2server/agents/sandcat.go   (amd64 ELF)
cp incalmo/c2server/agents/sandcat.go incalmo/c2server/payloads/sandcat.go-linux

# c) sensors (once): Suricata + Falco
bash scripts/sensor_setup.sh

# d) bring up the range (base + foothold + DB-pivot-reachable C2):
docker compose -f docker/docker-compose.yml -f docker/docker-compose.run.yml \
  -f docker/docker-compose.dbpivot.yml up -d --build

# e) generate a captured episode library (resumable; scripted/LLM/benign):
SCRIPTED=8 LLM=8 BENIGN=10 nohup bash scripts/capture_sweep.sh > caplib_sweep.log 2>&1 &
```

Key facts worth knowing (also in `PAPER_PLAN.md` / git history):
- Episodes run `MODE=docker` (foothold auto-plants); pass
  `C2C_SERVER_AGENTS=http://192.168.201.10:8888` so the DB can fetch the implant.
- The scripted `EquifaxStrategy` completes the full chain incl. exfiltration;
  the LLM attacker halts pre-exfil (safety guardrail — a finding, not a bug).
- Suricata's signature alerts don't reassemble on offloaded container bridges;
  we use its flow/http/ssh metadata (see `incalmo/defense/sensors.py`).

## 5. Contribution workflow

```bash
git switch feat/defense-orchestrator-experiment && git pull
git switch -c <type>/<topic>                     # e.g. feat/closed-loop-defender
# ... change code; keep changes small and tested ...
PYTHONPATH=. python3 tests/test_defense.py       # must pass
git commit -m "..."                              # end with the Co-Authored-By line if AI-assisted
git push -u origin <type>/<topic>                # open a PR against the feature branch (or main)
```
- Don't commit `.env`, `*.go` implant binaries, `caldera/`, or `research/out/`.
- Prefer verifying on the synthetic fixture or the captured `caplib/` before
  spending API budget or VM time.

## 6. What to work on
See the repo **Issues** — they break down the remaining analysis, the
closed-loop defender, the adaptive adversary, more topologies, and the write-up.
Start with the analysis issue once the captured sweep has finished.
