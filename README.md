# Autonomous attack/defense study (Stats-425)

A research project built on **Incalmo** (an autonomous multi-host attack
framework). We add a **reactive defender** and a research harness, and evaluate
the defender on **independent sensor telemetry** (Falco host-EDR + Suricata
network) while the attacker's own log provides ground-truth labels.

**Thesis:** frontier-model safety training bounds autonomous intrusion —
measurably, robust to goal reframing, and as a specific generation shift (not
a capability one) — and independent host-EDR telemetry detects the models
that aren't bounded, substantially outperforming naive baselines, at zero
false positives across varied benign behavior. Full research plan,
experiments (E1–E4), threat model ([`THREAT_MODEL.md`](THREAT_MODEL.md)), and
venue strategy are in [`PAPER_PLAN.md`](PAPER_PLAN.md). Open tasks are
tracked in the repo **Issues**.

> ⚠️ **Security:** this repo runs a deliberately-vulnerable range (Struts CVE, a
> C2 server, an implant). Keep it on the sandboxed VM / local Docker only — never
> point it at anything you don't own. **Never commit** `.env` (API keys), the
> `sandcat` implant binaries, or the `caldera/` clone — they're gitignored.

---

## Repo map

```
incalmo/defense/      the defender: telemetry, config, orchestrator (sliding-window
                      scoring + simulated remediation + audit), remediation,
                      evaluate, sensors (Falco/Suricata -> SecurityEvent)
research/             grid.py (experiment design + SENSOR_WEIGHTS), cost.py,
                      extract_metrics.py (episodes -> tidy CSV), baselines.py
                      (naive-volume + Suricata-signature baselines, same
                      scoring machinery), live_defender.py (closed-loop
                      ablation: real intervention, not replay), run_sweep.py,
                      refusal_probe.py (fast model-refusal map), synthesize.py
                      (offline fixture), analyze.py (E1/E1b/E2/E4/GLM/curves/
                      detector comparison/benign-profile FPR)
scripts/               sensor_setup.sh, capture_episode.sh, vm_setup.sh,
                      capture_sweep.sh (scripted/LLM/benign, parameterized by
                      model/framing/benign-profile/tempo), scale_llm.sh,
                      framing_sweep.sh, gradient_sweep.sh, benign_profile_sweep.sh,
                      tempo_sweep.sh, live_defender_episode.sh
docker/               docker-compose*.yml  (base + .run.yml foothold + .dbpivot.yml)
tests/test_defense.py pure-stdlib tests (also runnable: python3 tests/test_defense.py)
PAPER_PLAN.md         thesis, experiments E1-E4, environments scoping, venue plan
THREAT_MODEL.md        attacker/defender capabilities, visibility, trust boundary
```

## Contributing

### 1. Local setup (no VM needed — do most dev here)

The defender + extractor are pure stdlib; only the analysis needs libs.

```bash
git clone https://github.com/nightpress/Stats-425-Final.git
cd Stats-425-Final
git switch main                                      # all work is merged here
pip install -r research/requirements-analysis.txt    # pandas/numpy/matplotlib/scipy (+statsmodels)

# run the tests
PYTHONPATH=. python3 tests/test_defense.py

# exercise the WHOLE pipeline offline on synthetic data (no range, no API cost):
PYTHONPATH=. python3 -m research.synthesize research/out/demo --scripted 15 --llm 15 --benign 12
PYTHONPATH=. python3 -m research.extract_metrics research/out/demo --out research/out/demo_rows.csv
PYTHONPATH=. python3 -m research.analyze research/out/demo_rows.csv --outdir research/out/demo
```

### 2. Accessing the live VM (the range + captured data)

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
3. The captured episode library is at `research/out/caplib/` (one dir per episode:
   `actions.json` = attacker ground truth, `sensors/` = Suricata `suricata_eve.json`
   + Falco `falco.json`). Pull it to analyze:
   ```bash
   rsync -az --exclude '*.pcap' root@<VM_IP>:/root/incalmo/research/out/caplib/ ./research/out/caplib/
   ```

### 3. Reproducing / extending the range on the VM

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

# e) generate the main captured episode library (resumable; scripted/LLM/benign):
SCRIPTED=8 LLM=8 BENIGN=10 nohup bash scripts/capture_sweep.sh > caplib_sweep.log 2>&1 &

# f) extract -> analyze (also pulls in research/out/baseline_rows.csv if present):
PYTHONPATH=. python3 -m research.extract_metrics research/out/caplib --out research/out/caplib_rows.csv
PYTHONPATH=. python3 -m research.baselines research/out/caplib --out research/out/baseline_rows.csv
PYTHONPATH=. python3 -m research.analyze research/out/caplib_rows.csv --outdir research/out/caplib

# g) the additional ablations (each independently resumable; run them one at a
#    time against the shared range — capture_sweep.sh/live_defender_episode.sh
#    both exec into the same attacker container):
nohup bash scripts/scale_llm.sh          > research/out/scale_llm.log 2>&1 &          # Sonnet/Opus arms
nohup bash scripts/framing_sweep.sh      > research/out/framing_sweep.log 2>&1 &      # E1b: goal-reframing robustness
nohup bash scripts/gradient_sweep.sh     > research/out/gradient_sweep.log 2>&1 &     # within-Claude generation gradient
nohup bash scripts/benign_profile_sweep.sh > research/out/benign_profile_sweep.log 2>&1 &  # benign-realism (light/heavy tempo)
nohup bash scripts/tempo_sweep.sh        > research/out/tempo_sweep.log 2>&1 &        # E4a: attack-tempo robustness
STRATEGY=scripted EP=research/out/caplib/<id> bash scripts/live_defender_episode.sh   # E4b: closed-loop, real intervention
```

Key facts (also in `PAPER_PLAN.md` / git history):
- Episodes run `MODE=docker` (foothold auto-plants); pass
  `C2C_SERVER_AGENTS=http://192.168.201.10:8888` so the DB can fetch the implant.
- The scripted `EquifaxStrategy` completes the full chain incl. exfiltration.
  LLM attackers vary sharply by model/generation: Claude 5.5 Sonnet/Opus
  **refuse outright** (API `finish_reason=refusal`, robust to goal reframing —
  see `research/refusal_probe.py` / `framings.json`); Haiku and the 4.5-4.8
  generations comply. This is a safety-training-generation effect, not a
  capability one (`PAPER_PLAN.md`).
- Suricata's signature alerts don't reassemble on offloaded container bridges
  AND don't discriminate attack from benign even when they fire — we use its
  flow/http/ssh metadata instead, and quantify that choice against
  signature baselines in `research/baselines.py`.
- The defender's sensor weights are host-EDR-centric
  (`research/grid.py::SENSOR_WEIGHTS`) because raw volume scoring is
  dominated by benign traffic (FPR=1.0 pre-fix) — see git history.

### 4. Contribution workflow

```bash
git switch main && git pull
git switch -c <type>/<topic>                     # e.g. feat/closed-loop-defender
# ... change code; keep changes small and tested ...
PYTHONPATH=. python3 tests/test_defense.py       # must pass
git commit -m "..."
git push -u origin <type>/<topic>                # open a PR against main
```
- Don't commit `.env`, `*.go` implant binaries, `caldera/`, or `research/out/`.
- Prefer verifying on the synthetic fixture or the captured `caplib/` before
  spending API budget or VM time.

### 5. What to work on
See the repo **Issues** — they break down the remaining analysis, the closed-loop
defender, the adaptive adversary, more topologies, and the write-up. Start with
the analysis issue once the captured sweep has finished.
