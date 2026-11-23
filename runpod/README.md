# Running the defense study on RunPod

The experiment has two parts with very different infrastructure needs:

| Part | Needs | Cost |
|---|---|---|
| **Attacker episode library** (generate once) | the Incalmo range (Docker) + the Claude API | a CPU pod + your Claude credit |
| **Defender sweep + analysis** (free, offline) | just Python | negligible |

**You do NOT need a GPU.** The attacker's "intelligence" is the Claude API
(remote); the range is CPU-only containers. Rent the cheapest **CPU pod**, not a
GPU pod. The only metered Claude spend is generating the episode library, capped
hard by `research/run_sweep.py` (see `research/README.md` for the budget model).

## 1. Pick a Docker-capable pod

The range is `docker compose`, so the pod must be able to run Docker. Use a
RunPod **CPU pod** whose template provides Docker (a Docker-in-Docker / `dind`
template, or one where you have root to `apt-get install docker.io docker-compose-plugin`).
Nested Docker needs a privileged/dind-capable template; if a given RunPod
template refuses it, the exact same commands run on **any Linux host with Docker**
— including Docker Desktop on your own Mac for a dry run before you rent anything.

## 2. Bring up the range

```bash
git clone <your-fork-url> && cd Stats-425-Final
cp runpod/.env.example .env
#   edit .env: set ANTHROPIC_API_KEY=sk-ant-...   (this is the budget)
docker compose -f docker/docker-compose.yml up -d --build
#   brings up: attacker (C2 + Celery + Metasploit on :8888), Equifax webserver, db
docker compose -f docker/docker-compose.yml ps          # confirm all healthy
```

## 3. Run the pipeline

Everything runs inside the `attacker` container (it has the repo at `/incalmo`
and reaches the range at `http://localhost:8888`):

```bash
docker compose -f docker/docker-compose.yml exec \
  -e ANTHROPIC_API_KEY -e CAP_USD=45 -e COST_PER_EPISODE=0.25 -e PILOT=5 \
  attacker bash runpod/run_experiment.sh
```

`run_experiment.sh` prints the plan, generates the library (stopping the moment
the spend cap or the pilot extrapolation says it would exceed the cap), adds
synthetic benign episodes for the false-positive axis, extracts
`research/out/rows.csv`, and runs the analysis if its deps are present.

To include the stronger-attacker invariance arm (costs ~20× per episode — raise
`COST_PER_EPISODE` or lower `REPLICATES` in `research/grid.py` first):
`-e INVARIANCE_ARM=1`.

## 4. Get the results out

```bash
docker compose -f docker/docker-compose.yml cp \
  attacker:/incalmo/research/out ./out
```

`out/rows.csv` is the dataset; `out/summary_by_cell.csv` and `out/figures/*.png`
are the headline results. The analysis also runs locally: `pip install -r
research/requirements-analysis.txt && PYTHONPATH=. python3 -m research.analyze
out/rows.csv --outdir out`.

## Cost control checklist (stay under budget)

- Attacker stays on `claude-haiku-5-5` (default in `research/grid.py`).
- `CAP_USD` is a hard stop enforced *before* each episode — it cannot be exceeded.
- `PILOT=5` extrapolates real per-episode cost after 5 runs and aborts if the
  full run would cross the cap. **Always start with a pilot.**
- The defender operating-curve sweep (window × threshold × scope) is replayed
  offline over the library — it costs **nothing**, so make it as fine as you like.
- Stop the pod when the sweep finishes; a stopped CPU pod bills only disk.
