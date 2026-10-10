---
feature: project-scaffolding
status: delivered
specs: [docs/specs/1-mvp.md]
plans: [docs/plans/1-0-project-setup.md]
commits: (initial commit)
---

# Project Scaffolding

## What Was Built

Go module (`github.com/zeal/auth`) with project structure, env-based config, pgx DB pool, stdlib HTTP mux with health endpoint, Docker Compose for Postgres+Redis, and graceful shutdown. Foundation for all subsequent plans.

## Position in MVP

First plan — everything else builds on this. Provides config loading, DB connectivity, HTTP server skeleton, and local dev infrastructure.

## Data Model

No tables yet (Plan 1-1).

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Pings DB, returns 200 ok or 503 |

## Architecture

```
cmd/server/main.go         — entrypoint, wires config/DB/router, graceful shutdown
internal/config/config.go  — env-based Config struct with defaults
internal/db/db.go          — pgxpool.NewWithConfig + Ping on startup
internal/handler/handler.go — http.NewServeMux router with /health
docker-compose.yml         — postgres:18-alpine (5435), redis:8-alpine (6380)
.env.example               — all config vars with empty values
```

## Known Issues / Deferred Work

- No JWT signing keys yet (Plan 1-2)
- No OAuth providers wired (Plans 1-5, 1-6)
- Redis client not initialized (Plan 1-7 for sessions)
- No migrations (Plan 1-1)
