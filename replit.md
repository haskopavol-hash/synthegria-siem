# Synthegria SIEM — Log Ingestion API

A FastAPI log ingestion service for the Synthegria SIEM platform. Accepts structured log batches (plain JSON and gzip-compressed), authenticates tenants via API keys, runs a rules-based anomaly detection engine on every batch, and reports usage to Stripe Billing Meters.

## Run & Operate

- **Dev server (Replit):** workflow `Synthegria API` → `uvicorn main:app --host 0.0.0.0 --port 8000`
- **Run tests:** `python scripts/test_api.py`  (30 tests, requires server running)
- **Test Stripe meter:** `python scripts/test_stripe_meter_events.py`

Required env var: `STRIPE_SECRET_KEY` — Stripe secret key (`sk_test_...` or `sk_live_...`)

## Stack

- Python 3.11, FastAPI, uvicorn[standard], stripe-python
- Dependency management: uv + `uv.lock`
- No database — stateless API; rate-limit state is in-memory per process

## Where things live

```
main.py                       — FastAPI app, all routes, middleware
utils/auth.py                 — API key → Stripe Customer ID mapping
utils/anomaly.py              — Rules-based anomaly detection engine
scripts/start.sh              — Production entrypoint (used by Dockerfile)
scripts/test_api.py           — 30-test end-to-end suite
scripts/test_stripe_meter_events.py — Multi-tenant Stripe meter smoke test
Dockerfile                    — Production container image
fly.toml                      — Fly.io deployment config
render.yaml                   — Render.com deployment config
```

## API Surface

| Method | Path | Description |
|--------|------|-------------|
| GET | `/healthz` | Liveness probe |
| GET | `/v1/audit` | Last N structured audit log entries |
| POST | `/v1/logs` | Ingest plain JSON log batch |
| POST | `/v1/logs/bulk` | Ingest gzip-compressed JSON log batch |

All ingestion responses include `anomaly_count` and `anomalies[]` plus `meter_event_id`.

## Security hardening

- `X-API-Key` authentication → 401
- Per-key rate limit: 60 req/key/min (fixed window) → 429
- Bulk endpoint: 10 MB compressed body cap → 413
- Bulk endpoint: `Content-Encoding: gzip` required → 415
- Structured `AuditLogMiddleware` logs every request as JSON to stderr

## Anomaly detection categories

| Type | Severity | Example signatures |
|------|----------|--------------------|
| `brute_force` | HIGH | `failed password`, `account locked`, 401/403 in log values |
| `sql_injection` | CRITICAL | `UNION SELECT`, `DROP TABLE`, `SLEEP()`, hex payloads |
| `xss` | HIGH | `<script>`, `javascript:`, `onerror=`, `document.cookie` |
| `auth_anomaly` | MEDIUM | `privilege escalation`, `sudo`, JWT issues, credential stuffing |

## Stripe integration

- Meter event name: `log_delivery`
- Price ID: `price_1TZyx6Rvq8CwKfXtw04VZgey`
- Test tenants: `synthegria_test_key_1` → `cus_UZ7oQ2QGGb7PjN`, `synthegria_test_key_2` → `cus_UZGcWFCthk4shy`
- Meter fires on ALL lines regardless of anomaly status

## Cloud deployment

### Fly.io (recommended)
```bash
fly launch --copy-config          # first time: creates app, detects Dockerfile
fly secrets set STRIPE_SECRET_KEY=sk_live_...
fly deploy
```
Edit `fly.toml` → set a unique `app` name before first deploy.

### Render.com
1. Push repo to GitHub/GitLab
2. Render dashboard → New → Blueprint → select repo (`render.yaml` is auto-detected)
3. Add `STRIPE_SECRET_KEY` as a secret in the Render environment settings

### Docker (any platform)
```bash
docker build -t synthegria-api .
docker run -e STRIPE_SECRET_KEY=sk_live_... -p 8000:8000 synthegria-api
```

### Runtime tuning
| Env var | Default | Notes |
|---------|---------|-------|
| `PORT` | `8000` | Fly.io and Render set this automatically |
| `WEB_CONCURRENCY` | `1` | Workers per container; scale horizontally instead |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warning` / `error` |
| `FORWARDED_ALLOW_IPS` | `*` | Restrict to your LB CIDR in high-security deployments |

## Architecture decisions

- **Stateless by design:** rate-limit counters live in process memory. In a multi-worker or multi-instance deployment, counts are per-process. Promote to Redis if exact cross-instance enforcement is required.
- **AuditLogMiddleware is outermost:** it wraps `BulkSizeLimitMiddleware` so every request — including those short-circuited by the size check — appears in the audit log.
- **No access log from uvicorn:** `--no-access-log` is set in `start.sh`; the AuditLogMiddleware emits structured JSON instead, avoiding duplicate lines.
- **Anomaly detection is synchronous:** the rules engine runs inline before the Stripe meter event to keep the response self-contained. For very large batches, move it to a background task if latency becomes a concern.
- **Stripe meter fires on all lines:** billing is usage-based, not clean-traffic-only. Anomalous logs still consumed pipeline capacity.

## Gotchas

- `uv sync --no-install-project` installs deps without treating the root as a package — correct because `main.py` is a script, not a package.
- The `Dockerfile` copies only `main.py` and `utils/`; test scripts and pnpm workspace files are excluded via `.dockerignore`.
- `fly.toml` `app` name must be globally unique on Fly.io — change it before `fly launch`.
- `render.yaml` marks `STRIPE_SECRET_KEY` as `sync: false` — you must set it manually in the Render dashboard after blueprint import.

## User preferences

- Keep all Python production deps locked in `uv.lock`; never add `--no-frozen-lockfile` to uv commands.
