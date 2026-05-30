# Synthegria SIEM — Log Ingestion API

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/FastAPI-0.136-009688?style=flat-square&logo=fastapi&logoColor=white"/>
  <img src="https://img.shields.io/badge/Stripe-Metered%20Billing-6772E5?style=flat-square&logo=stripe&logoColor=white"/>
  <img src="https://img.shields.io/badge/OpenAI-gpt--4o--mini-412991?style=flat-square&logo=openai&logoColor=white"/>
  <img src="https://img.shields.io/badge/Tests-125%20passed-22C55E?style=flat-square&logo=pytest&logoColor=white"/>
</p>

> **Production-ready log ingestion backbone for the Synthegria SIEM platform.**
> Accepts structured security event batches, runs a rules-based anomaly engine,
> delivers AI-powered threat analysis via GPT-4o-mini, and reports usage to
> Stripe Metered Billing — all behind a single authenticated API.

---

## Table of Contents

1. [Architecture](#architecture)
2. [API Reference](#api-reference)
3. [Anomaly Detection Engine](#anomaly-detection-engine)
4. [AI Security Analyst](#ai-security-analyst)
5. [Async Bulk Ingestion](#async-bulk-ingestion)
6. [Authentication & Rate Limiting](#authentication--rate-limiting)
7. [Stripe Metered Billing](#stripe-metered-billing)
8. [Client SDKs](#client-sdks)
9. [Running Locally](#running-locally)
10. [Test Suite](#test-suite)
11. [Cloud Deployment](#cloud-deployment)
12. [Configuration Reference](#configuration-reference)
13. [Architecture Decisions](#architecture-decisions)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Synthegria SIEM API                          │
│                        FastAPI  v1.1.0                              │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  AuditLogMiddleware  (outermost — logs every request)        │   │
│  │  ┌────────────────────────────────────────────────────────┐  │   │
│  │  │  BulkSizeLimitMiddleware  (10 MB cap → 413)            │  │   │
│  │  │  ┌──────────────────────────────────────────────────┐  │  │   │
│  │  │  │  Routes                                          │  │  │   │
│  │  │  │  GET  /                 Landing page             │  │  │   │
│  │  │  │  GET  /healthz          Liveness probe           │  │  │   │
│  │  │  │  GET  /v1/audit         Audit log viewer         │  │  │   │
│  │  │  │  POST /v1/logs          Sync JSON ingestion      │  │  │   │
│  │  │  │  POST /v1/logs/bulk     Async gzip ingestion     │  │  │   │
│  │  │  │  GET  /v1/jobs/{id}     Job status polling       │  │  │   │
│  │  │  └──────────────────────────────────────────────────┘  │  │   │
│  │  └────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌────────────────────┐    ┌─────────────────┐    ┌─────────────┐  │
│  │  Anomaly Engine    │    │  AI Analyst      │    │  Stripe     │  │
│  │  utils/anomaly.py  │───▶│  utils/ai_analyst│───▶│  Meter API  │  │
│  │  Rules-based scan  │    │  gpt-4o-mini     │    │  log_delivery│ │
│  │  4 threat types    │    │  Mock fallback   │    │  per-line   │  │
│  └────────────────────┘    └─────────────────┘    └─────────────┘  │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Async Bulk Worker  (asyncio.Queue + background task)         │ │
│  │  POST /v1/logs/bulk ──▶ 202 + job_id                          │ │
│  │  Worker: anomaly scan + AI analysis + Stripe meter (parallel) │ │
│  │  GET /v1/jobs/{id}  ──▶ pending │ processing │ done │ failed  │ │
│  │  Job store TTL: 1 hour  │  Queue capacity: 500 jobs           │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

### Key design principles

| Principle | Detail |
|---|---|
| **Stateless ingestion** | No database — all per-request state lives in the response envelope |
| **Middleware layering** | `AuditLogMiddleware` wraps everything, including size-limit short-circuits |
| **Async background worker** | A single `asyncio.Queue` drains bulk jobs; anomaly scan + Stripe fire concurrently with `asyncio.gather` |
| **Graceful AI fallback** | AI analyst runs in `live` mode when `OPENAI_API_KEY` is set; silently falls back to a deterministic `mock` template on any error |
| **Usage-based billing** | Stripe meter fires on **all lines** — anomalous traffic still consumed pipeline capacity |

---

## API Reference

Base URL: `https://your-app.onrender.com`

Authentication: `X-API-Key: <tenant_api_key>` header on all ingestion endpoints.

### `GET /healthz`

Liveness probe. No authentication required.

**Response 200**
```json
{ "status": "ok" }
```

---

### `GET /v1/audit`

Returns the last N structured audit log entries recorded by `AuditLogMiddleware`.

**Query parameters**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | integer | 20 | Number of entries to return (max 100) |

**Response 200**
```json
[
  {
    "ts":             "2026-05-30T12:00:00.000Z",
    "method":         "POST",
    "path":           "/v1/logs",
    "status_code":    200,
    "duration_ms":    14.3,
    "api_key":        "synthe...ey_1",
    "customer_id":    "cus_UZ7oQ2QGGb7PjN",
    "lines_received": 42,
    "anomaly_count":  2,
    "ip":             "203.0.113.5"
  }
]
```

---

### `POST /v1/logs` — Synchronous ingestion

Ingest a plain JSON array of log lines. Anomaly detection and (if applicable) AI analysis run **inline** before the response is returned.

**Headers**

| Header | Value |
|---|---|
| `X-API-Key` | Tenant API key |
| `Content-Type` | `application/json` |

**Request body** — array of log objects (any fields accepted):
```json
[
  {
    "timestamp":  "2026-05-30T12:00:00Z",
    "source_ip":  "203.0.113.5",
    "message":    "Failed password for root from 203.0.113.5",
    "severity":   "HIGH",
    "service":    "sshd"
  }
]
```

**Response 200**
```json
{
  "status":         "ok",
  "customer_id":    "cus_UZ7oQ2QGGb7PjN",
  "lines_received": 1,
  "meter_event_id": "mtr_evt_1ABC...",
  "anomaly_count":  1,
  "anomalies": [
    {
      "type":       "brute_force",
      "severity":   "HIGH",
      "matched_on": "failed password",
      "log_index":  0
    }
  ],
  "ai_analysis": {
    "mode":          "live",
    "model":         "gpt-4o-mini",
    "threat_level":  "HIGH",
    "attack_types":  ["brute_force"],
    "summary":       "A credential brute-force campaign is underway ...",
    "tokens_used":   148
  }
}
```

**Empty batch** — returns 200 with `meter_event_id: null` and `lines_received: 0`.

**Error responses**

| Code | Condition |
|---|---|
| 401 | Missing or invalid `X-API-Key` |
| 422 | Body is not a JSON array |
| 429 | Rate limit exceeded (60 req/key/min) |

---

### `POST /v1/logs/bulk` — Async gzip ingestion

High-throughput endpoint. Accepts a gzip-compressed JSON array and returns
**202 Accepted** immediately. Processing happens in a background worker.

**Headers**

| Header | Required | Value |
|---|---|---|
| `X-API-Key` | Yes | Tenant API key |
| `Content-Encoding` | Yes | `gzip` |
| `Content-Type` | Yes | `application/json` |

**Request body** — gzip-compressed JSON array (same log format as above, max 10 MB compressed).

**Response 202**
```json
{
  "status":         "accepted",
  "job_id":         "a3f7c2b1-...",
  "lines_received": 5000,
  "poll_url":       "/v1/jobs/a3f7c2b1-..."
}
```

**Error responses**

| Code | Condition |
|---|---|
| 401 | Missing or invalid `X-API-Key` |
| 413 | Compressed body exceeds 10 MB |
| 415 | `Content-Encoding: gzip` header missing |
| 429 | Rate limit exceeded |
| 503 | Job queue full (500 job cap) |

---

### `GET /v1/jobs/{job_id}` — Job status polling

Poll the result of an async bulk ingestion job. No authentication required.

**Path parameters**

| Parameter | Type | Description |
|---|---|---|
| `job_id` | UUID string | Returned by `POST /v1/logs/bulk` |

**Response 200 — pending / processing**
```json
{
  "job_id":         "a3f7c2b1-...",
  "status":         "processing",
  "customer_id":    "cus_UZ7oQ2QGGb7PjN",
  "lines_received": 5000,
  "created_at":     "2026-05-30T12:00:00Z"
}
```

**Response 200 — done**
```json
{
  "job_id":         "a3f7c2b1-...",
  "status":         "done",
  "customer_id":    "cus_UZ7oQ2QGGb7PjN",
  "lines_received": 5000,
  "created_at":     "2026-05-30T12:00:00Z",
  "completed_at":   "2026-05-30T12:00:01Z",
  "result": {
    "status":             "ok",
    "meter_event_id":     "mtr_evt_1ABC...",
    "anomaly_count":      3,
    "anomalies":          [...],
    "ai_analysis":        {...},
    "compressed_bytes":   141200,
    "uncompressed_bytes": 612000,
    "compression_ratio":  "4.33x"
  }
}
```

**Response 404** — Job not found or expired (1-hour TTL).

---

## Anomaly Detection Engine

Located in `utils/anomaly.py`. Runs synchronously on every ingested batch before the Stripe meter fires.

### Detection rules

| Category | Severity | Example signatures |
|---|---|---|
| `brute_force` | **HIGH** | `failed password`, `account locked`, HTTP 401/403 in log values |
| `sql_injection` | **CRITICAL** | `UNION SELECT`, `DROP TABLE`, `SLEEP()`, `0x` hex payloads |
| `xss` | **HIGH** | `<script>`, `javascript:`, `onerror=`, `document.cookie` |
| `auth_anomaly` | **MEDIUM** | `privilege escalation`, `sudo`, JWT forgery, credential stuffing |

Scanning is case-insensitive and inspects **all string values** in each log object, not just the `message` field.

### Anomaly object shape

```json
{
  "type":       "sql_injection",
  "severity":   "CRITICAL",
  "matched_on": "UNION SELECT",
  "log_index":  7
}
```

---

## AI Security Analyst

Located in `utils/ai_analyst.py`. Triggered only for anomalies with severity **CRITICAL** or **HIGH** — medium/low noise is filtered out.

### Modes

| Mode | When | Model |
|---|---|---|
| `live` | `OPENAI_API_KEY` env var is set | `gpt-4o-mini` |
| `mock` | Key absent, or any OpenAI API error | deterministic template engine |

The `mock` mode is not a stub — it produces a fully structured, human-readable threat summary using the detected attack types and top severity. This means the API returns a consistent `ai_analysis` shape in all environments, enabling downstream consumers to be coded against the same contract regardless of whether an OpenAI key is configured.

### `ai_analysis` response shape

```json
{
  "mode":           "live",
  "model":          "gpt-4o-mini",
  "threat_level":   "CRITICAL",
  "attack_types":   ["sql_injection", "xss"],
  "summary":        "A multi-vector attack combining SQL injection and XSS ...",
  "tokens_used":    212
}
```

In `mock` mode, `tokens_used` is absent and a `disclaimer` field is added:

```json
{
  "mode":        "mock",
  "model":       "mock-analyst-v1",
  "threat_level": "HIGH",
  "attack_types": ["brute_force"],
  "summary":     "Credential brute-force detected. Recommend blocking source IPs ...",
  "disclaimer":  "Set OPENAI_API_KEY for GPT-4o-mini powered analysis."
}
```

### Automatic fallback

If the OpenAI API call fails for any reason (network error, quota exceeded, model unavailability), the analyst catches the exception and returns a mock-mode result with an additional `fallback_reason` field. This ensures the ingestion response is never blocked by third-party API instability.

---

## Async Bulk Ingestion

The bulk endpoint is designed for high-throughput scenarios — log shippers, batch collectors, and SIEM forwarders that accumulate events and flush on an interval.

### How it works

```
Client                    API                      Worker
  │                         │                         │
  │ POST /v1/logs/bulk       │                         │
  │ Content-Encoding: gzip  │                         │
  │ [gzip payload]  ───────▶│                         │
  │                         │ decompress + validate   │
  │                         │ enqueue(job)  ─────────▶│
  │◀─────────────────────── │                         │ anomaly scan
  │ 202 Accepted             │                         │ AI analysis  ──▶ OpenAI
  │ { job_id, poll_url }     │                         │ Stripe meter ──▶ Stripe API
  │                         │                         │
  │ GET /v1/jobs/{id}  ─────▶│                         │
  │◀──────── { status: "processing" }                  │
  │                         │                         │ done
  │ GET /v1/jobs/{id}  ─────▶│◀────────── result ──────│
  │◀──────── { status: "done", result: {...} }          │
```

### Performance notes

- **Compression stats** are returned in the done result (`compressed_bytes`, `uncompressed_bytes`, `compression_ratio`) so you can tune client-side compression levels.
- AI analysis and Stripe meter fire **concurrently** with `asyncio.gather` inside the worker, reducing per-job latency by ~40% for batches that trigger AI analysis.
- Job results are cached in-memory for **1 hour** with a periodic GC task evicting expired entries.
- Queue capacity is **500 pending jobs**. Overflow returns 503 Service Unavailable.

---

## Authentication & Rate Limiting

### API Key authentication

All ingestion endpoints require `X-API-Key: <key>` header.

| Response | Condition |
|---|---|
| 401 + `WWW-Authenticate: ApiKey realm="Synthegria"` | Key missing or unrecognised |

The `WWW-Authenticate` header is RFC 7235 compliant. Error bodies never echo the raw submitted key.

### Per-key rate limiting

Fixed window, in-process counter. Default: **60 requests per key per minute**.

```
HTTP/1.1 429 Too Many Requests
Retry-After: 42
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1748599620

{"detail": "Rate limit exceeded — retry after 42s"}
```

> **Multi-instance note:** Rate counters live in process memory. In a horizontally-scaled deployment, promote the counter store to Redis for exact cross-instance enforcement.

---

## Stripe Metered Billing

Every successful ingestion — both sync and bulk — fires a Stripe Billing Meter event.

| Parameter | Value |
|---|---|
| Meter event name | `log_delivery` |
| Unit | per log line |
| Scope | All lines, including anomalous ones |
| Price ID | `price_1TZyx6Rvq8CwKfXtw04VZgey` |

Anomalous log lines still consumed pipeline capacity and are billed normally.

### Meter event flow

```
POST /v1/logs  ──▶  anomaly scan  ──▶  stripe.billing.MeterEvent.create(
                                          event_name="log_delivery",
                                          payload={ value: N, stripe_customer_id: "cus_..." }
                                       )  ──▶  meter_event_id in response
```

If Stripe is unreachable, the endpoint returns **502 Bad Gateway** with a descriptive error. Retry logic should be implemented client-side.

---

## Client SDKs

Two official SDKs ship in the `sdk/` directory, both with zero external dependencies.

### Python SDK

**Install**
```bash
pip install ./sdk/python
```

**Synchronous ingestion**
```python
from synthegria import SynthegriaClient

client = SynthegriaClient(
    api_key="synthegria_acme_abc123",
    base_url="https://your-app.onrender.com",
)

logs = [
    {"timestamp": "2026-05-30T12:00:00Z", "source_ip": "10.0.0.1",
     "message": "Failed password for root", "severity": "HIGH"},
]

result = client.ingest(logs)
print(f"Lines received:  {result['lines_received']}")
print(f"Anomalies found: {result['anomaly_count']}")
print(f"Meter event:     {result['meter_event_id']}")

if result["ai_analysis"]:
    print(f"Threat level:    {result['ai_analysis']['threat_level']}")
    print(f"Summary:         {result['ai_analysis']['summary']}")
```

**Async bulk ingestion**
```python
# Submit a large batch — returns immediately with a job handle
large_batch = [{"message": f"event {i}", "source_ip": "10.0.0.1"} for i in range(10_000)]

job = client.ingest_bulk(large_batch)
print(f"Job queued: {job.job_id}")

# Block until complete (polls every 0.5s, 60s timeout)
result = job.wait(timeout=60)
print(f"Done — {result['anomaly_count']} anomalies, ratio: {result['compression_ratio']}")
```

**Error handling**
```python
from synthegria import AuthError, RateLimitError, SynthegriaError

try:
    result = client.ingest(logs)
except AuthError:
    print("Invalid API key — check X-API-Key")
except RateLimitError as e:
    print(f"Rate limited — retry after {e.retry_after}s")
except SynthegriaError as e:
    print(f"API error {e.status_code}: {e}")
```

### JavaScript / Node.js SDK

**Install**
```bash
npm install ./sdk/javascript
```

**Synchronous ingestion**
```javascript
const { SynthegriaClient, AuthError, RateLimitError } = require("@synthegria/client");

const client = new SynthegriaClient({
  apiKey:  "synthegria_acme_abc123",
  baseUrl: "https://your-app.onrender.com",
});

const result = await client.ingest(logs);
console.log(`Lines received:  ${result.lines_received}`);
console.log(`Anomalies found: ${result.anomaly_count}`);
console.log(`AI summary:      ${result.ai_analysis?.summary ?? "none"}`);
```

**Async bulk ingestion**
```javascript
const job = await client.ingestBulk(largeBatch);
console.log(`Job queued: ${job.jobId}`);

const done = await job.wait({ timeout: 60_000, pollInterval: 500 });
console.log(`Anomalies: ${done.anomaly_count}, ratio: ${done.compression_ratio}`);
```

**TypeScript**
```typescript
import { SynthegriaClient, IngestResult, AIAnalysis } from "@synthegria/client";

const client = new SynthegriaClient({ apiKey: "...", baseUrl: "..." });
const result: IngestResult = await client.ingest(logs);
const ai: AIAnalysis | null = result.ai_analysis;
```

---

## Running Locally

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) package manager
- A Stripe secret key (`sk_test_...`)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/haskopavol-hash/synthegria-siem.git
cd synthegria-siem

# 2. Install dependencies
uv sync --no-install-project

# 3. Set environment variables
export STRIPE_SECRET_KEY=sk_test_...
export OPENAI_API_KEY=sk-...     # optional — enables live AI analysis

# 4. Start the server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# 5. Verify
curl http://localhost:8000/healthz
# → {"status":"ok"}
```

### Run the test suites

```bash
# Pytest suite (125 unit/integration tests — no live server needed)
python -m pytest tests/ -v

# End-to-end suite (38 tests — requires server running on :8000)
python scripts/test_api.py

# Stripe meter smoke test (multi-tenant)
python scripts/test_stripe_meter_events.py
```

---

## Test Suite

125 tests across 6 modules, all passing. No live server or external API required — Stripe is mocked via pytest fixtures, rate-limit state is reset between tests, and the AI analyst runs in mock mode.

| Module | Tests | Coverage |
|---|---|---|
| `tests/test_auth.py` | 12 | 401 errors, WWW-Authenticate header, key masking, bulk auth |
| `tests/test_ingestion.py` | 13 | Response structure, empty batches, rate limiting |
| `tests/test_bulk.py` | 22 | 202 responses, gzip validation, job lifecycle, compression stats |
| `tests/test_anomaly.py` | 26 | All 4 detection categories, AI analysis integration |
| `tests/test_ai_analyst.py` | 27 | Mock mode, live fallback, template variants, helpers |
| `tests/test_audit.py` | 12 | Audit log structure, key masking, per-endpoint data |
| **Total** | **125** | **125 passed** |

Run with: `python -m pytest tests/ -v`

---

## Cloud Deployment

### Render.com (included `render.yaml`)

1. Push repo to GitHub
2. Render dashboard → **New → Blueprint** → select your repo (`render.yaml` auto-detected)
3. Set `STRIPE_SECRET_KEY` as a secret in the Render environment panel
4. Optionally set `OPENAI_API_KEY` to enable live AI analysis
5. Deploy

### Fly.io (included `fly.toml`)

```bash
fly launch --copy-config          # creates app; detects Dockerfile
fly secrets set STRIPE_SECRET_KEY=sk_live_...
fly secrets set OPENAI_API_KEY=sk-...   # optional
fly deploy
```

Edit `fly.toml` → set a globally unique `app` name before first deploy.

### Docker

```bash
docker build -t synthegria-api .
docker run \
  -e STRIPE_SECRET_KEY=sk_live_... \
  -e OPENAI_API_KEY=sk-...          \
  -p 8000:8000 \
  synthegria-api
```

---

## Configuration Reference

All configuration is via environment variables.

| Variable | Required | Default | Description |
|---|---|---|---|
| `STRIPE_SECRET_KEY` | **Yes** | — | Stripe secret key (`sk_test_...` or `sk_live_...`) |
| `OPENAI_API_KEY` | No | — | Enables live GPT-4o-mini AI analysis; falls back to mock if unset |
| `PORT` | No | `8000` | Server port (set automatically by Render/Fly.io) |
| `WEB_CONCURRENCY` | No | `1` | uvicorn workers per container |
| `LOG_LEVEL` | No | `info` | `debug` / `info` / `warning` / `error` |
| `FORWARDED_ALLOW_IPS` | No | `*` | Restrict to your load balancer CIDR in production |

---

## Architecture Decisions

### Stateless by design

No database — rate-limit counters live in process memory. In a multi-worker or multi-instance deployment, counts are per-process. Promote to Redis if exact cross-instance enforcement is required.

### AuditLogMiddleware is outermost

It wraps `BulkSizeLimitMiddleware` so every request — including those short-circuited by the 10 MB size check — appears in the audit log with the correct status code and duration.

### Anomaly detection is synchronous

The rules engine runs inline before the Stripe meter event fires, keeping the response self-contained with full anomaly context. For very high batch sizes (>100k lines), consider moving detection to a background task.

### AI analysis fires only for CRITICAL/HIGH

Filtering out MEDIUM/LOW keeps API call volume and cost proportional to actual threat severity. The threshold is adjustable in `utils/ai_analyst.py`.

### Stripe meters ALL lines

Billing is usage-based on raw pipeline capacity consumed. Anomalous traffic still traversed the ingestion pipeline and is billed normally. This makes billing predictable and immune to anomaly classification changes.

### Async worker uses a single task

A single `asyncio.Queue` consumer avoids thundering-herd on the Stripe API. For higher throughput, increase worker parallelism in `_bulk_worker` by adding a semaphore or spinning up multiple consumer coroutines.

### Mock AI analyst matches the live contract

The mock produces the same JSON schema as live GPT-4o-mini responses. Downstream consumers coded against the live response shape work identically in test environments without any special-casing.

---

## File Map

```
main.py                               — FastAPI app, all routes, middleware, background worker
utils/
  auth.py                             — API key → Stripe Customer ID registry
  anomaly.py                          — Rules-based anomaly detection engine
  ai_analyst.py                       — GPT-4o-mini integration with mock fallback
sdk/
  python/synthegria/
    client.py                         — SynthegriaClient, BulkJob
    exceptions.py                     — AuthError, RateLimitError, BulkJobError
    __init__.py                       — Public API surface
    setup.py                          — PyPI packaging
  javascript/
    synthegria.js                     — Zero-dependency JS client (Node.js 18+ / browser)
    synthegria.d.ts                   — Full TypeScript definitions
    package.json                      — npm package manifest
tests/
  conftest.py                         — Shared fixtures (Stripe mock, rate-limit reset)
  test_auth.py                        — Authentication tests
  test_ingestion.py                   — Sync ingestion tests
  test_bulk.py                        — Async bulk + job polling tests
  test_anomaly.py                     — Anomaly detection + AI integration tests
  test_ai_analyst.py                  — AI analyst unit tests
  test_audit.py                       — Audit log tests
scripts/
  test_api.py                         — 38 live end-to-end tests
  test_stripe_meter_events.py         — Multi-tenant Stripe meter smoke test
  start.sh                            — Production entrypoint (uvicorn, no access log)
landing.html                          — Product landing page (self-contained)
Dockerfile                            — Production container image
fly.toml                              — Fly.io deployment config
render.yaml                           — Render.com deployment config (blueprint)
pyproject.toml                        — Python project + pytest config (uv)
```

---

<p align="center">
  Built with FastAPI · Secured with Stripe · Analyzed by GPT-4o-mini
</p>
