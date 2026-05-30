"""
Synthegria SIEM — Log Ingestion API  v1.1.0
============================================
Endpoints
  GET  /healthz              — liveness probe
  GET  /v1/audit             — last N structured audit log entries
  POST /v1/logs              — plain JSON batch ingestion (synchronous)
  POST /v1/logs/bulk         — gzip-compressed batch ingestion (async, 202 + job_id)
  GET  /v1/jobs/{job_id}     — poll bulk-job status / result

Security hardening
  - X-API-Key authentication → 401 + WWW-Authenticate header (RFC 7235)
  - Per-key rate limit: MAX_REQUESTS_PER_MINUTE req/key/min → 429
  - /v1/logs/bulk: compressed body capped at MAX_COMPRESSED_BYTES → 413
  - /v1/logs/bulk: Content-Encoding: gzip required → 415

Anomaly detection (both ingestion endpoints)
  - Rules engine in utils/anomaly.py scans every log line
  - Categories: brute_force (HIGH), sql_injection (CRITICAL),
                xss (HIGH), auth_anomaly (MEDIUM)
  - Stripe meter reports ALL lines regardless of anomaly status

Background worker
  - POST /v1/logs/bulk returns 202 Accepted immediately with a job_id
  - A single asyncio worker drains the queue (anomaly scan + Stripe reporting)
  - Job results are cached in-memory for JOB_TTL_SECONDS (1 hour)
  - Expired jobs are evicted by a periodic GC task
"""

import asyncio
import contextlib
import gzip
import json
import logging
import os
import time
import threading
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import stripe
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from utils.auth import AuthError, resolve_customer
from utils.anomaly import scan_logs
from utils.ai_analyst import analyze_anomalies

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("synthegria")

_audit_handler = logging.StreamHandler()
_audit_handler.setFormatter(logging.Formatter("%(message)s"))
audit_log = logging.getLogger("synthegria.audit")
audit_log.setLevel(logging.INFO)
audit_log.addHandler(_audit_handler)
audit_log.propagate = False

_audit_buffer: deque[dict] = deque(maxlen=100)

# ---------------------------------------------------------------------------
# Stripe
# ---------------------------------------------------------------------------

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
METER_EVENT_NAME  = "log_delivery"

if not STRIPE_SECRET_KEY:
    raise RuntimeError("STRIPE_SECRET_KEY environment variable is not set.")

stripe.api_key = STRIPE_SECRET_KEY

# ---------------------------------------------------------------------------
# Limits & constants
# ---------------------------------------------------------------------------

MAX_COMPRESSED_BYTES: int    = 10 * 1024 * 1024   # 10 MB compressed body cap
MAX_REQUESTS_PER_MINUTE: int = 60                  # rate limit per API key
JOB_TTL_SECONDS: int         = 3_600               # bulk jobs expire after 1 h
QUEUE_MAX_SIZE: int          = 500                  # max queued bulk jobs

# ---------------------------------------------------------------------------
# Background-job store  (in-memory, process-scoped)
# ---------------------------------------------------------------------------

JOB_PENDING    = "pending"
JOB_PROCESSING = "processing"
JOB_DONE       = "done"
JOB_FAILED     = "failed"

_job_store: dict[str, dict[str, Any]] = {}

# Initialized in lifespan
_bulk_queue:   asyncio.Queue | None = None
_worker_task:  asyncio.Task  | None = None
_gc_task:      asyncio.Task  | None = None

# ---------------------------------------------------------------------------
# Rate limiter  (fixed window, thread-safe)
# ---------------------------------------------------------------------------

_rate_lock:  threading.Lock          = threading.Lock()
_rate_store: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))


def _check_rate_limit(api_key: str) -> None:
    """Increment the per-key counter; raise 429 if the limit is exceeded."""
    window = int(time.time() // 60)
    with _rate_lock:
        count = _rate_store[api_key][window] + 1
        _rate_store[api_key][window] = count
        # Evict stale windows to prevent unbounded growth
        for w in [w for w in list(_rate_store[api_key]) if w != window]:
            del _rate_store[api_key][w]

    if count > MAX_REQUESTS_PER_MINUTE:
        log.warning("Rate limit exceeded  key=%r  count=%d", api_key, count)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Rate limit exceeded: max {MAX_REQUESTS_PER_MINUTE} "
                "requests per API key per minute."
            ),
            headers={"Retry-After": str(60 - int(time.time() % 60))},
        )

# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------

def _mask_key(key: str) -> str:
    """Partially mask an API key: prefix...last4."""
    if len(key) <= 8:
        return "***"
    return f"{key[:6]}...{key[-4:]}"


def _emit_audit(entry: dict) -> None:
    _audit_buffer.append(entry)
    audit_log.info(json.dumps(entry))

# ---------------------------------------------------------------------------
# Middleware — AuditLog  (outermost)
# ---------------------------------------------------------------------------

class AuditLogMiddleware(BaseHTTPMiddleware):
    """
    Emit one structured JSON audit record per request.
    Route handlers annotate request.state with:
      customer_id, lines_received, anomaly_count
    """

    async def dispatch(self, request: Request, call_next):
        start    = time.perf_counter()
        response = await call_next(request)
        duration = round((time.perf_counter() - start) * 1000, 1)

        raw_key = request.headers.get("x-api-key")
        entry = {
            "ts":             datetime.now(timezone.utc).isoformat(),
            "method":         request.method,
            "path":           request.url.path,
            "status_code":    response.status_code,
            "duration_ms":    duration,
            "api_key":        _mask_key(raw_key) if raw_key else None,
            "customer_id":    getattr(request.state, "customer_id",    None),
            "lines_received": getattr(request.state, "lines_received", None),
            "anomaly_count":  getattr(request.state, "anomaly_count",  None),
            "ip":             request.client.host if request.client else None,
        }
        _emit_audit(entry)
        return response

# ---------------------------------------------------------------------------
# Middleware — BulkSizeLimit  (inner)
# ---------------------------------------------------------------------------

class BulkSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Short-circuit /v1/logs/bulk when Content-Length exceeds the cap,
    before the body is buffered.
    """

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/v1/logs/bulk":
            cl = request.headers.get("content-length")
            if cl is not None:
                try:
                    size = int(cl)
                except ValueError:
                    size = 0
                if size > MAX_COMPRESSED_BYTES:
                    return Response(
                        content=json.dumps({
                            "error": "payload_too_large",
                            "detail": (
                                f"Compressed payload ({size:,} B) exceeds the "
                                f"{MAX_COMPRESSED_BYTES // (1024 * 1024)} MB limit. "
                                "Split into smaller batches."
                            ),
                        }),
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        media_type="application/json",
                    )
        return await call_next(request)

# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

async def _bulk_worker() -> None:
    """Drain _bulk_queue; for each job: anomaly scan → Stripe meter → store result."""
    assert _bulk_queue is not None
    while True:
        job = await _bulk_queue.get()
        job_id      = job["job_id"]
        customer_id = job["customer_id"]
        payload     = job["payload"]
        extra       = job["extra"]

        try:
            _job_store[job_id]["status"] = JOB_PROCESSING

            anomaly_result = scan_logs(payload)
            line_count     = len(payload)

            # AI analysis and Stripe reporting run concurrently in threads
            ai_analysis, meter_event_id = await asyncio.gather(
                asyncio.to_thread(analyze_anomalies, anomaly_result["anomalies"]),
                asyncio.to_thread(_fire_stripe_meter, customer_id, line_count),
            )

            _job_store[job_id].update({
                "status":       JOB_DONE,
                "result":       _build_response(
                    customer_id, line_count, meter_event_id, anomaly_result,
                    ai_analysis=ai_analysis,
                    **extra,
                ),
                "completed_at": datetime.now(timezone.utc).isoformat(),
            })
            log.info(
                "Bulk job done  id=%s  customer=%s  lines=%d  anomalies=%d  ai=%s",
                job_id, customer_id, line_count, anomaly_result["anomaly_count"],
                ai_analysis["mode"] if ai_analysis else "none",
            )

        except Exception as exc:
            log.error("Bulk job failed  id=%s  error=%s", job_id, exc)
            _job_store[job_id].update({
                "status":       JOB_FAILED,
                "error":        str(exc),
                "completed_at": datetime.now(timezone.utc).isoformat(),
            })
        finally:
            _bulk_queue.task_done()


async def _job_gc() -> None:
    """Evict jobs older than JOB_TTL_SECONDS every 5 minutes."""
    while True:
        await asyncio.sleep(300)
        now     = time.time()
        expired = [
            jid for jid, j in list(_job_store.items())
            if now - j.get("_created_ts", 0) > JOB_TTL_SECONDS
        ]
        for jid in expired:
            _job_store.pop(jid, None)
        if expired:
            log.info("Job GC evicted %d expired jobs", len(expired))

# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _bulk_queue, _worker_task, _gc_task

    _bulk_queue  = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)
    _worker_task = asyncio.create_task(_bulk_worker())
    _gc_task     = asyncio.create_task(_job_gc())

    mode = "LIVE" if STRIPE_SECRET_KEY.startswith("sk_live_") else "TEST"
    log.info(
        "Synthegria SIEM API ready  stripe=%s  rate_limit=%d/min  "
        "max_body=%d MB  queue_capacity=%d",
        mode, MAX_REQUESTS_PER_MINUTE,
        MAX_COMPRESSED_BYTES // (1024 * 1024), QUEUE_MAX_SIZE,
    )
    yield

    _worker_task.cancel()
    _gc_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await asyncio.gather(_worker_task, _gc_task)
    log.info("Synthegria SIEM API shutdown complete")


app = FastAPI(
    title="Synthegria M2M Core",
    version="1.1.0",
    description="""
## Overview

**Synthegria M2M Core** is the machine-to-machine log ingestion backbone of the
Synthegria SIEM platform.  Autonomous servers, edge collectors, and third-party
security appliances use this API to deliver structured security event logs in
real time.

## Authentication

Every request to an ingestion endpoint must carry a tenant API key in the
`X-API-Key` header.  Keys are provisioned per tenant and map to a Stripe
Customer ID for metered billing.

```
X-API-Key: synthegria_<tenant>_<token>
```

Missing or unrecognised keys return **401 Unauthorized** with a
`WWW-Authenticate: ApiKey realm="Synthegria"` header (RFC 7235).

## Ingestion modes

| Endpoint | Encoding | Mode | Best for |
|---|---|---|---|
| `POST /v1/logs` | Plain JSON | Synchronous | Real-time event streams |
| `POST /v1/logs/bulk` | Gzip JSON | Async (202 + job_id) | High-throughput batch delivery |

Poll `GET /v1/jobs/{job_id}` for bulk results.

## Anomaly detection

Every batch is scanned by the rules engine.

| Category | Severity | Example triggers |
|---|---|---|
| `brute_force` | HIGH | Failed-password keywords, 401/403 status values |
| `sql_injection` | CRITICAL | `UNION SELECT`, `DROP TABLE`, `SLEEP()` |
| `xss` | HIGH | `<script>`, `javascript:`, `onerror=` |
| `auth_anomaly` | MEDIUM | Privilege escalation, sudo, JWT issues |

## Metered billing

All ingested lines are reported to Stripe Billing Meters regardless of anomaly
status.  Billing is usage-based on raw line volume.

## Rate limits

60 requests per API key per minute.  Exceeded requests receive **429
Too Many Requests** with a `Retry-After` header.
""",
    contact={
        "name":  "Synthegria Platform Team",
        "email": "platform@synthegria.io",
    },
    license_info={"name": "Proprietary"},
    openapi_tags=[
        {
            "name":        "ingestion",
            "description": "Log batch ingestion (plain and gzip-compressed).",
        },
        {
            "name":        "jobs",
            "description": "Bulk-job status polling.",
        },
        {
            "name":        "ops",
            "description": "Operational: liveness probe and audit log.",
        },
    ],
    lifespan=lifespan,
)

# Middleware registration: last added = outermost on request.
app.add_middleware(BulkSizeLimitMiddleware)
app.add_middleware(AuditLogMiddleware)

# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------

@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    """
    Convert AuthError to 401 Unauthorized with a WWW-Authenticate header
    (RFC 7235) and a consistent JSON body.
    """
    raw_key = request.headers.get("x-api-key", "")
    log.warning(
        "Auth failure  path=%s  key=%r  reason=%s",
        request.url.path,
        _mask_key(raw_key) if raw_key else "(none)",
        exc,
    )
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"error": "unauthorized", "detail": str(exc)},
        headers={"WWW-Authenticate": 'ApiKey realm="Synthegria"'},
    )

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _authenticate(api_key: str | None) -> str:
    """
    Resolve *api_key* to a Stripe Customer ID.

    Raises
    ------
    AuthError
        Propagates directly to ``auth_error_handler`` which returns 401.
        We do NOT re-raise as HTTPException — keeping the response format
        consistent across all auth-failure paths.
    """
    return resolve_customer(api_key)


def _fire_stripe_meter(customer_id: str, line_count: int) -> str | None:
    """
    Report *line_count* lines to the Stripe Billing Meter.

    Safe to call from background threads (no FastAPI request context needed).
    Raises RuntimeError on any Stripe failure.
    """
    if line_count == 0:
        return None
    try:
        event = stripe.billing.MeterEvent.create(
            event_name=METER_EVENT_NAME,
            payload={"value": str(line_count), "stripe_customer_id": customer_id},
            timestamp=int(time.time()),
        )
        log.info(
            "Stripe meter  customer=%s  lines=%d  id=%s",
            customer_id, line_count, event.identifier,
        )
        return event.identifier
    except stripe.error.StripeError as exc:
        log.error("Stripe error  customer=%s  error=%s", customer_id, exc)
        raise RuntimeError(str(exc)) from exc


def _report_to_stripe(customer_id: str, line_count: int) -> str | None:
    """
    Wrapper for synchronous route handlers.
    Converts RuntimeError from _fire_stripe_meter into HTTPException 502.
    """
    try:
        return _fire_stripe_meter(customer_id, line_count)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Billing error — {exc}. Retry later.",
        ) from exc


def _build_response(
    customer_id: str,
    line_count: int,
    meter_event_id: str | None,
    anomaly_result: dict,
    **extra: Any,
) -> dict:
    """Build the standard JSON response envelope shared by both ingestion paths."""
    resp: dict[str, Any] = {
        "status":         "ok",
        "customer_id":    customer_id,
        "lines_received": line_count,
        "meter_event_id": meter_event_id,
        "anomaly_count":  anomaly_result["anomaly_count"],
        "anomalies":      anomaly_result["anomalies"],
    }
    if line_count == 0:
        resp["message"] = "Empty batch — nothing reported to meter."
    resp.update(extra)
    return resp

# ---------------------------------------------------------------------------
# Routes — landing + ops
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def landing_page() -> HTMLResponse:
    """Serve the product landing page."""
    import pathlib
    html = pathlib.Path(__file__).parent / "landing.html"
    return HTMLResponse(content=html.read_text(encoding="utf-8"))


@app.get("/healthz", tags=["ops"])
async def health() -> dict:
    """Liveness probe."""
    return {"status": "ok"}


@app.get("/v1/audit", tags=["ops"])
async def get_audit(limit: int = 20) -> list:
    """
    Return the last *limit* structured audit log entries (max 100).

    Each entry: ts, method, path, status_code, duration_ms,
    api_key (masked), customer_id, lines_received, anomaly_count, ip.
    """
    entries = list(_audit_buffer)
    return entries[-min(limit, len(entries)):]

# ---------------------------------------------------------------------------
# Routes — ingestion
# ---------------------------------------------------------------------------

@app.post("/v1/logs", tags=["ingestion"], status_code=status.HTTP_200_OK)
async def ingest_logs(
    request: Request,
    payload: list[dict[str, Any]],
    x_api_key: str | None = Header(default=None),
) -> dict:
    """
    Ingest a plain JSON batch of log lines.  Synchronous — anomaly results
    and the Stripe meter event ID are returned in the response body.

    **Headers required:**
    - `X-API-Key` — tenant API key (401 if missing or unknown)
    - `Content-Type: application/json`

    **Rate limit:** 60 requests per key per minute (429 + Retry-After).
    """
    customer_id = _authenticate(x_api_key)
    _check_rate_limit(x_api_key)   # x_api_key is non-None after successful auth

    line_count     = len(payload)
    anomaly_result = scan_logs(payload)
    ai_analysis    = analyze_anomalies(anomaly_result["anomalies"])

    request.state.customer_id    = customer_id
    request.state.lines_received = line_count
    request.state.anomaly_count  = anomaly_result["anomaly_count"]

    if anomaly_result["anomaly_count"]:
        log.warning(
            "POST /v1/logs  customer=%s  lines=%d  anomalies=%d  ai=%s",
            customer_id, line_count, anomaly_result["anomaly_count"],
            ai_analysis["mode"] if ai_analysis else "none",
        )
    else:
        log.info("POST /v1/logs  customer=%s  lines=%d", customer_id, line_count)

    meter_event_id = _report_to_stripe(customer_id, line_count)
    return _build_response(
        customer_id, line_count, meter_event_id, anomaly_result,
        ai_analysis=ai_analysis,
    )


@app.post("/v1/logs/bulk", tags=["ingestion"], status_code=status.HTTP_202_ACCEPTED)
async def ingest_logs_bulk(
    request: Request,
    x_api_key: str | None = Header(default=None),
) -> dict:
    """
    Ingest a **gzip-compressed** JSON batch of log lines.

    Returns **202 Accepted** immediately with a `job_id`.
    Anomaly detection and Stripe reporting run in a background worker.
    Poll `GET /v1/jobs/{job_id}` for the full result.

    **Headers required:**
    - `X-API-Key` — tenant API key (401 if missing or unknown)
    - `Content-Encoding: gzip`
    - `Content-Type: application/json`

    **Limits:**
    - Compressed body ≤ 10 MB → 413
    - 60 requests per key per minute → 429
    - Processing queue full → 503 (retry after 5 s)
    """
    customer_id = _authenticate(x_api_key)
    _check_rate_limit(x_api_key)   # x_api_key is non-None after successful auth

    # Require gzip encoding
    if request.headers.get("content-encoding", "").lower() != "gzip":
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=(
                "This endpoint requires Content-Encoding: gzip. "
                "For plain JSON use POST /v1/logs."
            ),
        )

    # Read body (middleware already rejected oversized Content-Length)
    compressed       = await request.body()
    compressed_bytes = len(compressed)

    if compressed_bytes > MAX_COMPRESSED_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"Compressed payload ({compressed_bytes:,} B) exceeds the "
                f"{MAX_COMPRESSED_BYTES // (1024 * 1024)} MB limit."
            ),
        )

    # Decompress
    try:
        raw = gzip.decompress(compressed)
    except (gzip.BadGzipFile, OSError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to decompress gzip body: {exc}",
        )

    uncompressed_bytes = len(raw)

    # Parse JSON
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON after decompression: {exc}",
        )

    if not isinstance(payload, list):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Payload must be a JSON array of log objects.",
        )

    line_count = len(payload)
    ratio      = round(uncompressed_bytes / compressed_bytes, 2) if compressed_bytes else 0

    # Create job record
    job_id = str(uuid.uuid4())
    now_ts = time.time()
    _job_store[job_id] = {
        "status":         JOB_PENDING,
        "customer_id":    customer_id,
        "lines_received": line_count,
        "created_at":     datetime.now(timezone.utc).isoformat(),
        "_created_ts":    now_ts,
    }

    # Enqueue
    assert _bulk_queue is not None
    try:
        _bulk_queue.put_nowait({
            "job_id":      job_id,
            "payload":     payload,
            "customer_id": customer_id,
            "extra": {
                "compressed_bytes":   compressed_bytes,
                "uncompressed_bytes": uncompressed_bytes,
                "compression_ratio":  f"{ratio}x",
            },
        })
    except asyncio.QueueFull:
        del _job_store[job_id]
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Processing queue is full. Retry in a few seconds.",
            headers={"Retry-After": "5"},
        )

    # Annotate for audit log
    request.state.customer_id    = customer_id
    request.state.lines_received = line_count
    request.state.anomaly_count  = None   # unknown until worker finishes

    log.info(
        "POST /v1/logs/bulk  customer=%s  lines=%d  %dB→%dB  %.2fx  job=%s",
        customer_id, line_count, compressed_bytes, uncompressed_bytes, ratio, job_id,
    )

    return {
        "status":         "accepted",
        "job_id":         job_id,
        "lines_received": line_count,
        "poll_url":       f"/v1/jobs/{job_id}",
        "message":        "Batch queued for background processing.",
    }

# ---------------------------------------------------------------------------
# Routes — jobs
# ---------------------------------------------------------------------------

@app.get("/v1/jobs/{job_id}", tags=["jobs"])
async def get_job(job_id: str) -> dict:
    """
    Return the current status (and result, when done) of a bulk ingestion job.

    **Statuses:**
    - `pending`    — queued, not yet started
    - `processing` — anomaly scan / Stripe reporting in progress
    - `done`       — completed; `result` contains the full ingestion envelope
    - `failed`     — worker error; `error` contains the reason

    Jobs are retained for one hour then automatically evicted.
    """
    job = _job_store.get(job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found or expired (TTL: {JOB_TTL_SECONDS // 3600} h).",
        )

    resp: dict[str, Any] = {
        "job_id":         job_id,
        "status":         job["status"],
        "customer_id":    job["customer_id"],
        "lines_received": job["lines_received"],
        "created_at":     job["created_at"],
    }

    if job["status"] == JOB_DONE:
        resp["completed_at"] = job.get("completed_at")
        resp["result"]       = job["result"]
    elif job["status"] == JOB_FAILED:
        resp["completed_at"] = job.get("completed_at")
        resp["error"]        = job.get("error", "unknown error")

    return resp
