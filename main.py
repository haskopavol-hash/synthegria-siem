"""
Synthegria SIEM — Log Ingestion API
====================================
Endpoints
  GET  /healthz         — liveness probe
  GET  /v1/audit        — last N structured audit log entries
  POST /v1/logs         — plain JSON batch ingestion
  POST /v1/logs/bulk    — gzip-compressed JSON batch ingestion

Security hardening:
  - X-API-Key authentication (401 on missing/unknown key)
  - Per-key rate limit: MAX_REQUESTS_PER_MINUTE req/key/min (429)
  - /v1/logs/bulk: compressed body capped at MAX_COMPRESSED_BYTES (413)
  - /v1/logs/bulk: Content-Encoding: gzip required (415)

Anomaly detection (both ingestion endpoints):
  - Rules engine in utils/anomaly.py scans every log line
  - Categories: brute_force (HIGH), sql_injection (CRITICAL),
                xss (HIGH), auth_anomaly (MEDIUM)
  - Response includes anomaly_count + anomalies[] detail array
  - Stripe meter reports ALL lines regardless of anomaly status

Observability:
  - AuditLogMiddleware emits one JSON audit line per request to stderr
  - In-memory ring buffer (last 100 entries) served at GET /v1/audit
  Audit fields: ts, method, path, status_code, duration_ms,
                api_key (masked), customer_id, lines_received,
                anomaly_count, ip
"""

import gzip
import json
import logging
import os
import time
import threading
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import stripe
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from utils.auth import AuthError, resolve_customer
from utils.anomaly import scan_logs

# ---------------------------------------------------------------------------
# Logging — main logger (human-readable) + audit logger (raw JSON)
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("synthegria")

# Audit logger writes pure JSON lines, no decoration, to stderr.
# propagate=False prevents double-printing through the root logger.
_audit_handler = logging.StreamHandler()
_audit_handler.setFormatter(logging.Formatter("%(message)s"))
audit_log = logging.getLogger("synthegria.audit")
audit_log.setLevel(logging.INFO)
audit_log.addHandler(_audit_handler)
audit_log.propagate = False

# In-memory ring buffer — backs the GET /v1/audit endpoint
_audit_buffer: deque[dict] = deque(maxlen=100)

# ---------------------------------------------------------------------------
# Stripe initialisation
# ---------------------------------------------------------------------------

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
METER_EVENT_NAME  = "log_delivery"

if not STRIPE_SECRET_KEY:
    raise RuntimeError("STRIPE_SECRET_KEY environment variable is not set.")

stripe.api_key = STRIPE_SECRET_KEY

# ---------------------------------------------------------------------------
# Security limits
# ---------------------------------------------------------------------------

MAX_COMPRESSED_BYTES: int    = 10 * 1024 * 1024  # 10 MB
MAX_REQUESTS_PER_MINUTE: int = 60

# ---------------------------------------------------------------------------
# In-memory rate limiter (fixed window, thread-safe)
# ---------------------------------------------------------------------------

_rate_lock: threading.Lock = threading.Lock()
_rate_store: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))


def _check_rate_limit(api_key: str) -> None:
    window = int(time.time() // 60)
    with _rate_lock:
        count = _rate_store[api_key][window] + 1
        _rate_store[api_key][window] = count
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
    """Partially mask an API key for safe logging: prefix...last4."""
    if len(key) <= 8:
        return "***"
    return f"{key[:6]}...{key[-4:]}"


def _emit_audit(entry: dict) -> None:
    """Write one audit entry to the ring buffer and the audit logger."""
    _audit_buffer.append(entry)
    audit_log.info(json.dumps(entry))

# ---------------------------------------------------------------------------
# Middleware — Audit (outermost, sees every request & final status)
# ---------------------------------------------------------------------------

class AuditLogMiddleware(BaseHTTPMiddleware):
    """
    Emit one structured JSON audit line per HTTP request, after the response
    is fully formed.  Route handlers annotate request.state with context fields
    (customer_id, lines_received, anomaly_count) that are picked up here.
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
# Middleware — Bulk size limit (runs inside AuditLogMiddleware)
# ---------------------------------------------------------------------------

class BulkSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Reject /v1/logs/bulk requests whose Content-Length exceeds
    MAX_COMPRESSED_BYTES before the body is buffered, avoiding the
    TCP connection-reset race on oversized uploads.
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
                            "detail": (
                                f"Compressed payload ({size:,} B) exceeds the "
                                f"{MAX_COMPRESSED_BYTES // (1024 * 1024)} MB limit. "
                                "Split into smaller batches."
                            )
                        }),
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        media_type="application/json",
                    )
        return await call_next(request)

# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    mode = "LIVE" if STRIPE_SECRET_KEY.startswith("sk_live_") else "TEST"
    log.info(
        "Synthegria Log Ingestion API starting up  "
        "(Stripe: %s  rate_limit: %d req/key/min  max_body: %d MB)",
        mode, MAX_REQUESTS_PER_MINUTE, MAX_COMPRESSED_BYTES // (1024 * 1024),
    )
    yield
    log.info("Synthegria Log Ingestion API shutting down")


app = FastAPI(
    title="Synthegria M2M Core",
    version="1.0.0",
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

Missing or unrecognised keys return **401 Unauthorized**.

## Ingestion modes

| Endpoint | Encoding | Best for |
|---|---|---|
| `POST /v1/logs` | Plain JSON | Low-volume / real-time event streams |
| `POST /v1/logs/bulk` | Gzip-compressed JSON | High-throughput batch delivery |

Both endpoints accept a **JSON array** of log-line objects and return the same
response envelope.

## Anomaly detection

Every batch is scanned inline by the rules engine before the response is
returned.  Detected events are included in the response — no separate polling
required.

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
Too Many Requests** with a `Retry-After` header indicating the seconds
remaining in the current window.

## Reference integration

See `example_client.py` in the repository root for a fully-annotated,
zero-dependency Python integration example that any autonomous server can
adapt.
""",
    contact={
        "name":  "Synthegria Platform Team",
        "email": "platform@synthegria.io",
    },
    license_info={
        "name": "Proprietary",
    },
    openapi_tags=[
        {
            "name":        "ingestion",
            "description": "Log batch ingestion endpoints (plain JSON and gzip-compressed).",
        },
        {
            "name":        "ops",
            "description": "Operational endpoints: liveness probe and audit log.",
        },
    ],
    lifespan=lifespan,
)

# Middleware registration: last added = outermost (runs first on request,
# last on response).  AuditLogMiddleware must be outermost so it sees the
# final status even when BulkSizeLimitMiddleware short-circuits.
app.add_middleware(BulkSizeLimitMiddleware)
app.add_middleware(AuditLogMiddleware)

# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"error": "Unauthorized", "detail": str(exc)},
    )

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _authenticate(api_key: str | None) -> str:
    try:
        return resolve_customer(api_key)
    except AuthError as exc:
        log.warning("Auth failure  key=%r  reason=%s", api_key, exc)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))


def _report_to_stripe(customer_id: str, line_count: int) -> str | None:
    if line_count == 0:
        return None
    try:
        event = stripe.billing.MeterEvent.create(
            event_name=METER_EVENT_NAME,
            payload={"value": str(line_count), "stripe_customer_id": customer_id},
            timestamp=int(time.time()),
        )
        log.info(
            "Stripe meter event  customer=%s  lines=%d  id=%s",
            customer_id, line_count, event.identifier,
        )
        return event.identifier
    except stripe.error.InvalidRequestError as exc:
        log.error("Stripe InvalidRequestError: %s", exc.user_message)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Stripe error: {exc.user_message}",
        )
    except stripe.error.StripeError as exc:
        log.error("StripeError: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Upstream billing error — please retry.",
        )


def _build_response(
    customer_id: str,
    line_count: int,
    meter_event_id: str | None,
    anomaly_result: dict,
    **extra,
) -> dict:
    """
    Build the standard JSON response envelope.

    anomaly_result must be the dict returned by scan_logs():
      {"anomaly_count": int, "anomalies": [...]}
    """
    resp: dict[str, Any] = {
        "status":          "ok",
        "customer_id":     customer_id,
        "lines_received":  line_count,
        "meter_event_id":  meter_event_id,
        "anomaly_count":   anomaly_result["anomaly_count"],
        "anomalies":       anomaly_result["anomalies"],
    }
    if line_count == 0:
        resp["message"] = "Empty batch — nothing reported to meter."
    resp.update(extra)
    return resp

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/healthz", tags=["ops"])
async def health() -> dict:
    """Liveness probe."""
    return {"status": "ok"}


@app.get("/v1/audit", tags=["ops"])
async def get_audit(limit: int = 20) -> list:
    """
    Return the last *limit* structured audit log entries (max 100).

    Each entry contains: ts, method, path, status_code, duration_ms,
    api_key (masked), customer_id, lines_received, anomaly_count, ip.
    """
    entries = list(_audit_buffer)
    return entries[-min(limit, len(entries)):]


@app.post("/v1/logs", tags=["ingestion"], status_code=status.HTTP_200_OK)
async def ingest_logs(
    request: Request,
    payload: list[dict[str, Any]],
    x_api_key: str | None = Header(default=None),
) -> dict:
    """
    Ingest a plain JSON batch of log lines.

    **Headers required:**
    - `X-API-Key` — tenant API key (401 if missing or unknown)
    - `Content-Type: application/json`

    **Rate limit:** MAX_REQUESTS_PER_MINUTE requests per key per minute (429).

    **Anomaly detection:** every log line is scanned for brute-force,
    SQL injection, XSS, and auth-anomaly signatures.  Results are
    returned in the response regardless of line count.

    **Stripe reporting:** all lines are metered regardless of anomaly status.
    """
    customer_id = _authenticate(x_api_key)
    _check_rate_limit(x_api_key)  # type: ignore[arg-type]

    line_count     = len(payload)
    anomaly_result = scan_logs(payload)

    # Annotate request.state for AuditLogMiddleware
    request.state.customer_id    = customer_id
    request.state.lines_received = line_count
    request.state.anomaly_count  = anomaly_result["anomaly_count"]

    if anomaly_result["anomaly_count"]:
        log.warning(
            "POST /v1/logs  customer=%s  lines=%d  anomalies=%d",
            customer_id, line_count, anomaly_result["anomaly_count"],
        )
    else:
        log.info("POST /v1/logs  customer=%s  lines=%d", customer_id, line_count)

    meter_event_id = _report_to_stripe(customer_id, line_count)
    return _build_response(customer_id, line_count, meter_event_id, anomaly_result)


@app.post("/v1/logs/bulk", tags=["ingestion"], status_code=status.HTTP_200_OK)
async def ingest_logs_bulk(
    request: Request,
    x_api_key: str | None = Header(default=None),
) -> dict:
    """
    Ingest a **gzip-compressed** JSON batch of log lines.

    **Headers required:**
    - `X-API-Key` — tenant API key (401 if missing or unknown)
    - `Content-Encoding: gzip`
    - `Content-Type: application/json`

    **Limits:**
    - Compressed body ≤ MAX_COMPRESSED_BYTES (10 MB) → 413
    - MAX_REQUESTS_PER_MINUTE requests per key per minute → 429

    **Anomaly detection:** same rules as POST /v1/logs, applied after
    decompression.  Response includes anomaly_count and anomalies[].

    **Stripe reporting:** all lines are metered regardless of anomaly status.
    """
    customer_id = _authenticate(x_api_key)
    _check_rate_limit(x_api_key)  # type: ignore[arg-type]

    # Content-Encoding check
    if request.headers.get("content-encoding", "").lower() != "gzip":
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="This endpoint requires Content-Encoding: gzip. For plain JSON use POST /v1/logs.",
        )

    # Read body (middleware already rejected oversized Content-Length headers)
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

    line_count     = len(payload)
    ratio          = round(uncompressed_bytes / compressed_bytes, 2) if compressed_bytes else 0
    anomaly_result = scan_logs(payload)

    # Annotate request.state for AuditLogMiddleware
    request.state.customer_id    = customer_id
    request.state.lines_received = line_count
    request.state.anomaly_count  = anomaly_result["anomaly_count"]

    if anomaly_result["anomaly_count"]:
        log.warning(
            "POST /v1/logs/bulk  customer=%s  lines=%d  anomalies=%d  "
            "%dB→%dB  %.2fx",
            customer_id, line_count, anomaly_result["anomaly_count"],
            compressed_bytes, uncompressed_bytes, ratio,
        )
    else:
        log.info(
            "POST /v1/logs/bulk  customer=%s  lines=%d  %dB→%dB  %.2fx",
            customer_id, line_count, compressed_bytes, uncompressed_bytes, ratio,
        )

    meter_event_id = _report_to_stripe(customer_id, line_count)
    return _build_response(
        customer_id, line_count, meter_event_id, anomaly_result,
        compressed_bytes=compressed_bytes,
        uncompressed_bytes=uncompressed_bytes,
        compression_ratio=f"{ratio}x",
    )
