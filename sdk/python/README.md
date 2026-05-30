# Synthegria Python SDK

Official Python client for the **Synthegria SIEM** log ingestion API.

Zero external dependencies — standard library only.

## Installation

```bash
pip install synthegria          # from PyPI (once published)
# or directly from source:
pip install ./sdk/python
```

## Quick Start

```python
from synthegria import SynthegriaClient

client = SynthegriaClient(
    api_key="synthegria_<tenant>_<token>",
    base_url="https://your-app.onrender.com",
)

# ── Real-time synchronous ingestion ─────────────────────────────────────────
logs = [
    {"timestamp": "2026-01-01T00:00:00Z", "source_ip": "1.2.3.4",
     "message": "normal login", "severity": "LOW"},
]
result = client.ingest(logs)
print(result["anomaly_count"])           # 0
print(result["meter_event_id"])          # mtr_evt_...
print(result["ai_analysis"])             # None (clean batch)

# ── High-throughput async bulk ingestion ─────────────────────────────────────
import json, gzip

large_batch = [{"message": f"event {i}"} for i in range(5_000)]
job = client.ingest_bulk(large_batch)
print(job.job_id)                        # UUID
result = job.wait(timeout=60)            # blocks until done
print(result["anomaly_count"])
print(result["ai_analysis"])             # AI threat summary or None
```

## Anomaly Detection

The server automatically scans every batch for:

| Category | Severity | Examples |
|---|---|---|
| `brute_force` | HIGH | Failed password, account locked |
| `sql_injection` | CRITICAL | UNION SELECT, DROP TABLE |
| `xss` | HIGH | `<script>`, `document.cookie` |
| `auth_anomaly` | MEDIUM | Privilege escalation, sudo |

## AI Analysis

When `OPENAI_API_KEY` is configured on the server, CRITICAL/HIGH anomalies
receive a gpt-4o-mini generated threat summary in `ai_analysis.summary`.
Without a key the server runs in mock mode and returns a deterministic
template-based summary with the same structure.

## Error Handling

```python
from synthegria import AuthError, RateLimitError, SynthegriaError

try:
    result = client.ingest(logs)
except AuthError:
    print("Check your API key")
except RateLimitError as e:
    print(f"Retry after {e.retry_after}s")
except SynthegriaError as e:
    print(f"API error {e.status_code}: {e}")
```

## API Reference

### `SynthegriaClient(api_key, base_url, timeout)`

| Method | Returns | Description |
|---|---|---|
| `ingest(logs)` | `dict` | Sync JSON ingestion (returns anomalies + AI analysis) |
| `ingest_bulk(logs)` | `BulkJob` | Async gzip ingestion (returns job handle) |
| `get_job(job_id)` | `dict` | Poll job status |
| `get_audit(limit)` | `list` | Fetch audit log entries |
| `healthz()` | `dict` | Liveness probe |

### `BulkJob`

| Method/Attr | Description |
|---|---|
| `job_id` | UUID string |
| `lines_received` | Lines accepted by server |
| `wait(timeout, poll_interval)` | Block until done; returns result dict |
